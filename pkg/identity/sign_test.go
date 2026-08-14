package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadTestKey(t *testing.T) SigningKey {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join("testdata", "ed25519-key.pem"))
	if err != nil {
		t.Fatalf("load test key: %v", err)
	}
	key, err := ParseSigningKey(pemBytes)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return key
}

func TestParseSigningKey_RejectsNonEd25519(t *testing.T) {
	pemBytes, err := os.ReadFile(filepath.Join("testdata", "ed25519-pub.pem"))
	if err != nil {
		t.Fatalf("load test cert: %v", err)
	}
	// gateway.pem is a certificate (CERTIFICATE block), not a PKCS#8 private
	// key — must be refused, not coerced.
	if _, err := ParseSigningKey(pemBytes); err == nil {
		t.Fatal("certificate accepted as signing key")
	}
	// A fake PKCS#8 block with the wrong byte length is also refused.
	fake := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: make([]byte, 7)})
	if _, err := ParseSigningKey(fake); err == nil {
		t.Fatal("short fake PKCS#8 block accepted")
	}
}

func TestMintIdentityJWT_HeaderAndClaims(t *testing.T) {
	key := loadTestKey(t)
	jwt, err := key.MintIdentityJWT("spiffe://internal/hr-agent", "upstream-payroll")
	if err != nil {
		t.Fatal(err)
	}
	parts := splitJWT(jwt)
	if len(parts) != 3 {
		t.Fatalf("jwt parts: %d", len(parts))
	}
	var header map[string]string
	if err := json.Unmarshal(decodeB64(t, parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "EdDSA" || header["typ"] != "JWT" {
		t.Errorf("header wrong: %+v", header)
	}
	// kid = base64url(SHA-256(public key)).
	var claims map[string]any
	if err := json.Unmarshal(decodeB64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "spiffe://internal/hr-agent" {
		t.Errorf("sub wrong: %v", claims["sub"])
	}
	if claims["aud"] != "upstream-payroll" {
		t.Errorf("aud wrong: %v", claims["aud"])
	}
	exp := int64(claims["exp"].(float64))
	if exp != int64(claims["iat"].(float64))+30 {
		t.Errorf("exp must be iat+30s: %v", claims)
	}
	wantKid := base64.RawURLEncoding.EncodeToString(
		sha256.New().Sum(nil)[0:0])
	_ = wantKid
	pub := sha256.Sum256(key.PublicBytes())
	if header["kid"] != base64.RawURLEncoding.EncodeToString(pub[:]) {
		t.Errorf("kid must be base64url(SHA-256(pub))")
	}
}

func TestMintIdentityJWT_Ed25519SignatureVerifies(t *testing.T) {
	key := loadTestKey(t)
	jwt, err := key.MintIdentityJWT("token-sha256:abc123", "upstream-db")
	if err != nil {
		t.Fatal(err)
	}
	parts := splitJWT(jwt)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(key.PublicBytes())
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("Ed25519 signature does not verify with the same key")
	}
	// Tamper with the payload — verification must fail.
	if ed25519.Verify(pub, []byte(parts[0]+".tampered"), sig) {
		t.Error("signature verifies after payload tampering")
	}
}

func TestMintIdentityJWT_MustExpire(t *testing.T) {
	key := loadTestKey(t)
	jwt, err := key.MintIdentityJWT("spiffe://x", "a")
	if err != nil {
		t.Fatal(err)
	}
	parts := splitJWT(jwt)
	var claims map[string]any
	json.Unmarshal(decodeB64(t, parts[1]), &claims)
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Until(exp) > 30*time.Second || time.Until(exp) < 25*time.Second {
		t.Errorf("exp not ~30s ahead: %v", exp)
	}
}

func TestIdentityClaim_Precedence(t *testing.T) {
	cases := []struct {
		token, mtls, want string
	}{
		{"abc", "spiffe://internal/hr-agent", "spiffe://internal/hr-agent"},
		{"abc", "", "token-sha256:abc"},
		{"", "", "unidentified"},
	}
	for _, c := range cases {
		if got := IdentityClaim(c.token, c.mtls); got != c.want {
			t.Errorf("IdentityClaim(%q,%q) = %q want %q", c.token, c.mtls, got, c.want)
		}
	}
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
