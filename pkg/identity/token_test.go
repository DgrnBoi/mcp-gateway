package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- helpers ----------

func b64url(v []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(v), "=")
}

func encodeJWT(t *testing.T, alg string, kid string, claims map[string]any, signer any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	plain := b64url(hb) + "." + b64url(cb)
	var sig []byte
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		sig = mustRSASign(k, []byte(plain), alg)
	case *ecdsa.PrivateKey:
		var digest []byte
		switch alg {
		case "ES256":
			h := sha256.Sum256([]byte(plain))
			digest = h[:]
		case "ES384":
			digest = mustSHA384([]byte(plain))
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			t.Fatal(err)
		}
		curveBytes := k.Curve.Params().BitSize / 8
		rb, sb := r.Bytes(), s.Bytes()
		sig = make([]byte, 2*curveBytes)
		copy(sig[curveBytes-len(rb):curveBytes], rb)
		copy(sig[2*curveBytes-len(sb):], sb)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(plain))
	default:
		t.Fatalf("unsupported signer %T", signer)
	}
	return plain + "." + b64url(sig)
}

func mustRSASign(k *rsa.PrivateKey, plain []byte, alg string) []byte {
	var hash any
	switch alg {
	case "RS256":
		hash = sha256.Sum256(plain)
	case "RS384":
		hash = sha512_384(plain)
	case "RS512":
		hash = sha512Sum(plain)
	}
	switch h := hash.(type) {
	case [32]byte:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, 0, h[:])
		if err != nil {
			panic(err)
		}
		return s
	case [48]byte:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, 0, h[:])
		if err != nil {
			panic(err)
		}
		return s
	case [64]byte:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, 0, h[:])
		if err != nil {
			panic(err)
		}
		return s
	}
	panic("bad hash")
}

func sha512_384(data []byte) [48]byte {
	return sha384Sum(data)
}

func sha384Sum(data []byte) [48]byte {
	return sha512.Sum384(data)
}

func sha512Sum(data []byte) [64]byte {
	return sha512.Sum512(data)
}

func mustSHA384(data []byte) []byte {
	h := sha384Sum(data)
	return h[:]
}

func claimsMap(sub string, exp time.Time, nbf *time.Time) map[string]any {
	c := map[string]any{
		"sub": sub,
		"exp": exp.Unix(),
	}
	if nbf != nil {
		c["nbf"] = nbf.Unix()
	}
	return c
}

// ---------- tests ----------

func newRSA(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, &k.PublicKey
}

func newEC(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, &k.PublicKey
}

func newEd(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func pemOf(t *testing.T, pub any) string {
	t.Helper()
	der, err := marshalSPKI(pub)
	if err != nil {
		t.Fatal(err)
	}
	return "-----BEGIN PUBLIC KEY-----\n" + b64wrap(der) + "\n-----END PUBLIC KEY-----"
}

func marshalSPKI(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func b64wrap(der []byte) string {
	s := base64.StdEncoding.EncodeToString(der)
	var lines []string
	for i := 0; i < len(s); i += 64 {
		end := i + 64
		if end > len(s) {
			end = len(s)
		}
		lines = append(lines, s[i:end])
	}
	return strings.Join(lines, "\n")
}

func fixedClock(ts time.Time) func() time.Time {
	return func() time.Time { return ts }
}

func TestValidate_RS256_HappyPath(t *testing.T) {
	priv, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}

	token := encodeJWT(t, "RS256", "", claimsMap("sales-copilot", time.Unix(2000, 0), nil), priv)
	hash, err := tv.Validate("Bearer " + token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty token hash")
	}
	// hash must equal sha256 of the raw token
	sum := sha256.Sum256([]byte(token))
	want := fmtHex(sum[:])
	if hash != want {
		t.Fatalf("hash mismatch: %q != %q", hash, want)
	}
}

func fmtHex(b []byte) string {
	const hexchars = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, v := range b {
		s[i*2] = hexchars[v>>4]
		s[i*2+1] = hexchars[v&0x0f]
	}
	return string(s)
}

func TestValidate_EmptyHeaderIsOptional(t *testing.T) {
	_, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	hash, err := tv.Validate("")
	if err != nil {
		t.Fatalf("empty header must be optional: %v", err)
	}
	if hash != "" {
		t.Fatal("expected empty hash")
	}
}

func TestValidate_NonBearerIsRejected(t *testing.T) {
	tv := &TokenValidator{now: fixedClock(time.Unix(1000, 0))}
	_, err := tv.Validate("Basic dXNlcjpwYXNz")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidate_ExpiredIsRejected(t *testing.T) {
	priv, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	token := encodeJWT(t, "RS256", "", claimsMap("x", time.Unix(999, 0), nil), priv)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("expired token must fail: %v", err)
	}
}

func TestValidate_MissingExpiryIsRejected(t *testing.T) {
	priv, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	claims := map[string]any{"sub": "x"} // no exp
	token := encodeJWT(t, "RS256", "", claims, priv)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("missing exp must fail: %v", err)
	}
}

func TestValidate_NotYetValidIsRejected(t *testing.T) {
	priv, pub := newRSA(t)
	now := time.Unix(1000, 0)
	nbf := time.Unix(2000, 0)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(now)}
	token := encodeJWT(t, "RS256", "", claimsMap("x", time.Unix(3000, 0), &nbf), priv)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("nbf token must fail: %v", err)
	}
}

func TestValidate_WrongKeyIsRejected(t *testing.T) {
	priv1, pub1 := newRSA(t)
	priv2, _ := newRSA(t)
	_ = priv1
	tv := &TokenValidator{staticKey: pub1, now: fixedClock(time.Unix(1000, 0))}
	token := encodeJWT(t, "RS256", "", claimsMap("x", time.Unix(2000, 0), nil), priv2)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("tampered sig must fail: %v", err)
	}
}

func TestValidate_TamperedPayloadIsRejected(t *testing.T) {
	priv, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	token := encodeJWT(t, "RS256", "", claimsMap("sales-copilot", time.Unix(2000, 0), nil), priv)
	// flip one character of the payload segment
	parts := strings.SplitN(token, ".", 3)
	parts[1] = parts[1][:2] + "A" + parts[1][3:]
	tampered := strings.Join(parts, ".")
	_, err := tv.Validate("Bearer " + tampered)
	if err != ErrInvalidToken {
		t.Fatalf("tampered payload must fail: %v", err)
	}
}

func TestValidate_ECDSA_ES256(t *testing.T) {
	priv, pub := newEC(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	token := encodeJWT(t, "ES256", "", claimsMap("etl-worker", time.Unix(2000, 0), nil), priv)
	if _, err := tv.Validate("Bearer " + token); err != nil {
		t.Fatalf("es256 must validate: %v", err)
	}
}

func TestValidate_EdDSA(t *testing.T) {
	priv, pub := newEd(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	token := encodeJWT(t, "EdDSA", "", claimsMap("hr-agent", time.Unix(2000, 0), nil), priv)
	if _, err := tv.Validate("Bearer " + token); err != nil {
		t.Fatalf("eddsa must validate: %v", err)
	}
}

func TestValidate_JWKS_KidSelection(t *testing.T) {
	priv1, pub1 := newRSA(t)
	_, pub2 := newRSA(t)

	// Serve a JWKS with two keys; only kid-1 can verify.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n1, e1 := rsaPubToJWK(pub1, "kid-1")
		n2, e2 := rsaPubToJWK(pub2, "kid-2")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{n1, n2},
		})
		_ = e1
		_ = e2
	}))
	defer srv.Close()

	js := newJWKSSource(srv.URL)
	set, fetchErr := js.fetch()
	if fetchErr != nil {
		t.Fatalf("jwks fetch failed: %v", fetchErr)
	}
	if set.keys["kid-1"] == nil {
		t.Fatal("kid-1 missing from JWKS set")
	}
	got := set.keys["kid-1"].(*rsa.PublicKey)
	if got.N.Cmp(pub1.N) != 0 {
		t.Fatal("fetched key N differs from pub1 — JWK round-trip broken")
	}
	if got.E != pub1.E {
		t.Fatalf("fetched key E differs from pub1: got %d want %d", got.E, pub1.E)
	}
	tv := &TokenValidator{jwks: js, now: fixedClock(time.Unix(1000, 0))}

	good := encodeJWT(t, "RS256", "kid-1", claimsMap("x", time.Unix(2000, 0), nil), priv1)
	if _, err := tv.Validate("Bearer " + good); err != nil {
		t.Fatalf("kid-1 must validate via JWKS: %v", err)
	}
	wrong := encodeJWT(t, "RS256", "kid-2", claimsMap("x", time.Unix(2000, 0), nil), priv1)
	_, err := tv.Validate("Bearer " + wrong)
	if err != ErrInvalidToken {
		t.Fatalf("kid-2 (different key) must fail: %v", err)
	}
}

func rsaPubToJWK(pub *rsa.PublicKey, kid string) (map[string]any, error) {
	n := pub.N.Bytes()
	e := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256",
		"n": b64url(n), "e": b64url(e),
	}, nil
}

func TestValidate_UnknownKidIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}))
	defer srv.Close()
	tv := &TokenValidator{jwks: newJWKSSource(srv.URL), now: fixedClock(time.Unix(1000, 0))}
	priv, _ := newRSA(t)
	token := encodeJWT(t, "RS256", "ghost", claimsMap("x", time.Unix(2000, 0), nil), priv)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("unknown kid must fail: %v", err)
	}
}

func TestValidate_UnsupportedAlgIsRejected(t *testing.T) {
	priv, pub := newRSA(t)
	tv := &TokenValidator{staticKey: pub, now: fixedClock(time.Unix(1000, 0))}
	claims := map[string]any{"sub": "x", "exp": 2000}
	token := encodeJWTWithAlg(t, "none", "", claims, priv)
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("alg none must fail: %v", err)
	}
}

func encodeJWTWithAlg(t *testing.T, alg string, kid string, claims map[string]any, signer any) string {
	// Reuse encodeJWT but allow overriding alg via a special wrapper:
	// encodeJWT uses the alg string as-is; RS* paths need matching signer.
	// For "none" we skip signing entirely.
	hb, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": kid})
	cb, _ := json.Marshal(claims)
	return b64url(hb) + "." + b64url(cb) + "."
}

func TestValidate_AudienceMismatch(t *testing.T) {
	priv, pub := newRSA(t)
	now := time.Unix(1000, 0)
	claims := claimsMap("sales-copilot", time.Unix(2000, 0), nil)
	claims["aud"] = "other-system"
	token := encodeJWT(t, "RS256", "", claims, priv)
	tv := &TokenValidator{staticKey: pub, audience: "mcp-gateway", now: fixedClock(now)}
	_, err := tv.Validate("Bearer " + token)
	if err != ErrInvalidToken {
		t.Fatalf("audience mismatch must fail: %v", err)
	}
	// Correct audience passes.
	claims["aud"] = "mcp-gateway"
	token = encodeJWT(t, "RS256", "", claims, priv)
	if _, err := tv.Validate("Bearer " + token); err != nil {
		t.Fatalf("correct audience must pass: %v", err)
	}
}

func TestValidate_AudArray(t *testing.T) {
	priv, pub := newRSA(t)
	now := time.Unix(1000, 0)
	claims := claimsMap("x", time.Unix(2000, 0), nil)
	claims["aud"] = []string{"svc-a", "mcp-gateway"}
	token := encodeJWT(t, "RS256", "", claims, priv)
	tv := &TokenValidator{staticKey: pub, audience: "mcp-gateway", now: fixedClock(now)}
	if _, err := tv.Validate("Bearer " + token); err != nil {
		t.Fatalf("aud array containing required value must pass: %v", err)
	}
}

// YAML parsing of TokenConfig lives in the loader (webhooks/config.go
// pattern); this package intentionally stays stdlib-only at runtime.
// A loader unit test in cmd/mcp-gateway verifies the round-trip.
