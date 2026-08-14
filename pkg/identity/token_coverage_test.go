package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePEMPublicKey_PKIXRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := parsePEMPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Error("PKIX PEM must decode to an ECDSA public key")
	}
}

func TestParsePEMPublicKey_SelfSignedCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	got, err := parsePEMPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*ecdsa.PublicKey); !ok {
		t.Error("certificate PEM must yield its public key")
	}
}

func TestParsePEMPublicKey_UnsupportedAndMissingBlocks(t *testing.T) {
	if _, err := parsePEMPublicKey([]byte("not pem at all")); err == nil {
		t.Error("non-PEM input must error")
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := parsePEMPublicKey(bad); err == nil {
		t.Error("private-key blocks must be rejected")
	}
}

func TestNewTokenValidator_ConfigVariants(t *testing.T) {
	// Empty config → nil validator (token validation disabled).
	if tv, err := NewTokenValidator(TokenConfig{}); err != nil || tv != nil {
		t.Errorf("empty config must yield nil validator: %v", tv)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	// Static PEM config → validator wired with the static key.
	tv, err := NewTokenValidator(TokenConfig{PEM: string(pemBytes), Audience: "mcpgw"})
	if err != nil {
		t.Fatal(err)
	}
	if tv.staticKey == nil || tv.audience != "mcpgw" {
		t.Error("static-key validator must carry the parsed key and audience")
	}
	// Bad PEM → hard failure; a malformed key must never silently disable validation.
	if _, err := NewTokenValidator(TokenConfig{PEM: "garbage"}); err == nil {
		t.Error("malformed PEM must fail at startup")
	}
	// JWKS config → validator wired with the remote source (unreachable here).
	tv, err = NewTokenValidator(TokenConfig{JWKSURL: "https://auth.example/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	if tv.jwks == nil {
		t.Error("JWKS config must wire the key source")
	}
}

func TestValidate_EmptyAndMalformedBearer(t *testing.T) {
	tv := &TokenValidator{now: time.Now}
	// No token at all is not an error — identity simply lacks a token hash.
	if _, err := tv.Validate(""); err != nil {
		t.Errorf("empty bearer must be a no-op: %v", err)
	}
	if _, err := tv.Validate("Basic creds"); err != ErrInvalidToken {
		t.Error("non-Bearer scheme must fail closed")
	}
}

// jwksHTTPStub serves a signed JWKS so the JWKS path can be exercised
// against a real HTTP server instead of hand-built key material.
func TestJWKS_FetchFromHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	src := newJWKSSource(srv.URL)
	// An empty key set must fail open at lookup time (nil key), never
	// cache a poisoned result — every lookup is its own trust decision.
	if k := src.Key("missing-kid"); k != nil {
		t.Error("missing kid on an empty key set must return nil")
	}
}
