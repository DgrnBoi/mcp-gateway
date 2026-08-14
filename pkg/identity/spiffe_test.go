package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// certWithURIs builds a self-signed certificate carrying the given
// URI SANs for deterministic testing.
func certWithURIs(t *testing.T, uris ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*url.URL
	for _, u := range uris {
		parsed = append(parsed, mustParseURL(u))
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Unix(900, 0),
		NotAfter:     time.Unix(5000, 0),
		URIs:         parsed,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestParseSPIFFEID_Extracts(t *testing.T) {
	cert := certWithURIs(t, "https://example.com", "spiffe://internal/hr-agent")
	id, ok := ParseSPIFFEID(cert)
	if !ok || id != "spiffe://internal/hr-agent" {
		t.Fatalf("want spiffe id, got %q ok=%v", id, ok)
	}
}

func TestParseSPIFFEID_NoSPIFFEFails(t *testing.T) {
	cert := certWithURIs(t, "https://example.com/workload")
	id, ok := ParseSPIFFEID(cert)
	if ok || id != "" {
		t.Fatal("non-SPIFFE URIs must not be returned")
	}
}

func TestParseSPIFFEID_EmptyCertFails(t *testing.T) {
	_, ok := ParseSPIFFEID(&x509.Certificate{})
	if ok {
		t.Fatal("cert without URIs must fail")
	}
}

func TestCallerMTLSSubject_TrustDomainEnforcement(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			certWithURIs(t, "spiffe://internal/hr-agent"),
		},
	}

	// Correct domain: identity returned.
	if s := CallerMTLSSubject(state, "internal"); s != "spiffe://internal/hr-agent" {
		t.Fatalf("in-domain must return identity, got %q", s)
	}

	// Wrong domain: identity suppressed — the evaluator's pre-flight
	// gate must deny, never trust an out-of-domain certificate.
	if s := CallerMTLSSubject(state, "other-domain"); s != "" {
		t.Fatalf("out-of-domain must return empty, got %q", s)
	}

	// No trust domain configured: any SPIFFE ID accepted.
	if s := CallerMTLSSubject(state, ""); s != "spiffe://internal/hr-agent" {
		t.Fatalf("no trust domain must accept any SPIFFE id, got %q", s)
	}

	// No peer cert at all: empty identity.
	if s := CallerMTLSSubject(&tls.ConnectionState{}, "internal"); s != "" {
		t.Fatal("missing peer cert must return empty")
	}
	if s := CallerMTLSSubject(nil, "internal"); s != "" {
		t.Fatal("nil state must return empty")
	}
}

func TestBuildTLSConfig_DisabledReturnsNil(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSConfig{})
	if cfg != nil || err != nil {
		t.Fatal("disabled config must return nil, nil")
	}
}

func TestBuildTLSConfig_EnabledWithoutCertsFails(t *testing.T) {
	_, err := BuildTLSConfig(TLSConfig{Enabled: true})
	if err == nil {
		t.Fatal("enabled without cert/key must fail closed")
	}
}

func TestBuildTLSConfig_InvalidCAFileFails(t *testing.T) {
	_, err := BuildTLSConfig(TLSConfig{
		Enabled:           true,
		CertFile:          "testdata/gateway.pem",
		KeyFile:           "testdata/gateway-key.pem",
		RequireClientCert: true,
		ClientCAFiles:     []string{"/nonexistent/ca.pem"},
	})
	if err == nil {
		t.Fatal("missing CA file must fail closed")
	}
}

func TestDefaultTLSConfig_OptInOnly(t *testing.T) {
	if DefaultTLSConfig().Enabled {
		t.Fatal("default must be disabled — mTLS is opt-in")
	}
}
