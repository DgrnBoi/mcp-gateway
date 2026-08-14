package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoSPIFFEID is returned when a client certificate carries no
// spiffe:// URI SAN — the identity cannot be established.
var ErrNoSPIFFEID = errors.New("no spiffe:// URI found in certificate SANs")

// TLSConfig is the Stage 3 YAML surface for Ticket 15. mTLS is
// optional at the gateway level: when Enabled is false the gateway
// accepts plain HTTP and falls back to header-based identity. When
// RequireClientCert is true, every connection MUST present a
// certificate signed by one of the trusted CAs — this is the
// zero-trust posture.
type TLSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CertFile         string   `yaml:"cert_file"`
	KeyFile          string   `yaml:"key_file"`
	ClientCAFiles    []string `yaml:"client_ca_files"`
	RequireClientCert bool    `yaml:"require_client_cert"`
	TrustDomain      string   `yaml:"trust_domain,omitempty"`
}

// DefaultTLSConfig returns a disabled (plain HTTP) configuration — the
// operator must opt in explicitly, never implicitly.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{}
}

// ParseSPIFFEID extracts the workload identity from a certificate's
// URI SANs. It returns the first spiffe:// URI found (e.g.
// spiffe://internal/hr-agent) and a boolean success flag. Non-SPIFFE
// URIs are ignored.
func ParseSPIFFEID(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		if strings.HasPrefix(u.String(), "spiffe://") {
			return u.String(), true
		}
	}
	return "", false
}

// BuildTLSConfig materializes a *tls.Config from the operator's
// YAML. It validates the inputs up front so a misconfigured gateway
// refuses to start rather than silently accepting unverified clients.
func BuildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("tls enabled but cert_file/key_file missing")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading gateway identity: %w", err)
	}
	// MinVersion 1.2 is the practical floor; operators who need 1.3
	// only can harden the config themselves — the gateway never goes
	// below 1.2.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if len(cfg.ClientCAFiles) > 0 || cfg.RequireClientCert {
		pool := x509.NewCertPool()
		for _, ca := range cfg.ClientCAFiles {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("reading client CA %q: %w", ca, err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("client CA %q contains no valid certificates", ca)
			}
		}
		tlsCfg.ClientCAs = pool
		if cfg.RequireClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else if len(cfg.ClientCAFiles) > 0 {
			// CAs configured but not required: verify if presented,
			// but do not block anonymous connections (opt-in trust).
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tlsCfg, nil
}

// CallerMTLSSubject extracts CallerIdentity.MTLSSubject from the
// leaf peer certificate. It validates against an optional trust
// domain: if set, only SPIFFE IDs inside that domain are accepted,
// and all others fall back to the no-identity behavior that the
// evaluator's pre-flight gate denies.
func CallerMTLSSubject(state *tls.ConnectionState, trustDomain string) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	id, ok := ParseSPIFFEID(state.PeerCertificates[0])
	if !ok {
		return ""
	}
	if trustDomain == "" {
		return id
	}
	prefix := "spiffe://" + trustDomain + "/"
	if strings.HasPrefix(id, prefix) {
		return id
	}
	// Out-of-domain certificate: never leak it as an identity — the
	// evaluator will deny the unidentified caller instead.
	return ""
}
