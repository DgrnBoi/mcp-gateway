package server

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// stubEvaluator satisfies policy.Evaluator for gateway unit tests.
type stubEvaluator struct{}

func (s *stubEvaluator) Evaluate(msg *core.MCPMessage) policy.Decision {
	_ = msg
	return policy.Decision{Action: policy.ActionDeny}
}

func TestRequestWithTokenHash_InjectsHeaderAndClones(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r.Header.Set("Authorization", "Bearer abc")
	r2 := requestWithTokenHash(r, "sha-123")
	if got := r2.Header.Get("X-Mcpgw-Token-Hash"); got != "sha-123" {
		t.Errorf("header missing: %q", got)
	}
	// The original request must remain untouched (shallow copy).
	if r.Header.Get("X-Mcpgw-Token-Hash") != "" {
		t.Error("original request was mutated")
	}
}

func TestRequestWithMTLSSubject_TrustDomainFilter(t *testing.T) {
	// No TLS state at all → empty identity header.
	r := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r2 := requestWithMTLSSubject(r, nil, "spiffe://corp")
	if got := r2.Header.Get("X-Mcpgw-Mtls-Subject"); got != "" {
		t.Errorf("no-TLS request must carry an empty identity: %q", got)
	}
	// Out-of-domain certificate → empty identity (deny by pre-flight).
	r3 := requestWithMTLSSubject(httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil),
		&tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{
				SerialNumber: big.NewInt(1),
				URIs:         nil,
			}},
		}, "spiffe://corp")
	if got := r3.Header.Get("X-Mcpgw-Mtls-Subject"); got != "" {
		t.Errorf("out-of-domain cert must be filtered: %q", got)
	}
}

func TestTLSStateOf_NilSafety(t *testing.T) {
	if tlsStateOf(httptest.NewRequest(http.MethodGet, "http://gw/mcp", nil)) != nil {
		t.Error("plain request must yield no TLS state")
	}
	req := httptest.NewRequest(http.MethodGet, "http://gw/mcp", nil)
	req.TLS = &tls.ConnectionState{} // no peer certs
	if tlsStateOf(req) != nil {
		t.Error("TLS state without peer certificates must be treated as unverified")
	}
	req.TLS.PeerCertificates = []*x509.Certificate{{SerialNumber: big.NewInt(7)}}
	if tlsStateOf(req) == nil {
		t.Error("verified TLS state must be returned")
	}
}

func TestWriteAuthAudit_NilWriterSafe(t *testing.T) {
	// A gateway with no audit writer must survive identity failures
	// without panicking — the auth path must not depend on observability.
	g := &Gateway{
		Evaluator: &stubEvaluator{},
		Audit:     nil,
		Upstream:  "http://upstream",
	}
	g.writeAuthAudit(httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil),
		errTestToken)
}

func TestWriteAuthAudit_RecordsInvalidToken(t *testing.T) {
	var abuf safeBuffer
	g := &Gateway{
		Evaluator: &stubEvaluator{},
		Audit:     audit.NewWriterTo(&abuf, nil),
		Upstream:  "http://upstream",
	}
	r := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r.Header.Set("Authorization", "Bearer bad")
	g.writeAuthAudit(r, errTestToken)
	if abuf.Len() == 0 {
		t.Error("invalid-token audit line must be recorded")
	}
}

var errTestToken = &testTokenError{}

type testTokenError struct{}

func (e *testTokenError) Error() string { return "test token invalid" }

// safeBuffer satisfies io.Writer across goroutines.
type safeBuffer struct{ gwHelperBuf }

type gwHelperBuf struct{ b []byte }

func (b *gwHelperBuf) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *gwHelperBuf) String() string { return string(b.b) }
func (b *gwHelperBuf) Len() int       { return len(b.b) }
