package transport

import (
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

func TestParseSPIFFEID_URI_SAN(t *testing.T) {
	u, _ := url.Parse("spiffe://corp/hr-agent")
	id, ok := parseSPIFFEID(&x509.Certificate{
		URIs:         []*url.URL{u},
		SerialNumber: big.NewInt(1),
	})
	if !ok || id != "spiffe://corp/hr-agent" {
		t.Errorf("URI SAN must extract the SPIFFE ID: %q %v", id, ok)
	}
	// No URI SAN at all degrades to the CommonName path upstream.
	nook, ok2 := parseSPIFFEID(&x509.Certificate{SerialNumber: big.NewInt(2)})
	if ok2 || nook != "" {
		t.Error("certificate without a spiffe:// SAN must return no ID")
	}
}

func TestExtractIdentity_HeaderPriorityAndTLSFallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r.Header.Set("X-Client-Id", "cli-a")
	r.Header.Set("Authorization", "Bearer abc")
	id := ExtractIdentity(r, "initial-name")
	if id.ClientID != "cli-a" {
		t.Errorf("X-Client-Id must win: %q", id.ClientID)
	}
	// Without the header, the init client-info name from SSE bootstrap binds.
	r2 := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r2.Header.Set("Authorization", "Bearer abc")
	id2 := ExtractIdentity(r2, "sse-client")
	if id2.ClientID != "sse-client" {
		t.Errorf("init name fallback missing: %q", id2.ClientID)
	}
	// Verified JWT hash beats the blind Authorization header hash.
	r3 := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	r3.Header.Set("X-Mcpgw-Token-Hash", "verified-hash")
	r3.Header.Set("Authorization", "Bearer abc")
	id3 := ExtractIdentity(r3, "")
	if id3.TokenHash != "verified-hash" {
		t.Errorf("verified token hash must win over Authorization: %q", id3.TokenHash)
	}
}

func TestExtractIdentity_MTLSSubjectFallbacks(t *testing.T) {
	// Without TLS, the SPIFFE extraction path is skipped entirely — the
	// gateway injects X-Mcpgw-Mtls-Subject only after validating a client
	// certificate, so a plain request carries no mTLS identity.
	r := httptest.NewRequest(http.MethodPost, "http://gw/mcp", nil)
	id := ExtractIdentity(r, "")
	if id.MTLSSubject != "" {
		t.Errorf("non-TLS request must carry no mTLS subject: %q", id.MTLSSubject)
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestRead_TwiceConsumableBody(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call"}`)
	rw := &requestWrapper{body: append([]byte(nil), body...)}
	buf := make([]byte, len(body))
	n, err := rw.Read(buf)
	if err != nil || string(buf[:n]) != string(body) {
		t.Errorf("first read: %q %v", buf[:n], err)
	}
	// A second read on a drained body yields EOF — the wrapper does not
	// silently replay; callers who need the body twice reset explicitly.
	if _, err := rw.Read(buf); err != io.EOF {
		t.Errorf("drained body must return io.EOF: %v", err)
	}
	// Resetting the buffer pointer restores the full body for the
	// upstream replay.
	rw.body = append([]byte(nil), body...)
	got := make([]byte, len(body))
	n2, _ := rw.Read(got)
	if n2 != len(body) || string(got[:n2]) != string(body) {
		t.Errorf("reset body must be fully re-readable: %q", got[:n2])
	}
}

func TestDetectTransport_SSEAndStreamable(t *testing.T) {
	// The transport classifier keys on method + path + accept; a query
	// parameter alone does not classify — routing rules handle that.
	if got := DetectTransport(httptest.NewRequest(http.MethodGet, "http://gw/mcp?transport=sse", nil)); got != TransportUnknown {
		t.Errorf("query-param-only SSE must not classify: %v", got)
	}
	// SSE initialization channel: GET /sse with the event-stream accept.
	r := httptest.NewRequest(http.MethodGet, "http://gw/sse", nil)
	r.Header.Set("Accept", "text/event-stream")
	if got := DetectTransport(r); got != TransportSSE {
		t.Errorf("GET /sse with text/event-stream: %v", got)
	}
	// SSE message channel: POST /message with a session id.
	if got := DetectTransport(httptest.NewRequest(http.MethodPost, "http://gw/message?session_id=s1", nil)); got != TransportSSE {
		t.Errorf("POST /message must be the SSE channel: %v", got)
	}
	// Streamable HTTP: POST /mcp.
	if got := DetectTransport(httptest.NewRequest(http.MethodPost, "http://gw/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))); got != TransportStreamableHTTP {
		t.Errorf("streamable HTTP POST: %v", got)
	}
	// A POST to any other path is the plain-HTTP fallback, not streamable.
	if got := DetectTransport(httptest.NewRequest(http.MethodPost, "http://gw/api/v1", strings.NewReader(`{"jsonrpc":"2.0"}`))); got != TransportPlainHTTP {
		t.Errorf("plain POST fallback: %v", got)
	}
	// GET on an unrecognized path cannot be classified.
	if got := DetectTransport(httptest.NewRequest(http.MethodGet, "http://gw/api/v1", nil)); got != TransportUnknown {
		t.Errorf("unclassified GET: %v", got)
	}
}

var _ core.CallerIdentity
