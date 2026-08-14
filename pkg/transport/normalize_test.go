package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

const toolsCallBody = `{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_customer_data",
    "arguments": {
      "customer_id": "1 OR 1=1; DROP TABLE users;"
    }
  },
  "id": 42
}`

func TestDetectTransport_SSEInit(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/sse", nil)
	r.Header.Set("Accept", "text/event-stream")
	if got := DetectTransport(r); got != TransportSSE {
		t.Errorf("GET /sse + Accept text/event-stream: want sse, got %s", got)
	}
}

func TestDetectTransport_SSEMessage(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/message?session_id=abc", strings.NewReader(toolsCallBody))
	if got := DetectTransport(r); got != TransportSSE {
		t.Errorf("POST /message: want sse, got %s", got)
	}
}

func TestDetectTransport_StreamableHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCallBody))
	r.Header.Set("Accept", "application/json")
	if got := DetectTransport(r); got != TransportStreamableHTTP {
		t.Errorf("POST /mcp: want streamable_http, got %s", got)
	}
}

func TestDetectTransport_PlainPOST(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(toolsCallBody))
	r.Header.Set("Content-Type", "application/json")
	if got := DetectTransport(r); got != TransportPlainHTTP {
		t.Errorf("POST /: want plain_http, got %s", got)
	}
}

func TestExtractIdentity(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCallBody))
	r.Header.Set("X-Client-Id", "hr-agent-prod")
	r.Header.Set("Authorization", "Bearer secret-token")
	r.Header.Set("User-Agent", "Claude Desktop 1.0")

	id := ExtractIdentity(r, "")

	if id.ClientID != "hr-agent-prod" {
		t.Errorf("client_id: want hr-agent-prod, got %q", id.ClientID)
	}
	wantHash := sha256hex("Bearer secret-token")
	if id.TokenHash != wantHash {
		t.Errorf("token_hash mismatch:\nwant %s\ngot  %s", wantHash, id.TokenHash)
	}
	if id.UserAgent != "Claude Desktop 1.0" {
		t.Errorf("user_agent: want Claude Desktop 1.0, got %q", id.UserAgent)
	}
}

func TestExtractIdentity_InitClientInfoFallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "initialize",
		"params": {"clientInfo": {"name": "langchain-client"}},
		"id": 1
	}`))
	id := ExtractIdentity(r, "langchain-client")
	if id.ClientID != "langchain-client" {
		t.Errorf("fallback client_id: want langchain-client, got %q", id.ClientID)
	}
}

func TestNormalizeRequest_StreamableHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCallBody))
	r.Header.Set("Accept", "application/json")

	msg, fwdReader, err := NormalizeRequest(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method: want tools/call, got %s", msg.Method)
	}
	if msg.ToolCall == nil || msg.ToolCall.ToolName != "read_customer_data" {
		t.Error("tool call not parsed")
	}
	if msg.Transport != TransportStreamableHTTP {
		t.Errorf("transport: want streamable_http, got %s", msg.Transport)
	}
	if msg.ID != "42" {
		t.Errorf("id: want 42, got %s", msg.ID)
	}
	// Upstream must receive the ORIGINAL payload, unredacted.
	var buf bytes.Buffer
	buf.ReadFrom(fwdReader)
	if !strings.Contains(buf.String(), "1 OR 1=1") {
		t.Error("forwarded body lost the original payload — upstream would never see what the gateway saw")
	}
	// RawParams must survive for quarantine.
	if len(msg.RawParams) == 0 {
		t.Error("RawParams empty — quarantine would be impossible")
	}
}

func TestNormalizeRequest_SSEDataPrefix(t *testing.T) {
	body := "data: " + toolsCallBody
	r := httptest.NewRequest(http.MethodPost, "/message?session_id=abc", strings.NewReader(body))
	msg, _, err := NormalizeRequest(r)
	if err != nil {
		t.Fatalf("SSE event not normalized: %v", err)
	}
	if msg.Method != "tools/call" || msg.ToolCall.ToolName != "read_customer_data" {
		t.Error("SSE data: prefix payload not parsed")
	}
}

func TestNormalizeRequest_RejectsNonJSONRPC(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"not": "jsonrpc"}`))
	_, _, err := NormalizeRequest(r)
	if err == nil {
		t.Error("non-JSON-RPC body was accepted")
	}
}

func TestNormalizeRequest_RejectsBadVersion(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc": "1.0", "method": "tools/call", "params": {}}`))
	_, _, err := NormalizeRequest(r)
	if err == nil {
		t.Error("jsonrpc 1.0 was accepted")
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var _ core.TransportName // import use guard
