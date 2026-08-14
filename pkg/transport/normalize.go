package transport

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

// Transport detection constants (contract spec, Ticket 5).
const (
	TransportSSE            core.TransportName = "sse"
	TransportStreamableHTTP core.TransportName = "streamable_http"
	TransportPlainHTTP      core.TransportName = "plain_http"
	TransportUnknown        core.TransportName = "unknown"
)

// DetectTransport classifies an incoming request per the contract:
//   - GET /sse with Accept: text/event-stream          -> sse
//   - POST /message (SSE message channel)              -> sse
//   - POST /mcp                                       -> streamable_http
//   - any other JSON POST                             -> plain_http
func DetectTransport(r *http.Request) core.TransportName {
	method := strings.ToUpper(r.Method)
	path := strings.ToLower(r.URL.Path)

	// SSE initialization: GET /sse with Accept: text/event-stream
	if method == http.MethodGet && path == "/sse" &&
		strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		return TransportSSE
	}
	// SSE message channel: POST /message?session_id=...
	if method == http.MethodPost && path == "/message" {
		return TransportSSE
	}
	// Streamable HTTP: POST /mcp
	if method == http.MethodPost && path == "/mcp" {
		return TransportStreamableHTTP
	}
	// Plain POST fallback
	if method == http.MethodPost {
		return TransportPlainHTTP
	}
	return TransportUnknown
}

// ExtractIdentity populates CallerIdentity per the contract mapping:
//   - ClientID:   X-Client-Id header, or params.clientInfo.name from an
//     initialize request (parsed from the body by the caller
//     where available; this helper handles the header case).
//   - TokenHash:  SHA-256 of the full Authorization header value.
//   - MTLSSubject: req.TLS.PeerCertificates[0].Subject.CommonName.
//   - UserAgent:  request User-Agent, audit context only.
// parseSPIFFEID is the minimal URI-SAN reader for identity extraction;
// the full trust-domain enforcement lives in pkg/identity/spiffe.go and
// is applied by the gateway before this helper runs (out-of-domain
// certificates arrive here with an empty header and degrade to CN).
func parseSPIFFEID(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		if strings.HasPrefix(u.String(), "spiffe://") {
			return u.String(), true
		}
	}
	return "", false
}

func ExtractIdentity(r *http.Request, initClientInfoName string) core.CallerIdentity {
	id := core.CallerIdentity{
		UserAgent: r.UserAgent(),
	}
	if v := r.Header.Get("X-Client-Id"); v != "" {
		id.ClientID = v
	} else if initClientInfoName != "" {
		id.ClientID = initClientInfoName
	}
	if v := r.Header.Get("X-Mcpgw-Token-Hash"); v != "" {
		// Stage 3 / Ticket 14: the hash of a cryptographically verified
		// JWT always wins over the blind header hash — identity is proof,
		// not a claim.
		id.TokenHash = v
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		sum := sha256.Sum256([]byte(auth))
		id.TokenHash = hex.EncodeToString(sum[:])
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Stage 3 / Ticket 15: prefer the SPIFFE URI SAN when present;
		// fall back to the certificate CommonName.
		cert := r.TLS.PeerCertificates[0]
		if mtls := r.Header.Get("X-Mcpgw-Mtls-Subject"); mtls != "" {
			id.MTLSSubject = mtls
		} else if uri, ok := parseSPIFFEID(cert); ok {
			id.MTLSSubject = uri
		} else {
			id.MTLSSubject = cert.Subject.CommonName
		}
	}
	return id
}

// requestWrapper allows the body to be read twice: once for identity
// parsing (initialize clientInfo.name) and once by the caller/upstream.
type requestWrapper struct {
	body []byte
}

func (rw *requestWrapper) Read(p []byte) (int, error) {
	if len(rw.body) == 0 {
		return 0, io.EOF
	}
	n := copy(p, rw.body)
	rw.body = rw.body[n:]
	return n, nil
}

// jsonrpcRequest is the JSON-RPC envelope shape expected on all transports.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// NormalizeRequest converts an incoming HTTP request into exactly one
// core.MCPMessage per the contract spec. The returned reader contains the
// original unmodified body for upstream forwarding.
func NormalizeRequest(r *http.Request) (core.MCPMessage, io.Reader, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return core.MCPMessage{}, nil, fmt.Errorf("reading body: %w", err)
	}
	if len(body) == 0 {
		return core.MCPMessage{}, nil, fmt.Errorf("empty body")
	}

	var req jsonrpcRequest
	// The body may be JSON-RPC directly or an SSE "data: " prefixed event.
	// SSE payloads may span multiple "data:" lines, which must be joined
	// with newlines per the SSE specification.
	payload := body
	trimmed := bytes.TrimSpace(body)
	// SSE field parsing: only the line(s) carrying the "data:" field name
	// are prefixed; subsequent continuation lines belong to the same field
	// value and are joined with newlines per the SSE spec.
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		var parts []string
		dataStarted := false
		for _, line := range strings.Split(string(trimmed), "\n") {
			line = strings.TrimRight(strings.TrimSpace(line), "\r")
			if strings.HasPrefix(line, "data:") {
				dataStarted = true
				parts = append(parts, strings.TrimPrefix(line, "data:"))
				continue
			}
			if dataStarted && line != "" {
				// Continuation line of the same data field.
				parts = append(parts, line)
			}
		}
		payload = []byte(strings.Join(parts, "\n"))
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return core.MCPMessage{}, nil, fmt.Errorf("not valid JSON-RPC: %w", err)
	}
	if req.JSONRPC != "2.0" {
		return core.MCPMessage{}, nil, fmt.Errorf("unsupported jsonrpc version %q", req.JSONRPC)
	}

	// Identity: parse clientInfo.name from initialize params.
	var initName string
	if req.Method == "initialize" && len(req.Params) > 0 {
		var params struct {
			ClientInfo struct {
				Name string `json:"name"`
			} `json:"clientInfo"`
		}
		if json.Unmarshal(req.Params, &params) == nil {
			initName = params.ClientInfo.Name
		}
	}

	// Tool-call view: only for tools/call.
	var toolCall *core.ToolCallView
	if req.Method == "tools/call" && len(req.Params) > 0 {
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &params) == nil && params.Name != "" {
			toolCall = &core.ToolCallView{
				ToolName: params.Name,
				Args:     params.Arguments,
			}
		}
	}

	id := string(req.ID)
	msg := core.MCPMessage{
		ReceivedAt:      time.Now().UTC(),
		Transport:       DetectTransport(r),
		SourceAddr:      r.RemoteAddr,
		UpstreamURL:     r.Host + r.URL.Path,
		ProtocolVersion: r.Header.Get("Mcp-Protocol-Version"),
		Method:          req.Method,
		ID:              id,
		RawParams:       req.Params,
		CallerIdentity:  ExtractIdentity(r, initName),
		ToolCall:        toolCall,
	}
	return msg, bytes.NewReader(body), nil
}
