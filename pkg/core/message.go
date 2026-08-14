package core

import (
	"encoding/json"
	"time"
)

type TransportName string

const (
	TransportSSE            TransportName = "sse"
	TransportStreamableHTTP TransportName = "streamable_http"
	TransportPlainHTTP      TransportName = "plain_http"
	TransportStdio          TransportName = "stdio" // Reserved for future adapter
)

// CallerIdentity encapsulates the agent's normalized identity.
// Enforced priority: client_id -> mTLS subject -> hashed header-token -> UA.
// NOTE: UserAgent is collected for context only; rules SHOULD NOT rely on it
// for allow/deny decisions because UAs are trivially spoofed.
type CallerIdentity struct {
	ClientID    string `json:"client_id,omitempty"`
	MTLSSubject string `json:"mtls_subject,omitempty"`
	TokenHash   string `json:"token_hash,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
}

// ToolCallView is the only struct the policy engine matches on.
// The policy rules never touch raw JSON except inside quarantined violations.
type ToolCallView struct {
	ToolName string                 `json:"tool_name"`
	Args     map[string]interface{} `json:"args,omitempty"`
}

// MCPMessage represents a normalized JSON-RPC message from any transport layer.
type MCPMessage struct {
	// Provenance (per agreed spec)
	ReceivedAt      time.Time
	Transport       TransportName
	SourceAddr      string // peer IP:port
	UpstreamURL     string // target MCP server (alias lookup happens in engine)
	ProtocolVersion string // from mcp-protocol-version header

	// JSON-RPC envelope
	Method    string
	ID        string          // normalized JSON-RPC id as string for stable equality/routing
	RawParams json.RawMessage // Preserved ONLY for violation quarantine, NEVER indexed

	// Enforcement identity
	CallerIdentity CallerIdentity

	// Parsed tool-call view; nil for non-tool methods.
	ToolCall *ToolCallView
}
