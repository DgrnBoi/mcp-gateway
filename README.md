# MCP Security Gateway

A zero-trust policy proxy, runtime guardrail, and forensic firewall for autonomous AI agents using the Model Context Protocol (MCP).

---

## 1. Project Overview

### The Problem: Unchecked Autonomy in MCP Tool Deployments
The Model Context Protocol (MCP) standardizes how Large Language Model (LLM) agents discover and invoke external tools, ranging from database connectors and cloud infrastructure APIs to enterprise CRMs and command execution environments. While this protocol enables autonomous multi-agent workflows, it also introduces critical safety and security risks:

- **Direct, Unmediated Tool Access**: Agents frequently receive direct credentials to invoke sensitive tools such as delete_database_record, drop_table, 	ransfer_funds, deploy_service, or execute_bash.
- **Vulnerability to Indirect Prompt Injection and Jailbreaks**: Malicious data retrieved from untrusted external sources (such as emails, web scrapes, or customer tickets) can hijack an agent's reasoning process, directing it to execute unauthorized or irreversible actions.
- **Lack of Protocol-Level Enforcement**: Traditional web application firewalls and network proxies inspect HTTP routes and IP addresses. They lack awareness of JSON-RPC semantics and cannot distinguish between a benign search_contacts call and an unauthorized ulk_export_customers tool call.
- **Absence of Forensic Attribution and Real-Time Oversight**: In standard configurations, security teams cannot verify which specific agent invoked a tool, cannot sanitize dangerous parameters before upstream delivery, and lack an air-gapped forensic log to reconstruct what an agent attempted during an incident.

### The Solution: MCP Security Gateway
The MCP Security Gateway is an open-source, high-throughput security sidecar written in Go. Positioned transparently between LLM client applications and upstream MCP tool servers, the gateway intercepts all traffic across Streamable HTTP, Server-Sent Events (SSE), and standard POST transports. It normalizes incoming messages and evaluates every tool call against strict, identity-aware authorization policies in sub-millisecond evaluation time.

The gateway prevents unauthorized, dangerous, or irreversible AI actions before they reach execution targets, sanitizes sensitive parameters, isolates malicious payloads in forensic quarantine, and provides real-time visibility through a dedicated triage console and enterprise SIEM integrations.

---

## 2. Safety Approach: Preventing Unauthorized and Irreversible Actions

The gateway implements a multi-layered defense-in-depth architecture designed to guarantee that no AI agent can execute unverified, destructive, or out-of-scope actions:

### Default-Deny Zero-Trust Policy Engine
All tool calls (	ools/call) and resource accesses are blocked by default unless explicitly authorized by a matching rule. The evaluation engine runs before any payload reaches the upstream server. If an incoming message presents no authenticated caller identity, the pre-flight gate drops the request immediately (PRE_FLIGHT_UNIDENTIFIED), guaranteeing that an unauthenticated caller cannot trigger wildcard rules or bypass evaluation.

### Cryptographic Identity and Zero Header Spoofing
Traditional proxies often rely on easily spoofed HTTP headers like X-Client-Id. The gateway enforces cryptographic proof of identity:
- **Mutual TLS with SPIFFE**: In mTLS mode, the gateway validates client certificates against a trusted Certificate Authority (CA) and extracts the identity solely from the SPIFFE URI Subject Alternative Name (SAN), such as spiffe://internal/hr-agent. Certificates lacking a SPIFFE SAN or originating outside the trusted domain are denied.
- **Cryptographic JWT Validation**: Bearer tokens are cryptographically verified using RS256/384/512, ES256/384, or EdDSA against static PEM keys or dynamic JWKS endpoints. Standard claims (exp, 
bf, ud) are strictly enforced.
- **Cryptographic Audit Binding**: The gateway computes an immutable SHA-256 hash of the verified token (TokenHash) and binds it to every audit record.
- **Upstream Attestation Injection**: Once a request passes policy evaluation, the gateway mints a short-lived (30-second) Ed25519 JWT attestation token injected as X-Mcpgw-Identity on the forwarded upstream request, ensuring that the target server receives verified identity provenance without exposing long-lived agent credentials.

### Hierarchical Multi-Tenant Invariants (Org Baseline vs. Team Overrides)
Enterprise environments frequently struggle with security fragmentation, where individual engineering teams accidentally relax global safety rules. The gateway solves this with a strict two-tier policy hierarchy:
1. **Organizational Baseline (org_policy.yaml)**: Central security teams define immutable invariants, such as hard denials on table drops, bulk record deletions, or administrative tool invocations.
2. **Team Policy Layers (	eam_policy.yaml)**: Individual teams define specific allowances required for their domain.
3. **Shadowed Invariant Detection (ErrShadowedInvariant)**: If a team policy attempts to define an llow rule that collides with an organizational deny rule, the loader rejects the entire configuration at startup. Team policies can narrow permissions (for instance, adding parameter redactions to an allowed tool), but they can never weaken or override organizational guardrails.

### Parameter-Level Redaction and Safe Rewriting (deny_with_redact)
Rather than forcing a binary choice between allowing dangerous calls or breaking agent workflows, the gateway supports selective argument sanitization. When a rule triggers deny_with_redact, the enforcement layer strips dangerous argument keys (such as raw sql strings, payment fields, or sensitive customer PII) from the JSON-RPC request before forwarding it upstream. The target tool executes safely without access to the forbidden parameters, while the unredacted original payload is routed to quarantine.

### Forensic Quarantine and Real-Time Alerting
When an agent attempts a forbidden or destructive action:
- **Quarantine Store (iolations.log)**: The full, unredacted tool invocation and caller context are isolated under a unique quarantine identifier (Q-xxxx).
- **SIEM Audit Logging (udit.log)**: High-fidelity JSON-lines logs record every decision, matched rule ID, caller identity, and token hash for ingestion into security information and event management (SIEM) systems.
- **Real-Time Webhooks**: The gateway dispatches instant notifications to Slack and PagerDuty. PagerDuty alerts use sliding-window counters and identity-fingerprint deduplication, escalating only when an agent exceeds violation thresholds while preventing alert fatigue.
- **Role-Based Incident Investigation**: The built-in console enforces role-based access control (admin, analyst, auditor), allowing analysts to inspect quarantined payloads and export streaming gzip forensic archives without risking memory exhaustion.

### Protection Against Agent Runaway Loops and Denial of Service
Autonomous agents can enter recursive execution cycles or generate runaway tool calls. The gateway incorporates a token-bucket rate limiter keyed by a composite SHA-256 identity fingerprint (ClientID|TokenHash|MTLSSubject). Agents that exceed configured rate or burst limits receive standard HTTP 429 responses with Retry-After headers, halting runaway executions before they saturate downstream systems.

### Fail-Steady Atomic Hot-Reloading
Security policies can be updated in real time without dropping active agent connections or restarting the sidecar. The policy manager monitors policy files using timestamp polling and responds to SIGHUP signals. New policy files are parsed and validated in a background goroutine; only fully valid policies are committed via an atomic pointer swap (sync/atomic.Value). If a policy file contains syntax errors or invalid schemas, the gateway logs a rejection and maintains the active policy without interruption.

### Deny-First GitOps Incident Response
The triage console includes a GitOps rule generator that converts security violations into candidate policy patches. To prevent accidental privilege creep, the generator defaults strictly to DenyMode, crafting minimal denial rules tailored to the offending caller and tool. Generation of llow rules requires explicit administrative override with documented reasoning and mandatory expiration dates.

---

## 3. Supporting Evidence: Demos, Test Results, and Documentation

The reliability, performance, and security guarantees of the MCP Security Gateway are validated through comprehensive automated testing, adversarial simulations, and live integration tests:

### Test Suite and Code Quality Matrix
- **83.0% Test Coverage**: Verified across all 11 core Go packages (pkg/core, pkg/policy, pkg/transport, pkg/identity, pkg/server, pkg/enforcement, pkg/audit, pkg/console, pkg/webhooks, pkg/gitops, pkg/metrics).
- **Data Race Free**: The entire test suite passes cleanly under the Go race detector (CGO_ENABLED=1 go test -race ./...), confirming concurrency safety across the graceful drain coordinator, quarantine indexer, and rate-limiting buckets.
- **CI Gate Meta-Tests**: Continuous integration pipelines verify that architectural invariants are maintained. A custom meta-test deliberately injects forbidden imports (
et/http) into data plane packages and verifies that the CI gate rejects the build, ensuring that policy and audit components remain transport-agnostic and free from side effects.

### Benchmarks and Chaos Load Testing
- **Sub-Millisecond Policy Evaluation**: In benchmark evaluations simulating a worst-case 200-rule evaluation path, the policy engine completes decisions in **3,513 nanoseconds (3.5 microseconds)** per operation, operating well below the 5-millisecond CI enforcement limit.
- **Sustained 10,000 RPS Load Capacity**: Under chaos load testing (	ests/chaos/load_test.sh), the gateway successfully processes 10,000 requests per second with a 99th percentile (p99) decision latency of **330 microseconds**, proving that policy enforcement introduces negligible overhead to real-time agent communications.

### Live End-to-End Verification (stage3_live_test.sh)
The automated live verification harness tests the compiled binary against live upstream services, real ES256 cryptographic keys, and full X.509 certificate chains. The suite achieves a **22/22 PASS** record across critical safety scenarios:
1. Valid ES256 JWT with trusted in-domain mTLS client certificate returns HTTP 200 with identity binding in audit logs.
2. Tampered, expired, and wrong-audience JWTs trigger immediate HTTP 401 INVALID_TOKEN responses.
3. Out-of-domain SPIFFE certificates and certificates lacking SPIFFE SANs trigger default-deny HTTP 403 responses.
4. Client requests lacking TLS certificates are rejected at the TLS handshake level with zero HTTP exposure.
5. Token bucket exhaustion triggers HTTP 429 with valid Retry-After headers and updates Prometheus rate-limiting counters.
6. File modification on policy.yaml triggers atomic hot swapping without interrupting active streams.
7. Corrupted or invalid YAML policy updates are rejected, preserving the active security baseline.
8. Native /metrics endpoint accurately reports request counters, violation labels, and latency distribution histograms.

### Continuous Fuzzing and Adversarial Tests
Four dedicated fuzzing harnesses run continuously against the gateway's exposed attack surfaces:
- FuzzLoadPolicy: Validates YAML parsing against malformed documents, unexpected fields, and recursive YAML bombs.
- FuzzLoadLayers: Verifies multi-document inheritance streams, ensuring that invalid layer mergers never result in permissive fallback states.
- FuzzEvaluate: Exercises the evaluator against hostile identity inputs, verifying that decisions always resolve deterministically.
- FuzzParseExportQuery: Ensures that date range queries in forensic exports enforce a strict 90-day ceiling and never allocate unbounded memory buffers.

### Production Container Hardening
The gateway includes a multi-stage Dockerfile (uild/Dockerfile) that compiles a statically linked binary with CGO_ENABLED=0 and places it onto gcr.io/distroless/static-debian12. The final runtime container measures approximately 15MB, contains no shell binaries (sh, ash), and provides no package manager, eliminating attack vectors for container breakout or arbitrary script execution.

---

## 4. Limitations and Future Improvements

To provide transparency for security evaluators, we document the following known limitations and planned architectural enhancements:

1. **Syntactic Tool Matching vs. Deep Semantic Intent Analysis**:
   The gateway enforces authorization rules based on JSON-RPC methods, tool names, and parameter key-value pairs. It does not run an internal language model to analyze ambiguous natural language prompts embedded within valid parameters (such as an indirect prompt injection contained within a legitimate user search string). Organizations should pair the gateway with upstream LLM input filtering for multi-layered defense.
2. **In-Process Rate Limiting State**:
   The built-in token-bucket rate limiter stores state within the local process memory. While this ensures microsecond execution times, rate-limiting counters reset upon pod restarts and are not synchronized across multiple horizontally scaled gateway replicas. Future releases will introduce an optional distributed Redis backend for cluster-wide rate limiting.
3. **Unsigned Policy Ingestion in GitOps Pipelines**:
   The gateway validates YAML structure, schema constraints, and inheritance invariants, but currently relies on Git repository permissions and code review processes to protect policy files. Implementing cryptographic commit signing (such as Sigstore or Cosign verification) directly in the loader is planned to protect against compromised deployment pipelines.
4. **Certificate Revocation Checking (CRL/OCSP)**:
   The mTLS validation module verifies root trust, expiration dates, and SPIFFE trust domain formats, but does not currently query Online Certificate Status Protocol (OCSP) responders or Certificate Revocation Lists (CRLs). Operators are advised to issue short-lived client certificates (e.g., via SPIRE or HashiCorp Vault) to minimize risk from revoked credentials.

---

## 5. Architecture and Data Flow

`
+-----------------------------------------------------------------------------------+
|                                  AI Client / Agent                                |
|                        (Claude Desktop, Cursor, Agent SDK)                        |
+-----------------------------------------------------------------------------------+
                                          |
                         [mTLS / Bearer Token / HTTP Transports]
                                          v
+-----------------------------------------------------------------------------------+
|                               MCP Security Gateway                                |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | 1. Transport Normalization (pkg/transport)                                  |  |
|  |    Normalizes SSE, Streamable HTTP, and plain POST into internal messages   |  |
|  +-----------------------------------------------------------------------------+  |
|                                         |                                         |
|  +-----------------------------------------------------------------------------+  |
|  | 2. Cryptographic Identity & Rate Limiting (pkg/identity, pkg/server)        |  |
|  |    - Validates SPIFFE mTLS leaf SAN / Bearer JWT signatures                 |  |
|  |    - Enforces token-bucket rate limits per identity fingerprint             |  |
|  +-----------------------------------------------------------------------------+  |
|                                         |                                         |
|  +-----------------------------------------------------------------------------+  |
|  | 3. Policy Evaluation Engine (pkg/policy)                                    |  |
|  |    - Default-deny evaluation order                                          |  |
|  |    - Hierarchical invariant enforcement (Org Baseline -> Team Policy)       |  |
|  |    - Pre-flight rejection of unauthenticated callers                        |  |
|  +-----------------------------------------------------------------------------+  |
|                     |                                         |                   |
|              [Action: Allow]                          [Action: Deny / Redact]     |
|                     |                                         |                   |
|  +------------------------------------+     +----------------------------------+  |
|  | 4a. Forwarding & Attestation       |     | 4b. Enforcement & Quarantine     |  |
|  |    - Mints 30s Ed25519 token       |     |    - Strips redact_keys (params) |  |
|  |    - Injects X-Mcpgw-Identity      |     |    - Quarantines unredacted body |  |
|  |    - Forwards to Upstream MCP      |     |    - Dispatches webhook alerts   |  |
|  +------------------------------------+     +----------------------------------+  |
|                     |                                         |                   |
|  +-----------------------------------------------------------------------------+  |
|  | 5. Observability & Auditing (pkg/audit, pkg/console, pkg/metrics)           |  |
|  |    - Immutable JSON-lines audit stream with token hash binding              |  |
|  |    - Prometheus exposition (/metrics) and web triage dashboard              |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+--------------------------+                      +---------------------------------+
|   Upstream MCP Server    |                      | SIEM / SOC Incident Response    |
| (Database, Filesystem,   |                      | (Audit Logs, Slack, PagerDuty,  |
| Cloud APIs, Shell Tools) |                      | Forensic Quarantine Exports)    |
+--------------------------+                      +---------------------------------+
`

---

## 6. Quickstart: Building and Running the Gateway

### Prerequisites
- Go 1.23 or higher
- Optional: OpenSSL (for generating test mTLS certificates), Docker (for container builds)

### 1. Build the Binary
`ash
go build -o mcp-gateway ./cmd/mcp-gateway/
`

### 2. Run in Standalone Mode
Start the gateway pointing to an upstream MCP server (e.g., listening on port 3001):
`ash
./mcp-gateway \
  --policy examples/policy.yaml \
  --upstream http://localhost:3001 \
  --listen :9090 \
  --console :9091 \
  --audit-log audit.log \
  --violations-log violations.log
`

AI agents configure their MCP client to connect to http://localhost:9090/mcp instead of connecting directly to the target server.

### 3. Run with Hierarchical Multi-Tenant Invariants
To enforce central organizational invariants alongside team policies:
`ash
./mcp-gateway \
  --org-policy examples/org_policy.yaml \
  --team-policy examples/team_policy.yaml \
  --upstream http://localhost:3001 \
  --listen :9090
`

### 4. Command-Line Reference

| Flag | Description | Default |
|---|---|---|
| --policy | Path to single YAML policy file | policy.yaml |
| --org-policy | Path to central organizational baseline policy | Disabled |
| --team-policy | Path to team policy layer (repeatable flag) | Disabled |
| --upstream | Target MCP server address | Required |
| --listen | Gateway listen address | :9090 |
| --console | Address for triage console and metrics endpoint | Disabled |
| --console-users | Path to static credentials YAML for console RBAC | Disabled |
| --console-jwt-secret | HMAC secret for console session authentication | Random |
| --config | Path to webhook, rate limit, and TLS configuration file | Disabled |
| --audit-log | File path for JSON-lines audit output | stdout |
| --violations-log | File path for quarantined violation payloads | stderr |
| --identity-signing-key | Path to Ed25519 private key PEM for upstream identity injection | Disabled |

---

## 7. Policy Configuration Examples

### Basic Policy (examples/policy.yaml)
Demonstrates explicit allows, explicit denials, parameter redactions, and temporary emergency access:
`yaml
default_action: deny

rules:
  # Allow specific agent to search contacts
  - id: R-001
    agent:
      client_id: sales-copilot
    tool:
      name: search_contacts
    action: allow

  # Deny bulk export attempts
  - id: R-002
    agent:
      client_id: sales-copilot
    tool:
      name: export_contacts_bulk
    action: deny
    reason: Bulk export forbidden; use the approved reporting pipeline

  # Strip raw SQL queries before forwarding
  - id: R-003
    agent:
      client_id: etl-worker
    tool:
      name: execute_query
    action: deny_with_redact
    redact_keys:
      - sql
    reason: Raw SQL parameter stripped; query quarantined for analysis

  # Time-bounded emergency access (requires mandatory expiration)
  - id: R-999
    agent:
      mtls_subject: /CN=incident-response/O=Acme
    tool:
      name: *
    action: allow_all
    reason: Production incident mitigation under ticket INC-4109
    expires_at: 2026-12-31T23:59:59Z
`

### Multi-Tier Policy Inheritance
Central security teams declare organizational invariants in examples/org_policy.yaml:
`yaml
default_action: deny
policy_layer: org

rules:
  # Hard invariant: no agent may delete records
  - id: ORG-001
    agent: {client_id: any-agent}
    tool: {name: delete_record}
    action: deny
    reason: Legal hold: record deletion is strictly forbidden
    expires_at: 2099-12-31T23:59:59Z
`

Individual teams define domain-specific allowances in examples/team_policy.yaml:
`yaml
default_action: allow
policy_layer: team

rules:
  # Team confirms redaction on customer data
  - id: TEAM-001
    agent: {client_id: sales-agent}
    tool: {name: search_contacts}
    action: deny_with_redact
    redact_keys: [email, phone]
    reason: Redact PII from external search results
    expires_at: 2099-12-31T23:59:59Z
`
If 	eam_policy.yaml attempted to add an llow rule for delete_record, the gateway would fail to load with ErrShadowedInvariant.

---

## 8. Verifying the Project

Reviewers can verify the implementation, test coverage, and safety guarantees using standard Go tooling:

`ash
# 1. Run static analysis and vet
go vet ./...

# 2. Run all unit, integration, and adversarial tests
go test -count=1 -timeout 240s ./...

# 3. Verify concurrency safety with the Go race detector
CGO_ENABLED=1 go test -race ./pkg/server ./pkg/console ./pkg/policy

# 4. Measure policy evaluation latency benchmark
go test -bench=BenchmarkEvaluator_WorstCase -benchtime=1x ./pkg/policy/

# 5. Run end-to-end live integration verification (Linux/macOS)
bash tests/live/stage3_live_test.sh
`

---

## 9. License

This repository is distributed under the terms of the project license for research, educational, and evaluation purposes. Review the included LICENSE file for details.