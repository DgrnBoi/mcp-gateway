# MCP Security Gateway — Stage 3 Completion & v4 Handoff

**Date:** August 13, 2026
**Version:** v4 (Stage 3: Production Hardening complete)
**Status:** VERIFIED GREEN — 12 packages pass, worst-case latency 3.5µs, live E2E 22/22 PASS

---

## 1. Executive Summary

Stage 3 elevated the gateway from a functional enforcement proxy to
enterprise-ready, zero-trust infrastructure. The five production-hardening
tickets are implemented, wired into the binary, unit-tested, and
demonstrated live against the real compiled binary with real ES256-signed
JWTs and real X.509/SPIFFE certificates. Every Stage 3 guarantee stated in
the ticket spec was verified with actual HTTP responses, not mocks.

## 2. Ticket Results

### Ticket 14 — Token-Bound Validation (`pkg/identity/token.go`)
- Validates `Authorization: Bearer` as proof: RS256/384/512, ES256/384,
  EdDSA signatures; `exp`, `nbf`, `aud` claim enforcement.
- Static PEM (`token.pem`) or lazy-fetched JWKS (`token.jwks_url`).
- Valid token → SHA-256 hash bound to `CallerIdentity.TokenHash`, visible
  in every audit line. Invalid token → immediate `401`, audited as
  `INVALID_TOKEN` with identity `anonymous`.
- **Live proof:** valid JWT + mTLS → 200; tampered / expired /
  wrong-audience JWTs → 401.

### Ticket 15 — Cryptographic Identity (`pkg/identity/spiffe.go`)
- Strict mTLS listener: `tls.enabled`, trusted CA pool
  (`tls.client_ca_files`), `require_client_cert`, and a SPIFFE trust
  domain (`tls.trust_domain`).
- Identity is extracted **only** from the SPIFFE URI SAN of the leaf
  certificate; out-of-domain certs fall back to `anonymous` and hit
  default-deny; certs with no SPIFFE SAN never authenticate; missing
  client certs are refused at the TLS handshake layer (no HTTP path).
- **Live proof:** `spiffe://internal/hr-agent` → 200; out-of-domain and
  no-SAN certs → 403; no-cert → TLS alert `certificate required`.

### Ticket 16 — Per-Identity Rate Limiting (`pkg/server/ratelimit.go`)
- Token-bucket limiter keyed by `SHA-256(ClientID|TokenHash|MTLSSubject)`
  (the same fingerprint used for PagerDuty deduplication).
- `429` with `Retry-After` when the budget is exceeded; audited as
  `RATE_LIMITED` but **never** escalated to PagerDuty unless
  `ratelimit.include_in_alerts: true`.
- Configured from `config.yaml` (`requests_per_second`, `burst`).
- **Live proof:** 5 RPS / burst 5 → 429 within 6–7 rapid requests, with
  `Retry-After` present; violations counter visible in `/metrics`.

### Ticket 17 — Zero-Downtime Hot Reload (`pkg/policy/manager.go`)
- 2-second mtime poll on `policy.yaml` **plus** classic Nginx-style
  `SIGHUP` forced reload.
- New YAML is parsed and validated in the background; only a fully valid
  policy is swapped in via an atomic `sync/atomic.Value` pointer exchange.
- Unparseable YAML is rejected; the last-good policy keeps enforcing
  (fail-steady).
- **Live proof:** mtime bump → swap logged, `get_contact` newly allowed
  without any restart; garbage YAML → "hot-reload rejected" logged,
  behavior unchanged; `SIGHUP` → forced reload logged and effective.

### Ticket 18 — Prometheus Metrics (`pkg/metrics/prometheus.go`)
- Console serves `/metrics` with hand-rolled Prometheus exposition
  (zero external dependency beyond `yaml.v3`).
- Counters: `mcpgw_requests_total{action}`,
  `mcpgw_violations_total{rule_id,identity}`,
  `mcpgw_rate_limited_total{identity}`.
- Histogram: `mcpgw_evaluate_latency_seconds` (buckets down to 0.5ms).
- **Live proof:** all four metrics present in exposition with correct
  labels after the live attack sequence.

## 3. Verification Summary

| Gate | Result |
|------|--------|
| `go vet ./...` | clean |
| `go test ./...` (12 packages) | all green |
| Worst-case evaluator (200 rules) | **3,547 ns/op** (CI gate: 5ms) |
| Live Stage 3 E2E (`tests/live/stage3_live_test.sh`) | **22/22 PASS** |
| Identity coverage (`pkg/identity`) | 65.9% (metrics 98.5%, policy 88.9%) |

The live script starts a stub MCP server and the compiled gateway with
`require_client_cert` + JWT + rate limiting enabled, then exercises every
path with real cryptography (`mint_token.py` signs ES256 against the repo's
P-256 testdata key; `openssl` mints a full test CA/SPIFFE chain).

## 4. Architectural Decisions (Open Questions Resolved)

1. **Rate limit config location:** per-gateway limits live in
   `config.yaml` (the ticket's suggested placement), keyed per-identity at
   runtime. Per-agent limits can be added later to `policy.yaml` without
   touching the data plane.
2. **Reload trigger:** **both** — automatic 2s mtime polling (works with
   Kubernetes ConfigMap propagation) **and** SIGHUP for deterministic
   operator-triggered reloads. The atomic swap guarantees zero dropped
   connections in both paths.

## 5. Deployment Notes

- The gateway listener now requires `tls` config when mTLS is enabled; a
  production deployment must point `tls.client_ca_files` at the corporate
  SPIFFE CA bundle (e.g. SPIRE/SPIFFE trust domain root).
- Token validation is opt-in: if `token.pem` and `token.jwks_url` are both
  unset, the gateway degrades gracefully to header hashing (pre-Stage-3
  behavior) — useful during migration, remove once agents carry JWTs.
- SSE clients see zero interruption during policy swaps; only the
  *decision* for each new message changes.
- `pkg/identity` remains below the data-plane import line of `pkg/policy`
  and `pkg/audit` in the dependency tree; the CI grep gate still passes.

## 6. v4 Tarball

`mcp-gateway-v4.tar.gz` contains the full source tree (81 entries),
excluding the built binary and live-test scratch directories. Extraction
verified: `go vet` and unit tests pass from a clean extract.

## 7. Remaining Work (Not in Scope for v4)

- JWKS rotation polling interval hardening (currently lazy-fetch per kid
  miss).
- A signed-policy release channel (git-commit binding for `policy.yaml`).
- Per-agent rate-limit overrides inside `policy.yaml` (architecture is
  ready; single-line change to the limiter key).
- TLS client certificate revocation list (CRL/OCSP) checking.
