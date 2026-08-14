# MCP Security Gateway — v6
A Go-based security sidecar for AI agents that speak the Model Context
Protocol. The gateway sits between an LLM application and any MCP server
and enforces fine-grained authorization, redacts sensitive data, and
provides a live visibility console with Slack/PagerDuty alerting.

v6 adds **Stage 5: Enterprise Features** on top of the Stage 4
Go-To-Market hardening: multi-layer policy inheritance with strict
org→team precedence and shadowed-invariant detection, JWT role-based
access control securing the visibility console (admin/analyst/auditor),
and streaming gzip forensic quarantine exports for SOC integration.

---

## Running the gateway

```bash
# Build
go build -o mcp-gateway ./cmd/mcp-gateway/

# Run: proxy + policy + audit + console + webhooks
./mcp-gateway \
  --policy examples/policy.yaml \
  --config examples/config.yaml \
  --upstream http://localhost:3001 \
  --listen :9090 \
  --console :9091 \
  --audit-log audit.log \
  --violations-log violations.log
```

Clients connect to `http://gateway:9090/mcp` instead of the upstream.
The gateway accepts the three transports defined by the MCP spec
(Streamable HTTP, SSE, plain POST) and normalizes them into a single
internal message before evaluation.

### Flags

| Flag | Meaning | Default |
|------|---------|---------|
| `--policy` | YAML policy file (GitOps-managed, hot-reloaded) | `policy.yaml` |
| `--org-policy` | Org baseline for policy inheritance (implies `--policy` ignored) | disabled |
| `--team-policy` | Team policy layer — repeatable per team | disabled |
| `--console-users` | Static `users.yaml` for console RBAC (empty → console refuses all API) | disabled |
| `--console-jwt-secret` | HMAC secret for console login tokens (empty → random) | random |
| `--config` | Webhook/alerting + JWT + mTLS + rate-limit config (optional) | disabled |
| `--upstream` | MCP server behind the gateway | required |
| `--listen` | Gateway listen address | `:9090` |
| `--console` | Triage console + `/metrics` address (optional) | disabled |
| `--audit-log` | JSON-lines audit output (SIEM ingestion) | stdout |
| `--violations-log` | Quarantined violation payloads | stderr |

## Architecture

```
LLM app ──► [:9090 gateway] ──► upstream MCP server
                 │
                 ├── pkg/transport    (normalize SSE/Streamable HTTP/POST)
                 ├── pkg/policy       (YAML loader + evaluator + atomic PolicyManager)
                 ├── pkg/enforcement  (rewrite/redact on deny_with_redact)
                 ├── pkg/audit        (JSON-lines audit + quarantine)
                 ├── pkg/identity     (JWT/JWKS validation + SPIFFE extraction)
                 ├── pkg/server       (per-identity rate limiter + gateway loop)
                 ├── pkg/metrics      (Prometheus exposition)
                 ├── pkg/console      (dashboard + REST API + events stream)
                 ├── pkg/webhooks     (Slack + PagerDuty observers, DLQ)
                 └── pkg/gitops       (deny-first rule suggestion)
```

The policy engine runs in under 5ms even in the 200-rule worst case
(enforced by the CI latency gate). The gateway never imports `net/http`
inside `pkg/policy` or `pkg/audit`, guaranteeing the data plane stays
pure.

## Stage 3 features

### Token-bound validation (Ticket 14 — `pkg/identity`)

An `Authorization: Bearer` header is now proof, not a claim: it must be
a cryptographically valid JWT. The validator supports `RS256/384/512`,
`ES256/384`, and `EdDSA` against a static public key (config
`token.pem`) or a lazy-fetched JWKS endpoint (`token.jwks_url`). Claims
`exp`, `nbf`, and `aud` are enforced; an invalid token is an immediate
`401` that is audited with rule `INVALID_TOKEN` and identity
`anonymous`. Valid tokens bind their SHA-256 hash to the
`CallerIdentity.TokenHash`, visible in every audit line.

### Cryptographic mTLS identity (Ticket 15 — `pkg/identity`)

With `tls.enabled: true`, the gateway listener requires and verifies a
client certificate against a trusted CA (`tls.client_ca_files`). The
identity is the **SPIFFE URI SAN** of the leaf cert restricted to a
configured trust domain (e.g. `spiffe://internal/*`); certificates
outside the domain fall back to `anonymous` and hit the default-deny
fallback. Certs without a SPIFFE SAN never authenticate. Connections
with no client cert are refused at the TLS handshake layer (the server
never accepts the connection).

### Per-identity rate limiting (Ticket 16 — `pkg/server`)

A token-bucket limiter keyed by a SHA-256 fingerprint of the verified
identity (`ClientID|TokenHash|MTLSSubject`) protects the upstream from
runaway agents. Excess requests get `429` with a `Retry-After` header;
they are written to `audit.log` with rule `RATE_LIMITED` but never
escalate to PagerDuty by default. Limits live in `config.yaml`:

```yaml
ratelimit:
  enabled: true
  requests_per_second: 5
  burst: 5
  include_in_alerts: false   # PagerDuty muted by default
```

### Zero-downtime hot reload (Ticket 17 — `pkg/policy`)

`PolicyManager` watches `policy.yaml` (2-second mtime poll) and also
responds to `SIGHUP` for forced reloads. New YAML is parsed and
validated in the background; only a fully valid policy is swapped in
via an atomic `sync/atomic.Value` pointer exchange, so active SSE
streams and in-flight requests are never dropped. An unparseable file
is rejected and the last-good policy keeps enforcing (fail-steady).

### Prometheus metrics (Ticket 18 — `pkg/metrics`)

The console exposes `/metrics` with hand-rolled Prometheus exposition
(no dependency on the official client):

- `mcpgw_requests_total{action=allow|deny|invalid_token}`
- `mcpgw_violations_total{rule_id, identity}`
- `mcpgw_rate_limited_total{identity}`
- `mcpgw_evaluate_latency_seconds` (histogram, buckets down to 0.5ms)

## Stage 2 features

### Console (`--console :9091`)

- `/` — triage dashboard (live event stream, rule hit counts)
- `/api/audit` — paged JSON-lines audit entries
- `/api/violations/:qid` — quarantined raw payload for a violation
- `/metrics` — Prometheus exposition (Stage 3)
- `/api/rules/suggest` — **deny-first GitOps rule generation**:

```bash
# Secure default: tightens enforcement, never grants access
curl -X POST "http://localhost:9091/_console/api/rules/suggest?quarantine_id=Q-000001"

# One-click allow is REFUSED unless an analyst opts in WITH a reason:
curl -X POST ".../suggest?quarantine_id=Q-000001" \
  -H "X-GitOps-Opt-In: allow" \
  -H "X-GitOps-Reason: temp access for sales migration"
```

The default (no opt-in header) always produces a `deny` or
`deny_with_redact` rule bound to the exact attacking identity. An opt-in
allow carries a mandatory human reason and an auto-expiry (14 days).

### Webhooks (`--config examples/config.yaml`)

- **Slack**: async workers, backoff retries, and a durable file-based
  dead-letter queue; 4xx responses are never retried (permanent errors).
- **PagerDuty**: incidents fire only when a single identity's weighted
  violations *exceed* the threshold (default 5) inside a 60s sliding
  window; the dedup key is `SHA-256(ClientID|TokenHash|MTLSSubject)`;
  re-alerts for the same identity are muted for 5 minutes.

Both observers run fully off the critical path: `Observe` never blocks
the proxy goroutine.

### GitOps generation (`pkg/gitops`)

Every violation produces a suggested rule patch that a CI job can turn
into a PR against the policy repo. Allowed-with-redaction entries can
also be proposed (they tighten enforcement rather than relaxing it).

## Verification

```bash
go vet ./...                              # static analysis
go test -count=1 -timeout 240s ./...      # all unit + adversarial tests
go test -bench=BenchmarkEvaluator_WorstCase -benchtime=1x ./pkg/policy/
bash tests/live/stage2_live_test.sh       # Stage 2 end-to-end demo
bash tests/live/stage3_live_test.sh       # Stage 3 end-to-end demo (JWT, mTLS, 429, reload, metrics)
```

Stage 3 live results (`22/22 PASS`):

- Valid ES256 JWT + in-domain mTLS client cert → 200, audit carries
  `token_hash` and `spiffe://internal/hr-agent`.
- Tampered / expired / wrong-audience tokens → 401 `INVALID_TOKEN`.
- Out-of-domain SPIFFE cert, cert without SPIFFE SAN → default-deny 403.
- No client cert → TLS handshake refused (server alert, no HTTP).
- Burst exhaustion → 429 with `Retry-After`; identity fingerprint
  quarantined in violations and counted in `mcpgw_rate_limited_total`.
- `policy.yaml` mtime bump → atomic hot swap, active streams intact;
  invalid YAML → reject + fail-steady on last-good policy; `SIGHUP` →
  forced reload.
- `/metrics` exposes counters and the latency histogram.

## Stage 4 features

### Deployment & orchestration (Ticket 19 — `build/`, `deploy/`)

- `build/Dockerfile`: multi-stage build. Stage 1 compiles with
  `CGO_ENABLED=0` and full static linking; Stage 2 lands on
  `gcr.io/distroless/static-debian12` — a ~15MB immutable image with
  **zero shell access** (no busybox, no `sh`, nothing to exploit).
- `deploy/kubernetes/`: reference `Deployment` + `Service` with a strict
  sidecar layout, `ConfigMap` for `config.yaml`, `Secret` for TLS and
  signing keys, and `livenessProbe`/`readinessProbe` on `/healthz`.
- `deploy/helm/mcp-gateway/`: a linted, rendered chart for the sidecar
  pattern (`helm install` + `helm template --debug` verified).
- `/healthz` readiness endpoint — probes fail closed on drained or
  reloading gateways.

### Performance & chaos hardening (Ticket 20 — `pkg/server`)

- `DrainTracker` (SIGTERM): stop accepting, finish in-flight JSON-RPC
  calls, sever SSE keepalives, flush the audit buffer fully, exit clean.
- Shared upstream `http.Transport` with connection pooling + strict
  `ReadHeaderTimeout`/`WriteTimeout`/`IdleTimeout` (slowloris defense).
- Load proof: `tests/chaos/load_test.sh` sustains **10,000 RPS**; p99 of
  the enforcement decision stays at **330µs** — 15x under the 5ms CI
  gate even at saturation.

### Upstream identity injection (Ticket 21 — `pkg/identity`)

Once a caller clears JWT/mTLS validation and policy evaluation, the
gateway mints a **short-lived (30s) Ed25519 JWT** and injects it as
`X-Mcpgw-Identity` on the forwarded upstream request.

| Claim | Meaning |
|---|---|
| `sub` | verified caller identity (`spiffe://…` or `token-sha256:…`) |
| `aud` | upstream alias (each upstream may restrict acceptance) |
| `iat` / `exp` | issued at issuance, expires 30s later |

- Configured via `identity_signing_key` (PKCS#8 Ed25519 PEM) in
  `config.yaml`; a non-Ed25519 key is a **startup hard failure** — never
  a silent passthrough. `kid` is `base64url(SHA-256(public key))` for
  key rotation.
- Upstream verification is self-contained: header + claims + signature.
  `tests/live/verify_upstream_sig.py <jwt> <pub.pem>` performs the full
  OpenSSL `pkeyutl -rawin` verification (tampered headers and wrong-key
  negative tests both correctly fail).
- An unsigned header is worthless: anything that reaches the upstream
  directly can set any string — only the verified signature proves the
  gateway vouched for the identity, enabling row-level security on the
  upstream's tool executions.

CI gates (`.github/workflows/ci.yml`):

- build + lint + import-cycle checks
- `grep` gate forbidding `net/http` in `pkg/policy` and `pkg/audit`
- worst-case latency under 5ms
- minimum 80% coverage (currently **82.6%** over `./pkg/...`)

Package (`make package` / tarball): `mcp-gateway-v6.tar.gz` contains
the binary, `build/`, `deploy/`, `examples/`, and `tests/chaos/`.

## Stage 5 features

### Policy inheritance (Ticket 19 — `pkg/policy/inheritance.go`)

Large organizations centralize security baselines while individual
teams define specific allowances. The gateway now merges an **org
baseline** with any number of **team policy** layers into one
evaluated hierarchy:

```bash
./mcp-gateway \
  --org-policy examples/org_policy.yaml \
  --team-policy examples/team_policy.yaml \
  --team-policy examples/billing_policy.yaml \
  --upstream http://localhost:3001 --listen :9090
```

Every YAML document carries `policy_layer: org` or `policy_layer: team`
(unknown layers and duplicate rule IDs across layers are rejected at
load time). The merged enforcement order is strict:

1. **Org deny invariants** — identity scope is erased, so the tool is
   locked for *every* agent regardless of identity claims (FIX #1
   bypass-proofing).
2. **Team denies** (`deny` and `deny_with_redact`).
3. **Team allows**.
4. **Org allows** — identity scope retained; unscoped callers fall
   through to default resolution.
5. **Universal org denies** (`client_id: any-agent` wildcard).
6. **Default action** — chosen per request: callers matching an
   org-specific identity scope get the org default; unknown callers
   get the team default (`default_action: allow` is only valid on a
   team-layer document).

The loader refuses to silently let a team erode the baseline: a team
allow whose identity *and* tool scope collide with an org deny raises
`ErrShadowedInvariant` and the whole hierarchy is rejected. Hot reload
(`mtime` bump or `SIGHUP`) re-merges the full hierarchy and is equally
fail-closed — an invalid edit leaves the last-good merged policy in
place. See `examples/org_policy.yaml` and `examples/team_policy.yaml`.

### Console RBAC (Ticket 20 — `pkg/console/auth.go`)

The visibility console is now JWT-protected. Login (`/_console/api/auth/login`)
mints an HS256 token bound to a static `users.yaml` credential store
(`console.LoadUsersFile`); without `--console-users` the console serves
the dashboard shell but **refuses every API request with 403**.

| Role | Dashboard | Quarantine payloads (`/api/violations/:qid`) | GitOps rule generation |
|------|-----------|-----------------------------------------------|------------------------|
| `admin` | yes | yes | yes |
| `analyst` | yes | yes | no (403) |
| `auditor` | yes | **no (403)** | no (403) |

The auditor restriction is deliberate: auditors verify enforcement
through metadata without ever seeing raw quarantined payloads that
might contain PII or secrets.

### Forensic quarantine export (Ticket 21 — `pkg/console/export.go`)

`GET /api/export` streams a **gzip** archive of `violations.log`
entries directly to the client — entries are written to the stream
as they are scanned, so exporting millions of quarantine events never
materializes more than one buffer in memory:

```bash
# Everything from identity sales-agent in August
$ curl "http://localhost:9091/_console/api/export?start_time=2026-08-01T00:00:00Z&end_time=2026-09-01T00:00:00Z&identity=sales-agent" \
    -H "Authorization: Bearer <analyst-or-admin-token>" \
    | gunzip > /tmp/forensics.jsonl
```

`start_time`/`end_time` are RFC3339 and mandatory (unbounded exports
are refused), and `identity` filters by the caller's SHA-256 identity
fingerprint, enabling SOC teams to pull a single agent's quarantine
evidence into Splunk or Elastic.

### Stage 5 verification

- `pkg/policy/inheritance_test.go` — precedence walk, collision
detection, token-hash prefix overlap, multi-document streams, ID
uniqueness, and team-layer fallback.
- `manager_layers_test.go` — layered manager init, hot-reload
rejection of shadowed invariants, and clean merge swaps.
- Live: layered boot (`--org-policy` + `--team-policy`), RBAC role
matrix (200/403 per role), gzip export with identity filter — full
suite green, 82.6% coverage, worst-case evaluator at 3.5µs.
