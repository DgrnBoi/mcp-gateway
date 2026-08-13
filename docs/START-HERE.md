# The DIY Kit

## Start Using the MCP Security Gateway Today — Open Source, Zero Guesswork

**Author:** Manus AI · **License:** Apache 2.0 (the whole project) · **Date:** August 13, 2026

This is the simplest possible on-ramp to the MCP Security Gateway. It assumes you have never seen the codebase before. By the end of Part 1 you will have a running gateway protecting a toy tool server. By the end of Part 3 you will know how to evolve it into something yours. Everything referenced lives in the v6 release tarball (`mcp-gw-v6.tar.gz`); all filenames are short and Windows-friendly.

---

## Part 0 — What This Thing Is (2 minutes)

Imagine your AI assistant (Claude Desktop, a custom agent, anything that talks Model Context Protocol) reaching into your company's servers to run tools — SQL queries, service restarts, file operations. Right now, almost nothing stands between the agent and the server: no policy, no identity check, no log of who asked for what. The MCP Security Gateway is that missing layer. It is a small Go program that sits in front of your MCP server and enforces one rule on every single request:

> **Identity first, policy second, deny by default.** If we cannot verify who is asking, or the request is not explicitly allowed, it does not happen — and if it's denied, the attempt is quarantined with its sensitive parts redacted and streamed to your security logs.

The whole decision takes **3.47 microseconds** in the worst case (across 200 rules), so the gateway is invisible in practice. It deploys as a ~15MB container in Kubernetes, or as a plain binary on any machine.

## Part 1 — Run It in Five Minutes

**What you need:** Go 1.22+ (or just Docker), a terminal, five minutes.

```bash
# 1. Unpack the release
tar -xzf mcp-gw-v6.tar.gz
cd mcp-gw-v6

# 2. Start a toy MCP server (or point --upstream at your real one)
go run ./cmd/stub-mcp-server --port 8090   # included test server

# 3. Start the gateway in front of it
go run ./cmd/mcpgateway \
  --policy examples/policy.yaml \
  --upstream http://127.0.0.1:8090 \
  --listen 127.0.0.1:8080

# 4. From another terminal, hit the gateway the way an agent would
curl -X POST http://127.0.0.1:8080 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"db.execute_sql","arguments":{"q":"SELECT 1"}}}'
```

Watch what happens: a call to an allowed tool passes through; a call to `db.execute_sql` from an unknown agent is **denied**, and a line appears in `audit.log` with a quarantine ID (`qid`). Open `audit.log` — that is the whole product in one file.

**With Docker instead:**

```bash
docker run -p 8080:8080 \
  -v $(pwd)/examples/policy.yaml:/etc/gw/policy.yaml \
  mcp-gateway:v6 \
  --policy /etc/gw/policy.yaml --upstream http://host.docker.internal:8090
```

## Part 2 — Write Your First Policy (10 minutes)

All rules live in `examples/policy.yaml`. Open it and read the three sentences at the top:

```yaml
version: "1.0"
default_action: deny        # nothing happens unless a rule says so
rules:
  - id: R-001
    action: deny            # block it
    agent: "finance-agent"
    tool: "db.execute_sql"

  - id: R-002
    action: deny_with_redact   # block it AND strip secrets from the evidence
    agent: "*"
    tool: "db.*"
    redact_fields: ["connection_string", "raw_query"]
    expires_at: "2026-12-31T23:59:59Z"
    reason: "pending schema audit"

  - id: R-003
    action: allow           # the rare explicit yes
    agent: "hr-agent"
    tool: "hr.lookup_employee"
    expires_at: "2027-06-30T23:59:59Z"
    reason: "HR service launch"
```

The muscle memory to build:

| Situation | What you write |
| --- | --- |
| New agent onboarded | An `allow` rule with a `reason` and an `expires_at` — no exceptions |
| Tool misbehaves | A `deny` rule, restart the gateway (or edit live — hot reload is on) |
| Sensitive tool queried | `deny_with_redact` so the attempt is evidence, not just noise |
| Emergency access | `allow_all` — but only with `reason` + `expires_at`; the schema refuses it otherwise |

Reload happens automatically when you save the file — no dropped connections. The CI gates guarantee nobody can ever commit a policy loader that forgets the default-deny default.

## Part 3 — Deploy It For Real

**Standalone:** `mcpgateway` binary + config + a systemd unit. Point your agents at the gateway's address instead of the server's.

**Kubernetes sidecar (the designed pattern):**

```bash
helm install mcp-gw deploy/helm/mcp-gateway/ \
  --set upstream=http://your-mcp-server:8080
```

The chart installs the Deployment, Service, ConfigMap (your policy), Secret (your certs), and probes. Every request your agents make now passes through the guard.

**Wire an agent:** in Claude Desktop (or your agent config), change the MCP server URL from `http://mcp-server:8080` to `http://gateway:8080`. That is the only change on the agent side.

## Part 4 — Verify It Is Doing Its Job

Three checks, thirty seconds each. First, `tail -f audit.log` while an agent works — every call should appear with identity, tool, action, and rule ID. Second, fire an unauthorized call (the repo ships attack fixtures in `tests/adversarial/attacks/`) and confirm a `qid` quarantine line lands. Third, run the benchmark: `go test -bench=Evaluator ./pkg/policy/` — if worst case is anywhere near 5ms, something is wrong; our reference lands at 3.47µs.

## Part 5 — Make It Yours (the evolution path)

The project was deliberately built so each layer can be extended independently. Where to reach for what:

| You want to... | Touch | Start here |
| --- | --- | --- |
| Add new rule types | `pkg/policy/` | the Evaluator is pure Go; tests run against in-memory policies |
| Support a new transport | `pkg/transport/` | the normalizer maps SSE/Streamable HTTP/POST to one message shape |
| Change redaction | `pkg/enforcement/rewrite.go` | the map-cleanup logic, with its own tests |
| Add a notifier | `pkg/notify/` | Slack/PagerDuty workers, deterministic rate-limit tests |
| Build your own console | `pkg/console/` | JWT auth + RBAC middleware already wired |
| Contribute | `CONTRIBUTING.md` | run `go test -count=1 ./...`, keep the latency gate green, add adversarial tests for new features |

Security findings go to the address in `SECURITY.md` — never a public issue.

---

**That is the whole kit:** run it, write a policy, deploy it, verify it, extend it. The rest of the repo — 17 ADRs, the QA log, the SDLC workbook — is the story of how it got built, there if you want it. Open source, Apache 2.0, no strings.
