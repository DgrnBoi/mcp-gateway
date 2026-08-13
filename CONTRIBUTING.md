# Contributing to the MCP Security Gateway

Thank you for considering a contribution. This is a **security product that lives in the data plane**: every request to every AI agent in the world that routes through this gateway touches this code. Contributions are welcome, but they are held to the standards below so that the latency budget, architectural constraints, and security guarantees are never degraded.

Please read this document before opening a pull request.

## Architecture You Must Not Break

The gateway's architecture is enforced by CI, not by convention. The design decisions you must preserve are:

1. **Transport-agnostic core.** `pkg/policy`, `pkg/audit`, and `pkg/core` must never import `net/http`. A `grep` gate in CI fails the build if they do. The policy engine must remain a pure Go evaluator that knows nothing about sockets.
2. **Default-deny precedence.** The evaluation order is strict: org deny → team deny → team allow → org allow → default deny. Team policies can never shadow an org invariant (`ErrShadowedInvariant`). If your change alters precedence, it will not be merged regardless of motivation.
3. **Identity-locked quarantine.** Raw quarantined payloads are the most sensitive artifact in the system. The `auditor` role must never gain read access to them, and the export endpoint must remain time-bounded (maximum 90-day window) and streamed in bounded memory.
4. **Fail-closed, never fail-open.** Any component that cannot verify its configuration or state must refuse to serve, not permit traffic.

## Development Workflow

```bash
# 1. Get the code
git clone https://github.com/antigravity-mcp/mcp-gateway.git
cd mcp-gateway

# 2. Run the full suite (the gate uses count=1 to defeat result caching)
go test -count=1 ./pkg/...

# 3. Run the race detector on concurrency-critical packages
CGO_ENABLED=1 go test -race ./pkg/console/ ./pkg/server/ ./pkg/policy/

# 4. Run the latency benchmark gate — your change must stay under 5ms
go test -bench=BenchmarkEvaluate -benchtime=2s ./pkg/policy/

# 5. Verify coverage (CI gate: >= 80% total)
go test -coverprofile=coverage.out ./pkg/...
go tool cover -func=coverage.out | grep -E '^\s*total:'
```

All five checks must be green for your PR to be considered. The CI workflow (` .github/workflows/ci.yml`) runs them automatically, but running them locally first saves everyone's time.

## The Latency Budget

The worst-case evaluator latency is capped at **5,000,000 ns/op** (the mean of the worst-case 200-rule benchmark). This budget exists because the gateway is on the hot path of every agent request; a slow gateway is a denied-of-service attack against your own agents.

- Before adding a rule-matching path, ask whether it can be evaluated in a single comparison.
- Avoid allocations in the evaluator hot path.
- If you add a benchmark, name it `Benchmark*` and keep the worst case under the limit. CI will reject the PR if any benchmark line exceeds 5ms.

## Adversarial Testing Requirement

Every feature or bug fix that touches the data plane or the security boundary **must include adversarial tests**. The fixture format is JSON-RPC payloads in `tests/adversarial/attacks/` (e.g., `sql_injection.json`, `unauthorized_tool.json`), exercised end-to-end by `pkg/server` gateway tests. Concretely:

- New policy semantics → new fixture proving the rule cannot be shadowed or evaded.
- New identity path → fixtures attempting identity spoofing on that path.
- Console changes → tests proving the RBAC matrix and export bounds still hold.
- Bug fixes → a regression test reproducing the exact failure mode first, then the fix.

Fixes without a regression test, or features without adversarial fixtures, will be asked to re-open the PR.

## Code Review Requirements

| Change scope | Review requirement |
|---|---|
| `pkg/policy/*`, `pkg/core/*` | 2 approvals, at least one from a repository maintainer |
| `pkg/console/*`, `pkg/identity/*` | 2 approvals |
| All other packages | 1 approval |

## Coordinated Vulnerability Disclosure

Security researchers must not open public issues for bypasses, identity spoofing, or quarantine failures. Read [`SECURITY.md`](SECURITY.md) for the confidential disclosure process (`security@mcp-gateway.dev`).

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). In short: be respectful, assume good faith, and take disputes to the maintainers rather than into comment threads.

## Licensing

Contributions are accepted under the terms of the [Apache License 2.0](LICENSE). Do not contribute code that you do not have the right to license under Apache 2.0.
