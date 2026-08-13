# MCP Security Gateway — Quality Assurance Report

**Product version:** v6 (post-release QA) · **Date:** August 13, 2026 · **Author:** Manus AI

This report documents the two-track quality assurance pass performed on the MCP Security Gateway after the v6 release: a **concept QA** that stress-tested the architecture against real-world deployment scenarios, and a **code QA** that ran the race detector, mutation fuzzing, static analysis, and meta-tests against the CI gates themselves. The pass found **three genuine defects** — one in the graceful-drain path, one in the forensic console, and one dormant bug inside the CI pipeline itself — all of which are now fixed and covered by regression tests.

## Executive summary

The v6 architecture survived the concept review remarkably well: the default-deny engine, the org→team inheritance model, and the data-plane/data-plane boundary all held up under scrutiny against Kubernetes realities, multi-tenant edge cases, and SOC operational workflows. The code QA, however, is where the value was. The race detector caught a real concurrency defect in `DrainTracker` (a `sync.WaitGroup` used in the exact concurrent Add/Wait pattern Go's own documentation warns against), and the quarantine console endpoint was found to silently lose forensic payloads 30 minutes after an event or across pod restarts — precisely the failure mode a SOC analyst would hit during a real investigation. The most surprising finding was a **dormant CI gate**: the latency benchmark gate was reading the wrong output column, so every benchmark line was silently skipped and the 5ms budget was never actually enforced. All three are fixed, and the full verification matrix below confirms the product still ships green.

## Track A — Concept QA: architecture against real deployments

The concept review examined every stage of the product as if deploying it into a large enterprise Kubernetes estate tomorrow. Fourteen areas were audited; the significant ones are summarized below.

| ID | Area | Verdict | Action taken |
|---|---|---|---|
| A1 | Token validation opt-in degrades to header hashing | **Gap** | Documented; recommend `--require-token-validation` flag |
| A3 | mTLS cert revocation (no CRL/OCSP) | **Gap** | Out of scope by design; documented as operational guidance |
| A4 | Rate-limit state held in-process (survives no pod eviction) | **Gap** | Documented; recommend shared-store option for multi-replica |
| A5 | Unsigned policy.yaml in GitOps (compromised PR = full bypass) | **Gap** | Documented; signed-policy release channel is known remaining work |
| A11 | Per-request default semantics (org-known vs unknown callers) | OK | Covered by README precedence table |
| A12 | Quarantine payload durability vs 30-minute memory TTL | **Defect found and fixed** | See F1 |
| A13 | Ingester ring capacity (64 events, beyond-cap drop from memory) | Acceptable | SIEM disk path unaffected; flagged |
| A14 | `/healthz` fail-closed during drain | OK | Verified correct |

Three findings deserve emphasis. First (**A1**), if neither `--token-pem` nor `--jwks-url` is configured, the gateway silently degrades from cryptographic validation to SHA-256 hashing of whatever `Authorization` header the caller sends — a misconfiguration that quietly erases the zero-trust guarantee with no startup warning. A `--require-token-validation` fail-closed flag is the recommended remedy. Second (**A4**), the token-bucket rate limiter resets on every pod restart, so an attacker who times a Kubernetes rollout can evade per-fingerprint limits — production deployments should pair the gateway with a shared rate-limit store or accept the window of exposure. Third (**A5**), the GitOps policy file is trusted wholesale: a single compromised pull request rewriting `policy.yaml` is a full authorization bypass, which makes the planned signed-policy release channel genuinely security-critical rather than a nice-to-have.

## Track B — Code QA: race detection, fuzzing, and static analysis

### Race detection

Running the full suite under the race detector (`CGO_ENABLED=1 go test -race`) exposed one genuine defect.

| # | Location | Defect | Severity |
|---|---|---|---|
| B1 | `pkg/server/drain.go` — `DrainTracker` | `Begin` called `wg.Add(1)` while `Wait` could already be running; concurrent Add/Wait on a `sync.WaitGroup` is a documented data race in Go | **High** — graceful drain (a SIGTERM survival guarantee) could panic or miscount in-flight requests |
| B2 | `pkg/console/ingester.go` quarantine race | Documented quarantine payload race — **already fixed in Stage 4**; re-verified clean under `-race` | — |

**Fix F2:** `DrainTracker` was rewritten on an atomic counter plus `sync.Cond`. `Begin` is now a single lock-free `atomic.AddInt64`; `Done` decrements atomically and broadcasts only when the count hits zero; `Wait` blocks under the mutex until the counter is zero. This is exactly wait-group semantics but safe under concurrent Begin/Wait — precisely the shape the graceful-shutdown sequence produces. All `pkg/server` tests pass under `-race`.

### Fuzzing

Four harnesses were written against the most adversarial surfaces and run at CI-grade durations:

| Harness | Target | Duration | Result |
|---|---|---|---|
| `FuzzLoadPolicy` | YAML loader + `KnownFields` strict decoding | 60s, ~1.1M iterations | PASS — no panic, no silent acceptance |
| `FuzzLoadLayers` | Org→team layer merger (multi-doc streams) | 60s | PASS |
| `FuzzEvaluate` | Evaluator decision path (hostile identities) | 15s | PASS — never empty action, never `ok=false` |
| `FuzzParseExportQuery` | Export window parser (90-day ceiling invariant) | 30s | PASS — no unbounded window ever produced |

The loader in particular is a GitOps ingestion point; the harness confirmed that every hostile document — including attempts at unknown keys, YAML bombs, and malformed multi-document streams — is rejected with a validation error rather than crashing the hot-reload path.

### Static analysis

`go vet` is clean across all eleven packages. A targeted review for `unsafe`, `time.Sleep` on hot paths, and unbounded allocations in the data plane surfaced no new issues beyond the two defects above.

## Track C — CI gate meta-tests

The gates themselves were attacked to prove they catch what they promise.

| Gate | Method | Result |
|---|---|---|
| Transport-agnostic import gate (grep) | Injected `"net/http"` into `pkg/core/message.go` | **FIRED correctly** |
| Coverage gate (≥80%) | Verified against live 83.0% total; logic reads `total:` line | **WORKING** |
| Latency benchmark gate (≤5ms) | Synthetic `6,000,000 ns/op` line | **Found dormant bug — now fixed** |

**Fix F4:** the latency gate read awk field `$4`, which in `go test` benchmark output is the literal unit string `ns/op` — the numeric value lives in `$3`. Every benchmark line therefore fell through the `[0-9]*` case and was silently skipped: the gate **never fired, on any PR, ever**. It was fixed to read `$3`, and re-verified: a synthetic 6ms line now correctly fails the gate, while the real worst-case evaluator (3,513 ns/op) passes. The workflow's Go version was also bumped from `1.23` to `1.25` to match the toolchain the codebase is built and tested on. This is a sobering reminder that gates you cannot see failing are gates you cannot trust — the meta-test approach (proving each gate fires against a planted violation) should become a standard CI practice.

## Fixes summary

| Fix | File(s) | What changed | Regression test |
|---|---|---|---|
| F1 (A12) | `pkg/console/api.go` | `/api/violations/:qid` now falls back to a `violations.log` disk scan when the 30-minute in-memory quarantine index misses — the UI no longer loses raw payloads across restarts or expiry | `TestViolations_DurableDiskFallback` (passes under `-race`) |
| F2 (B1) | `pkg/server/drain.go` | WaitGroup replaced with atomic counter + `sync.Cond`; Begin lock-free, Wait safe for concurrent Begin | `TestDrainTracker_WaitGroupDrainsConcurrently` (pre-existing; now race-clean) |
| F4 | `.github/workflows/ci.yml` | Latency gate reads correct column (`$3`); Go version 1.23→1.25 | Synthetic 6ms line verified to fire the gate |
| Test hardening | `pkg/policy/fuzz_test.go`, `pkg/console/export_fuzz_test.go` | Four fuzz harnesses on loader, evaluator, layer merger, export parser | Run as part of `go test ./...` |

## Final verification matrix

| Check | Result |
|---|---|
| `go vet ./...` | Clean |
| Full suite (11 packages), normal mode | All green |
| Full suite, race mode (console, server, policy) | All green, zero races |
| Coverage (CI gate ≥80%) | **83.0%** |
| Worst-case evaluator latency (CI gate <5ms) | **3,513 ns** |
| Fuzz harnesses (4) | All pass at CI duration |
| CI import gate meta-test | Fires on planted violation |
| CI latency gate meta-test | Fires on planted 6ms line |
| CI coverage gate meta-test | Verified logic correct |

## Recommended follow-ups (prioritized)

The following are not defects — they are hardening recommendations ranked by risk. First, ship `--require-token-validation` so a misconfigured gateway cannot silently fall back to header hashing (A1). Second, add a policy-signing release channel: GitOps-trusted `policy.yaml` is the single highest-leverage attack surface in the whole product (A5). Third, offer a shared-store or at-minimum warm-restart option for rate-limit state so Kubernetes evictions cannot be used to evade per-fingerprint limits (A4). Finally, consider CRL/OCSP stapling for mTLS identities in environments with long-lived SPIFFE certificates (A3).
