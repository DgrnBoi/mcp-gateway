# Stage 3 Live Test — Working Notes (internal)

## Environment facts
- Repo: /home/ubuntu/verify/mcp-gateway (not a git repo).
- Go binary: `./mcp-gateway` (built via `go build ./cmd/mcp-gateway/`).
- Flags: --listen :9090 (default), --upstream, --policy, --config, --audit-log,
  --violations-log, --console ":PORT", --log-prefix "gw3". NO --watch-policy or
  --reload-log flags; hot reload is automatic (2s mtime poll) + SIGHUP force reload.
- config.yaml sections: webhooks, token (pem, audience), tls (enabled, cert_file,
  key_file, client_ca_files, require_client_cert, trust_domain),
  ratelimit (enabled, requests_per_second, burst, window, include_in_alerts).
- Metric names use `mcpgw_` prefix: mcpgw_requests_total, mcpgw_violations_total,
  mcpgw_rate_limited_total, mcpgw_evaluate_latency_seconds. Console metrics at
  /_console/metrics.
- Denied decisions return HTTP 403 (policy deny); invalid JWT returns 401.
- Require_client_cert=true: no-client-cert curl -> 000 exit 35 (TLS handshake refused).
- Testdata key pkg/identity/testdata/gateway-key.pem is P-256 EC -> sign ES256.
  Go verifier expects fixed-length r||s (RFC 7515), NOT DER — use
  cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature.
- Live test ports: stub MCP 8101, gateway 9101, console 9102.
- Live certs minted in tests/live/.testdata-stage3 (kept between runs — do not
  delete; config references them).

## Live test script
- tests/live/stage3_live_test.sh (15 sections, check() PASS/FAIL counter).
- helpers: tests/live/mint_token.py (--kid/--aud/--exp), tests/live/make_expired_token.py
  (expired exp + valid-length signature, so claim-check fails not signature length).
- Known quirk: `bash -n` shows final paren balance +2 — the two extra '(' are inside
  comments/dummy lines? Actual bash -n error: "line 328: unexpected EOF while looking
  for matching ')'" — caused by the embedded single-quoted JSON in a command
  substitution at line 215 (curl -k line: single quotes around JSON fine; actual cause
  was earlier stray ')' removed; current state: re-run bash -n after last fix).

## Remaining fixes to verify
1. make_expired_token.py: imports fixed (asymmetric.utils) — VERIFY it runs.
2. bash -n must pass; then full re-run.
3. Expect ~all PASS: sections 6-14 fixed.

## Last run results (before fixes)
PASS=14 FAIL=7. Failing then: 7b (expired helper), 8d x2 (expected ERR got 000),
12 (old-rule expectation), 13 x4 (metric prefix). All fixed since.
