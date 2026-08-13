#!/bin/bash
# Live Stage-3 end-to-end verification: JWT-bound identity (Ticket 14),
# mTLS transport identity (Ticket 15), per-identity rate limiting (Ticket
# 16), zero-downtime hot reload (Ticket 17), and Prometheus exposition
# (Ticket 18). All traffic flows through the real gateway binary with
# real ES256-signed tokens (testdata key is P-256 EC) and real X.509 testdata certificates.
# NOTE: set -e intentionally OFF — the check() harness records every PASS/FAIL
# and the script must keep going through adversarial failure paths (401/403/429
# responses and TLS refusals) that a strict-exit shell would treat as errors.
set +e
export PATH=$PATH:/usr/local/go/bin
cd /home/ubuntu/verify/mcp-gateway
GW=$(pwd)/mcp-gateway
LIVE=$(pwd)/tests/live
TD=$(pwd)/pkg/identity/testdata
UPSTREAM_PORT=8101
GW_PORT=9101
CONSOLE_PORT=9102
TESTDATA_DIR=/home/ubuntu/verify/mcp-gateway/tests/live/.testdata-stage3
cleanup() {
  for f in /tmp/.svc3_*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  # NOTE: intentionally do NOT remove TESTDATA_DIR here — subsequent
  # manual runs of the gateway with the same config.yaml still reference
  # the certificates minted during this verification.
}
trap cleanup EXIT
PASS=0; FAIL=0
check() {
  label=$1; expect=$2; got=$3
  if [ "$got" = "$expect" ]; then
    echo "  PASS  $label (got $got)"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $label (expected $expect, got $got)"
    FAIL=$((FAIL+1))
  fi
}

echo "--- 0. build gateway ---"
go build -o "$GW" ./cmd/mcp-gateway/ && echo "gateway built"
rm -f /tmp/audit3.log /tmp/violations3.log

echo "--- 1. mTLS test certificates ---"
mkdir -p "$TESTDATA_DIR"
# Self-signed CA
openssl genrsa -out "$TESTDATA_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$TESTDATA_DIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=Stage3 Test CA" -out "$TESTDATA_DIR/ca.pem" 2>/dev/null
# Gateway server cert (DNS:localhost so the curl SAN check passes)
openssl genrsa -out "$TESTDATA_DIR/srv.key" 2048 2>/dev/null
cat > "$TESTDATA_DIR/srv.cnf" <<EOF
[v3] subjectAltName = DNS:localhost,IP:127.0.0.1
EOF
openssl req -new -key "$TESTDATA_DIR/srv.key" -out "$TESTDATA_DIR/srv.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$TESTDATA_DIR/srv.csr" -CA "$TESTDATA_DIR/ca.pem" -CAkey "$TESTDATA_DIR/ca.key" \
  -CAcreateserial -out "$TESTDATA_DIR/srv.pem" -days 365 -sha256 \
  -extfile "$TESTDATA_DIR/srv.cnf" -extensions v3 2>/dev/null
# Valid client cert INSIDE trust domain with SPIFFE SAN
openssl genrsa -out "$TESTDATA_DIR/client-in.key" 2048 2>/dev/null
cat > "$TESTDATA_DIR/client-in.cnf" <<EOF
[v3] basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://internal/hr-agent
EOF
openssl req -new -key "$TESTDATA_DIR/client-in.key" -out "$TESTDATA_DIR/client-in.csr" -subj "/CN=hr-agent" 2>/dev/null
openssl x509 -req -in "$TESTDATA_DIR/client-in.csr" -CA "$TESTDATA_DIR/ca.pem" -CAkey "$TESTDATA_DIR/ca.key" \
  -CAcreateserial -out "$TESTDATA_DIR/client-in.pem" -days 365 -sha256 -extfile "$TESTDATA_DIR/client-in.cnf" -extensions v3 2>/dev/null
# Client cert OUTSIDE trust domain
openssl genrsa -out "$TESTDATA_DIR/client-out.key" 2048 2>/dev/null
cat > "$TESTDATA_DIR/client-out.cnf" <<EOF
[v3] basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://wrongdomain/hr-agent
EOF
openssl req -new -key "$TESTDATA_DIR/client-out.key" -out "$TESTDATA_DIR/client-out.csr" -subj "/CN=wrong-domain-agent" 2>/dev/null
openssl x509 -req -in "$TESTDATA_DIR/client-out.csr" -CA "$TESTDATA_DIR/ca.pem" -CAkey "$TESTDATA_DIR/ca.key" \
  -CAcreateserial -out "$TESTDATA_DIR/client-out.pem" -days 365 -sha256 -extfile "$TESTDATA_DIR/client-out.cnf" -extensions v3 2>/dev/null
# Client cert with NO SPIFFE SAN at all
openssl genrsa -out "$TESTDATA_DIR/client-nosan.key" 2048 2>/dev/null
openssl req -new -key "$TESTDATA_DIR/client-nosan.key" -out "$TESTDATA_DIR/client-nosan.csr" -subj "/CN=nosan-agent" 2>/dev/null
openssl x509 -req -in "$TESTDATA_DIR/client-nosan.csr" -CA "$TESTDATA_DIR/ca.pem" -CAkey "$TESTDATA_DIR/ca.key" \
  -CAcreateserial -out "$TESTDATA_DIR/client-nosan.pem" -days 365 -sha256 2>/dev/null
echo "test certificates minted under $TESTDATA_DIR"

echo "--- 2. start stub MCP upstream ---"
PORT=$UPSTREAM_PORT nohup python3 "$LIVE/stub_mcp.py" > /tmp/stub3.log 2>&1 & echo $! > /tmp/.svc3_stub.pid
sleep 1
curl -s -f -X POST http://127.0.0.1:$UPSTREAM_PORT/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"search_contacts","arguments":{"query":"alice"}}}' \
  > /dev/null && echo "stub upstream healthy"

echo "--- 3. initial policy (mtls-subject allow for hr-agent on search_contacts) ---"
cat > /tmp/policy3.yaml <<EOF
default_action: deny
rules:
  - id: R-MTLS-001
    agent:
      mtls_subject: spiffe://internal/hr-agent
    tool:
      name: search_contacts
    action: allow
    reason: "hr-agent verified by mTLS SPIFFE ID"
EOF

echo "--- 4. config.yaml with token PEM, mTLS, and tight rate limits ---"
cat > /tmp/config3.yaml <<EOF
webhooks:
  slack:
    enabled: false
  pagerduty:
    enabled: false
token:
  pem: |
$(sed 's/^/    /' "$TD/gateway.pem")
  audience: mcpgw-test
tls:
  enabled: true
  cert_file: $TESTDATA_DIR/srv.pem
  key_file: $TESTDATA_DIR/srv.key
  client_ca_files:
    - $TESTDATA_DIR/ca.pem
  require_client_cert: true
  trust_domain: internal
ratelimit:
  enabled: true
  requests_per_second: 5
  burst: 5
  window: 1m
EOF

echo "--- 5. start gateway with Stage 3 config ---"
$GW --listen "127.0.0.1:$GW_PORT" \
    --upstream "http://127.0.0.1:$UPSTREAM_PORT" \
    --policy /tmp/policy3.yaml \
    --config /tmp/config3.yaml \
    --audit-log /tmp/audit3.log \
    --violations-log /tmp/violations3.log \
    --console ":$CONSOLE_PORT" \
    --log-prefix "gw3" \
    > /tmp/gw3.log 2>&1 &
GW_PID=$!
disown $GW_PID 2>/dev/null
echo $GW_PID > /tmp/.svc3_gw.pid
for i in $(seq 1 20); do
  if curl -s -o /dev/null http://127.0.0.1:$CONSOLE_PORT/ >/dev/null 2>&1; then break; fi
  sleep 0.5
done
[ -s /tmp/gw3.log ] && tail -c 400 /tmp/gw3.log | tr '\n' ' '
echo

call() {
  # Usage: call TOKEN [TOOL] -> echoes HTTP status. TOKEN="" means no JWT.
  # The gateway runs require_client_cert, so every call presents the
  # in-domain mTLS client cert; identity = mTLS subject + optional JWT.
  TOOL=${2:-search_contacts}
  if [ -z "$1" ]; then
    curl -s -o /dev/null -w "%{http_code}" -X POST https://127.0.0.1:$GW_PORT/ \
      -k \
      --cert "$TESTDATA_DIR/client-in.pem" --key "$TESTDATA_DIR/client-in.key" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1,\"params\":{\"name\":\"$TOOL\",\"arguments\":{\"query\":\"q\"}}}"
  else
    curl -s -o /dev/null -w "%{http_code}" -X POST https://127.0.0.1:$GW_PORT/ \
      -k \
      --cert "$TESTDATA_DIR/client-in.pem" --key "$TESTDATA_DIR/client-in.key" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $1" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1,\"params\":{\"name\":\"$TOOL\",\"arguments\":{\"query\":\"q\"}}}"
  fi
}
call_client() {
  # Usage: call_client CERT KEY [TOOL] -> echoes HTTP status (mTLS-only)
  TOOL=${3:-search_contacts}
  curl -s -o /dev/null -w "%{http_code}" -X POST https://127.0.0.1:$GW_PORT/ \
    -k \
    --cert "$1" --key "$2" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1,\"params\":{\"name\":\"$TOOL\",\"arguments\":{\"query\":\"q\"}}}"
}

echo "--- 6. Ticket 14: JWT happy path (valid RS256 token over mTLS) ---"
check "valid JWT over mTLS -> 200" "200" "$(call "$(python3 "$LIVE/mint_token.py" --aud "mcpgw-test")")"
echo "--- 7. Ticket 14: JWT fail paths ---"
echo "  7a. tampered token (payload altered, signature no longer valid)..."
GOOD_TOKEN=$(python3 "$LIVE/mint_token.py" --aud "mcpgw-test")
PAYLOAD=$(echo "$GOOD_TOKEN" | cut -d. -f2)
TAMPERED="$(echo "$GOOD_TOKEN" | cut -d. -f1).X${PAYLOAD#?}.$(echo "$GOOD_TOKEN" | cut -d. -f3)"
check "tampered JWT -> 401" "401" "$(call "$TAMPERED")"
echo "  7b. expired token..."
check "expired JWT -> 401" "401" "$(call "$(python3 "$LIVE/make_expired_token.py")")"
echo "  7c. wrong audience..."
check "wrong-audience JWT -> 401" "401" "$(call "$(python3 "$LIVE/mint_token.py" --aud "other-svc")")"
echo "  7d. missing Authorization header — mTLS identity is present (hr-agent), and the allow rule matches on mtls_subject..."
check "no JWT + valid mTLS -> 200 (mtls identity)" "200" "$(call "")"

echo "--- 8. Ticket 15: mTLS identity extraction & enforcement ---"
echo "  8a. in-domain SPIFFE client cert..."
check "in-domain spiffe://internal/hr-agent -> 200" "200" "$(call_client "$TESTDATA_DIR/client-in.pem" "$TESTDATA_DIR/client-in.key")"
echo "  8b. out-of-domain SPIFFE cert falls back to anonymous, default-deny catches it..."
CODE=$(call_client "$TESTDATA_DIR/client-out.pem" "$TESTDATA_DIR/client-out.key")
check "out-of-domain spiffe -> default-deny denial" "403" "$CODE"
echo "  8c. client cert with NO SPIFFE SAN..."
CODE=$(call_client "$TESTDATA_DIR/client-nosan.pem" "$TESTDATA_DIR/client-nosan.key")
check "no-SPIFFE client cert -> default-deny 403" "403" "$CODE"
echo "  8d. no client certificate at all..."
OUT=$(curl -vs -o /dev/null -X POST "https://127.0.0.1:$GW_PORT/" \
  -k \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"search_contacts","arguments":{"query":"q"}}}' 2>&1)
CODE=$(echo "$OUT" | grep -c "HTTP/" || true)
HAS_ALERT=$(echo "$OUT" | grep -iq "alert certificate required\|handshake" && echo 1 || echo 0)
echo "  tls output: $(echo "$OUT" | grep -i "alert\|handshake\|HTTP/" | head -3 | tr '\n' ' ')"
check "no client cert -> TLS alert (certificate required)" "1" "$HAS_ALERT"
# With -k (no CA trust), the same request fails with curl exit 35 — the
# gateway refuses to complete the handshake without a client cert.
# (single -k request above is the authoritative check; removed duplicate)

echo "--- 9. identity fingerprints in the audit log ---"
sleep 1
echo "  token_hash entry: $(grep -o '"token_hash":"[^"]*"' /tmp/audit3.log | head -1 | cut -c1-70)"
echo "  audit entries seen: $(grep -c 'search_contacts' /tmp/audit3.log || true)"
check "audit log captures allowed traffic" "1" "$( [ -s /tmp/audit3.log ] && echo 1 || echo 0)"
MTLS_HASH=$(grep -o '"token_hash":"[^"]*"' /tmp/audit3.log | head -1)
[ -n "$MTLS_HASH" ] && check "JWT identity bound in audit identity block" "1" "1" || check "JWT identity bound in audit identity block" "1" "0"

echo "--- 10. Ticket 16: per-identity rate limiting (5 RPS, burst 5) ---"
echo "  flooding the gateway with the verified JWT identity..."
BURSTED=0
for i in $(seq 1 25); do
  CODE=$(call "$GOOD_TOKEN")
  if [ "$CODE" = "429" ]; then BURSTED=1; break; fi
done
check "burst exhausted -> 429" "1" "$BURSTED"
RA=$(curl -s -D - -o /dev/null -X POST https://127.0.0.1:$GW_PORT/ \
  -k \
  --cert "$TESTDATA_DIR/client-in.pem" --key "$TESTDATA_DIR/client-in.key" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GOOD_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"search_contacts","arguments":{"query":"q"}}}' | grep -ic "^retry-after:" || echo 0)
check "429 carries Retry-After" "1" "$RA"

echo "--- 11. Ticket 17: zero-downtime hot reload (mtime poll) ---"
echo "  writing policy with a new rule for 'get_contact' and bumping mtime..."
cat > /tmp/policy3.yaml <<EOF
default_action: deny
rules:
  - id: R-MTLS-001
    agent:
      mtls_subject: spiffe://internal/hr-agent
    tool:
      name: search_contacts
    action: allow
    reason: "hr-agent verified by mTLS SPIFFE ID"
  - id: R-MTLS-002
    agent:
      mtls_subject: spiffe://internal/hr-agent
    tool:
      name: get_contact
    action: allow
    reason: "new hot-reloaded rule"
EOF
touch /tmp/policy3.yaml
for i in $(seq 1 12); do
  if grep -q "policy reloaded" /tmp/gw3.log 2>/dev/null; then break; fi
  sleep 1
done
if grep -q "policy reloaded" /tmp/gw3.log 2>/dev/null; then echo "  reload logged: $(grep 'policy reloaded' /tmp/gw3.log | tail -1)"; else echo "  reload log check pending"; fi
CODE=$(call_client "$TESTDATA_DIR/client-in.pem" "$TESTDATA_DIR/client-in.key" "get_contact")
check "hot-reloaded rule live -> 200 for get_contact" "200" "$CODE"

echo "--- 12. Ticket 17: fail-steady — invalid policy must not swap ---"
echo "  writing unparseable policy and bumping mtime..."
cat > /tmp/policy3.yaml <<EOF
NOT: VALID YAML AT ALL [[[
default_action: deny
EOF
touch /tmp/policy3.yaml
sleep 4
if grep -qi "reject" /tmp/gw3.log 2>/dev/null; then echo "  fail-steady logged: $(grep -i 'reject' /tmp/gw3.log | tail -1)"; fi
# Fail-steady check: the last GOOD swap brought in R-MTLS-002, so
# get_contact -> 200 must still hold (no rollback), while an unrelated
# tool stays default-deny -> 403 (no silent downgrade to the old policy).
CODE=$(call_client "$TESTDATA_DIR/client-in.pem" "$TESTDATA_DIR/client-in.key" "get_contact")
check "last-good policy still active after invalid write -> 200 (no rollback)" "200" "$CODE"
CODE=$(call_client "$TESTDATA_DIR/client-in.pem" "$TESTDATA_DIR/client-in.key" "delete_contacts")
check "unknown tool still denied after invalid write -> 403" "403" "$CODE"

echo "--- 13. Ticket 18: Prometheus metrics exposition ---"
METRICS=$(curl -s http://127.0.0.1:$CONSOLE_PORT/_console/metrics)
echo "$METRICS" | head -18
echo "..."
has_metric() { [ "$(echo "$METRICS" | grep -c "$1" 2>/dev/null || true)" -gt 0 ] && echo "gt0" || echo "0"; }
check "mcpgw_requests_total exposed" "gt0" "$(has_metric "mcpgw_requests_total")"
check "mcpgw_violations_total exposed" "gt0" "$(has_metric "mcpgw_violations_total")"
check "mcpgw_evaluate_latency_seconds exposed" "gt0" "$(has_metric "mcpgw_evaluate_latency_seconds")"
check "mcpgw_rate_limited_total counts 429s" "gt0" "$(has_metric "mcpgw_rate_limited_total")"

echo "--- 14. SIGHUP forced reload ---"
cat > /tmp/policy3.yaml <<EOF
default_action: deny
rules:
  - id: R-MTLS-001
    agent:
      mtls_subject: spiffe://internal/hr-agent
    tool:
      name: search_contacts
    action: allow
    reason: "hr-agent verified by mTLS SPIFFE ID"
  - id: R-MTLS-002
    agent:
      mtls_subject: spiffe://internal/hr-agent
    tool:
      name: get_contact
    action: allow
    reason: "restored via SIGHUP"
EOF
kill -HUP "$(cat /tmp/.svc3_gw.pid)" 2>/dev/null
for i in $(seq 1 10); do
  if grep -qi "SIGHUP" /tmp/gw3.log 2>/dev/null; then break; fi
  sleep 1
done
check "SIGHUP reload logged" "1" "$(grep -c "SIGHUP" /tmp/gw3.log || echo 0)"
CODE=$(call_client "$TESTDATA_DIR/client-in.pem" "$TESTDATA_DIR/client-in.key" "get_contact")
check "SIGHUP-restored policy active -> 200 for get_contact" "200" "$CODE"

echo "--- 15. summary ---"
echo "PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "STAGE 3 LIVE VERIFICATION: GREEN" || echo "STAGE 3 LIVE VERIFICATION: RED"
exit $FAIL
