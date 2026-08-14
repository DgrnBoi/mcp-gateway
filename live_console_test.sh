#!/bin/bash
# Live Stage-2 console integration test.
set -e
export PATH=$PATH:/usr/local/go/bin
GW=/home/ubuntu/verify/gateway-bin
UPSTREAM_PORT=8089
GW_PORT=9090
CONSOLE_PORT=9091

# Stub MCP upstream (lightweight Go program served separately)
cat > /tmp/stub_mcp.go <<'STUB'
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     any             `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "tools/call" {
			var p struct {
				Name string          `json:"name"`
				Args json.RawMessage `json:"arguments"`
			}
			json.Unmarshal(req.Params, &p)
			fmt.Printf("upstream: tool=%s args=%s\n", p.Name, string(p.Args))
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": "ok from upstream"}}}})
	})
	fmt.Println("stub ready")
	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}
STUB
echo "(stub prepared)"

killall -q mcpgateway stub 2>/dev/null || true

# build gateway
cd /home/ubuntu/verify/mcp-gateway
go build -o $GW ./cmd/mcp-gateway/
echo "gateway built"

# start stub
PORT=$UPSTREAM_PORT nohup go run /tmp/stub_mcp.go >/tmp/stub.log 2>&1 &
STUBPID=$!
sleep 2

# start gateway with console
POLICY=/home/ubuntu/verify/gw_policy.yaml
nohup $GW --policy $POLICY --upstream http://localhost:$UPSTREAM_PORT --listen :$GW_PORT --console :$CONSOLE_PORT --audit-log /tmp/audit.log --violations-log /tmp/violations.log >/tmp/gw.log 2>&1 &
GWPID=$!
sleep 2

echo "=== 1. allowed call ==="
curl -s -X POST http://localhost:$GW_PORT/mcp -H "Content-Type: application/json" -H "X-Client-Id: sales-copilot" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_contacts","arguments":{"query":"x"}}}' | head -c 200
echo

echo "=== 2. denied call ==="
curl -s -X POST http://localhost:$GW_PORT/mcp -H "Content-Type: application/json" -H "X-Client-Id: sales-copilot" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"export_contacts_bulk","arguments":{"limit":10000}}}' | head -c 200
echo

echo "=== 3. UI root ==="
curl -s -o /dev/null -w "UI: %{http_code}\n" http://localhost:$CONSOLE_PORT/_console/

echo "=== 4. audit API ==="
curl -s "http://localhost:$CONSOLE_PORT/_console/api/audit?offset=0&limit=10" | python3 -m json.tool | head -20

echo "=== 5. violations API ==="
QID=$(grep -o '"quarantine_id":"Q-[0-9]*"' /tmp/violations.log | head -1 | grep -o 'Q-[0-9]*')
echo "quarantine_id: $QID"
curl -s "http://localhost:$CONSOLE_PORT/_console/api/violations/$QID" | head -c 300
echo

echo "=== 6. SSE stream opens ==="
curl -sN -m 3 "http://localhost:$CONSOLE_PORT/_console/api/events/stream" | head -c 200
echo

kill $GWPID $STUBPID 2>/dev/null || true
echo "=== LIVE CONSOLE TEST COMPLETE ==="
