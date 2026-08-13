import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n))
        params = req.get("params") or {}
        if req.get("method") == "tools/call":
            print(f"upstream: tool={params.get('name')} args={params.get('arguments')}")
        print(f"upstream: x-mcpgw-identity={self.headers.get('X-Mcpgw-Identity', '')}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc":"2.0","id":req.get("id"),"result":{"content":[{"type":"text","text":"ok"}]}}).encode())
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
