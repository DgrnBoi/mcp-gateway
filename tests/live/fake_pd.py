import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        with open("/tmp/pd_calls.log", "a") as f:
            f.write(json.dumps({"path": self.path, "body": body.decode()[:500]}) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
