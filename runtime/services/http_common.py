"""HTTP response and probe helpers; never log request credentials."""
import http.server


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body, content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def probe(self):
        if self.path == "/healthz":
            self.reply(200, b"ok\n")
        elif self.path == "/readyz":
            self.reply(200, b"ready\n")
        else:
            return False
        return True
