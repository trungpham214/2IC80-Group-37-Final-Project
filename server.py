# vhost_http.py
import os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Domain to impersonate
HOSTNAME = "example.com"
# Port to bind; use 80 for standard HTTP
PORT = 8080

class VHostHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Serve your page for example.com
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pretending to be {HOSTNAME}</title>
</head>
<body>
<h1>😈 This is an evil website! 😈</h1>
</body>
</html>
"""
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - [{self.log_date_time_string()}] {fmt%args}")

def run():
    # Ensure static‐relative paths (if you add them later)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = ThreadingHTTPServer(('', PORT), VHostHTTPRequestHandler)
    print(f"[+] HTTP vhost for {HOSTNAME} listening on port {PORT}")
    server.serve_forever()

if __name__ == '__main__':
    run()
