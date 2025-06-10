from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Simple HTML response
        html = """
        <html>
            <head>
                <title>Simple HTTP Server</title>
            </head>
            <body>
                <h1>Welcome to Simple HTTP Server</h1>
                <p>This is a basic HTTP server running on port 8080.</p>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

def run_server():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print('Starting server on port 8080...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
