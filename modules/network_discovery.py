from scapy.all import srp, Ether, ARP, IP, TCP, sr1, send, ICMP
from mac_vendor_lookup import MacLookup, VendorNotFoundError

class NetworkScanner():
    def __init__(self, gateway, iface, subnet_mask=24, deep_scan=False) -> None:
        self.network = gateway + f'/{subnet_mask}'
        self.ports = [53, 80] # Common ports
        self.deep_scan = deep_scan
        self.iface = iface
        self.victim_list = []
    
    def arp_scan(self):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.network),
                        timeout=5, iface=self.iface)
        for i in ans:
            mac = i.answer[ARP].hwsrc
            ip = i.answer[ARP].psrc
            try:
                vendor = MacLookup().lookup(mac)
            except VendorNotFoundError:
                vendor = 'Unknown Device'
            self.victim_list.append([ip, vendor, mac])  # Use mac directly instead of calling get_mac again
        
        for i, victim in enumerate(self.victim_list):
            print(f"{i}. {victim}")

    def half_syn_scan(self):
        print("[*] Starting Half-open SYN scan...")
        
        for victim_ip, _, _ in self.victim_list:
            print(f"[*] Scanning {victim_ip}...")
            open_ports = []
            for port in self.ports:
                # Craft SYN packet
                syn_packet = IP(dst=victim_ip)/TCP(dport=port, flags="S")
                
                # Send SYN and wait for SYN-ACK or RST
                # sr1 sends the packet and waits for only one reply
                resp = sr1(syn_packet, timeout=1, verbose=0)
                
                if resp:
                    if resp.haslayer(TCP) and resp[TCP].flags == 0x12: # 0x12 is SYN-ACK (S | A)
                        print(f"    [+] Port {port} on {victim_ip} is open (SYN-ACK received)")
                        # Send RST to close the connection without completing handshake
                        # Important: sport of RST should be dport of SYN-ACK, and seq should be ack of SYN-ACK
                        rst_packet = IP(dst=victim_ip)/TCP(dport=resp.sport, flags="R", sport=resp.dport, seq=resp.ack, ack=resp.seq + 1)
                        send(rst_packet, verbose=0) # Use send for fire-and-forget, no need to wait for response
                    elif resp.haslayer(TCP) and (resp[TCP].flags == 0x04 or resp[TCP].flags == 0x14): # 0x04 is RST, 0x14 is RST-ACK
                        print(f"    [-] Port {port} on {victim_ip} is closed (RST received)")
                    elif resp.haslayer(ICMP):
                        # Port is filtered (ICMP type 3, code 1, 2, 3, 9, 10, or 13)
                        print(f"    [!] Port {port} on {victim_ip} is filtered (ICMP received)")
                else:
                    # No response, port might be filtered or host is down
                    print(f"    [*] Port {port} on {victim_ip} did not respond (filtered or host down)")
            
            
            

    def ack_scan(self):
        print("[*] Starting ACK scan...")

        for victim_ip, _, _ in self.victim_list:
            print(f"[*] Scanning {victim_ip} with ACK scan...")
            for port in self.ports:
                ack_packet = IP(dst=victim_ip)/TCP(dport=port, flags="A")
                resp = sr1(ack_packet, timeout=1, verbose=0)

                if resp is None:
                    print(f"    [!] Port {port} on {victim_ip}: Filtered (No response)")
                elif resp.haslayer(TCP) and (resp[TCP].flags == 0x04 or resp[TCP].flags == 0x14): # RST or RST-ACK
                    print(f"    [+] Port {port} on {victim_ip}: Unfiltered (RST received)")
                elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    print(f"    [!] Port {port} on {victim_ip}: Filtered (ICMP unreachable received)")
                else:
                    print(f"    [?] Port {port} on {victim_ip}: Unexpected response (0x{resp[TCP].flags:02x})")

    def start(self):
        print("[*] Start scanning network:")
        self.arp_scan()
        if self.deep_scan:
            self.half_syn_scan()
            self.ack_scan()

if __name__ == "__main__":
    scanner = NetworkScanner('192.168.0.156', 'en0', 24)  # Updated gateway IP to match your network

    print("[*] Start scanning network:")
    scanner.start()