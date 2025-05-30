from scapy.all import srp, Ether, ARP
from mac_vendor_lookup import MacLookup, VendorNotFoundError

class NetworkScanner():
    def __init__(self, gateway, iface, prefix_length=24) -> None:
        self.network = gateway + f'/{prefix_length}'
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
            print(f'{ip} ({vendor})')
            self.victim_list.append(ip)

    def start(self):
        print("[*] Start scanning network:")
        self.arp_scan()

if __name__ == "__main__":
    scanner = NetworkScanner('192.168.0.1', 'en0')

    print("[*] Start scanning network:")
    scanner.start()