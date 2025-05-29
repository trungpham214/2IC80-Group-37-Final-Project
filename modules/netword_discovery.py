import sys
from scapy.all import srp, Ether, ARP
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import socket

def arp_scan(network_prefix):
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        # Create ARP request packet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        try:
            # Send ARP request and wait for response
            arp_response = srp(arp_request, timeout=1, verbose=0)[0]
            if arp_response:
                mac = arp_response[0][1].hwsrc
                try:
                    vendor = MacLookup().lookup(mac)
                    print(f"[+] Host {ip} is up - MAC: {mac} - Vendor: {vendor}")
                except VendorNotFoundError:
                    print(f"[+] Host {ip} is up - MAC: {mac}")
        except IndexError:
            continue
        except KeyboardInterrupt:
            print("\n[*] Stopping network discovery...")
            sys.exit(0)

def get_network_prefix():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    prefix = '.'.join(local_ip.split('.')[:3])
    return prefix

if __name__ == "__main__":
    network_prefix = get_network_prefix()
    print(f"[*] Detected network prefix: {network_prefix}")
    if network_prefix == "127.0.0":
        print("[!] Could not detect a valid network connection. Exiting.")
    else:
        print("[*] Live hosts in the network:")
        arp_scan(network_prefix)