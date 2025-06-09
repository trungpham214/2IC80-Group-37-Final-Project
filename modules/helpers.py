from scapy.all import ARP, Ether, srp

def get_mac(ip):
    '''
    Get the MAC address of the target or gateway
    '''
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    attempts = 0
    max_attempts = 10
    
    while attempts < max_attempts:
        try:
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            attempts += 1
            continue
    return None