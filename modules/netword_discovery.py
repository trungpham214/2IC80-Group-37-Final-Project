from scapy.all import sr1, IP, ICMP
import socket

def ping_sweep(network_prefix):
    live_hosts = []
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp:
            print(f"[+] Host {ip} is up")
            live_hosts.append(ip)
    return live_hosts

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
        live_hosts = ping_sweep(network_prefix)
        print("[*] Live hosts in the network:")
        for host in live_hosts:
            print(host)