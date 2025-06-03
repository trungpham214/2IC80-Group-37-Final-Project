# 2IC80-Final-Project

## Pre-requisite
1. This version is only tested on the macOS operating system.
2. Auto forward function is enabled; if not, run this command:
```bash
sudo sysctl -w net.inet.ip.forwarding=1 
```
3. The attacker is connected to the same Wi-Fi network as the victim(s).

## Instruction
1. Installation
```bash
pip install -r requirements.txt
```

2. Usage
```bash
sudo python3 mitm_tool.py -i <interface> -g <gateway_ip> -t <attack_type> -m <manual>
```
Parameters:
- -i, --interface: Network interface to use (e.g., en0 for macOS, eth0 for Linux)
- -g, --gateway: Gateway IP address
- -t, --type: Attack mode to use (arp: ARP spoofing only (default), dns: DNS spoofing only, ssl: SSL stripping only)
- -m, --manual: set to manual if you want to attack only 1 target, otherwise it will attack all.

If you enable the flag "-m", this will be printed:
```bash
0. ['192.168.0.1', 'TP-Link Corporation Limited', '34:60:f9:55:c8:6c'] !!This is a router
1. ['192.168.0.8', 'Unknown Device', '5c:3e:1b:9d:fb:d7']
2. ['192.168.0.189', 'Apple, Inc.', 'a4:83:e7:bc:08:54']
```
Then select the IP by entering the index, not the IP itself. (This should be improved)

## Limitations
1. This attack only works in a local network due to the scope of the course
2. The DNS attack is hard-coded to attack the domain "example.com"

