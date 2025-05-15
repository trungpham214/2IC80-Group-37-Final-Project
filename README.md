# 2IC80-Final-Project

## Instruction
1. Installation
```bash
pip install -r requirements.txt
```

2. Usage
```bash
sudo python3 mitm_tool.py -i <interface> -t <target_ip> -g <gateway_ip> -m <mode>
```
Parameters:
- -i, --interface: Network interface to use (e.g., en0 for macOS, eth0 for Linux)
- -t, --target: Target IP address
- -g, --gateway: Gateway IP address
- -m, --mode: Attack mode to use (arp: ARP spoofing only, dns: DNS spoofing only, ssl: SSL stripping only, all: All attacks (default))
## Minutes
Meeting 1:
Discusses LAB relation to project and decided that it can be applied if we get "plug and play" to work.
Then discussed what we thing an automated tool would look like and decided to ask during next lab.
Decided to try and finish ARP and DNS by the end of week 4. Try and work on the sniffing tool meanwhile.
Ask for direction during lab as proceeding further seems unclear
