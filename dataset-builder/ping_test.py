from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP

dest_ip = "8.8.8.8"
ping = IP(dst=dest_ip, ttl=20) / ICMP()
sr1(ping)
