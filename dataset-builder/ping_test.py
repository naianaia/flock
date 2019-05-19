from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP

packet = IP(dst="192.168.86.131", ttl=20) / ICMP()
reply = sr1(packet)
print(reply)

RadioTap() / Dot11(
    type=0,
    subtype=4,
    addr1="ff:ff:ff:ff:ff:ff",
    addr2="00:11:22:33:44:55",
    addr3="ff:ff:ff:ff:ff:ff",
) / Dot11Elt(ID="SSID", info="")
