from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP

dest_ip = "8.8.8.8"
ml_mac = "9c:b6:d0:01:92:ef"
fake_mac = "aa:bb:cc:01:92:ef"
SEND_INTERVAL = 2  # seconds

ping = IP(dst=dest_ip, ttl=20) / ICMP()
sr1(ping)

probereq = RadioTap() / Dot11(
    type=0,
    subtype=4,
    addr1="ff:ff:ff:ff:ff:ff",
    addr2=ml_mac,
    addr3="ff:ff:ff:ff:ff:ff",
) / Dot11Elt(ID="SSID", info="")

while True:
    print(datetime.now())
    sendp(probereq)
    print()
    time.sleep(SEND_INTERVAL)
