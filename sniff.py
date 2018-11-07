# Output is saved to output.txt when program is terminated (it is also printed to the terminal while running though).

from scapy.all import *
from datetime import datetime
import sys
import time

found = {}


def sniffmgmt(p):
  stamgmtstypes = (0, 2, 4)
  if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
    ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
    probe = { "ssid": ssid, "cli": p.addr2, "lastseen" : datetime.fromtimestamp(time.time()).isoformat() }
    key = "%s_%s" % (ssid, p.addr2)
    found[key] = probe
    print(probe)


if len(sys.argv) < 2:
  print("usage: sniff.py <iface>")
  sys.exit(-1)

sniff(iface=sys.argv[1], prn=sniffmgmt, monitor=True)

# When ctrl+c is pressed this code writes discovered APs to output.txt
with open('output.txt', 'a') as f:
  f.write(",".join(["ssid", "cli", "lastseen"]) + "\r\n")
  for key in found:
    f.write(",".join(['"%s"' % x for x in [ found[key]['ssid'], found[key]['cli'], found[key]['lastseen']]]) + "\r\n")
