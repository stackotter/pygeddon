# Output is saved to output.txt when program is terminated (it is also printed to the terminal while running though).
# Remove the channel selection code to make this compatible with linux.
# Weird channel selection glitch at the moment
from scapy.all import *
from datetime import datetime
import sys
import time

if len(sys.argv) < 2:
  print("usage: sniff.py <iface>")
  sys.exit(-1)

# WARNING: The following channel selection code only works on mac. Remove to make the code linux compatible.
# Linux compatibility will be added soon
channel = ""
while channel.isdigit() != True:
  channel = input("channel to use : ")
os.system("nohup /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + conf.iface + " sniff " + channel + " |tee &")
time.sleep(0.5)

found = {}

def sniffmgmt(p):
  stamgmtstypes = (0, 2, 4)
  if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
    ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
    probe = { "ssid": ssid, "cli": p.addr2, "lastseen" : datetime.fromtimestamp(time.time()).isoformat() }
    key = "%s_%s" % (ssid, p.addr2)
    found[key] = probe
    print(probe)

sniff(iface=sys.argv[1], prn=sniffmgmt, monitor=True)

# When ctrl+c is pressed this code writes discovered APs to output.txt
with open('output.txt', 'a') as f:
  f.write(",".join(["ssid", "cli", "lastseen"]) + "\r\n")
  for key in found:
    f.write(",".join(['"%s"' % x for x in [ found[key]['ssid'], found[key]['cli'], found[key]['lastseen']]]) + "\r\n")
