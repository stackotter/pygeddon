#!/usr/bin/env python
from scapy.all import *
from datetime import datetime
import sys
import time

hosts = {}

count = 0
threshold = 3 # Number of deauth frames that need to be detected within timeout milliseconds of eachother to trigger system
timeout = 100000 # Maximum amount of time between deauth frames for it to be considered an attack (in milliseconds)
last = int(round(time.time() * 1000))

if len(sys.argv) < 2:
  print("usage: deauth-detect.py <iface>")
  sys.exit(-1)

# WARNING: The following channel selection code only works on mac. Remove to make the code linux compatible.
# Select channel
channel = ""
while channel.isdigit() != True:
  channel = input("channel to use : ")
os.system("nohup /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + conf.iface + " sniff " + channel + " &")
time.sleep(0.5)

def sniffmgmt(pkt):
  global last
  global count
  stamgmtstypes = (0, 2, 4)
  if pkt.haslayer(Dot11Deauth):
    if int(round(time.time() * 1000)) - last > timeout:
      count = 0
    count += 1
    ap = pkt.addr2
    victim = pkt.addr1
    last = int(round(time.time() * 1000))

    # Print deauth frame details
    if count == threshold:
      print("Deauth Attack!!")
      print()
      if ap in hosts:
        print("host   : " + str(hosts[ap]["ssid"])[2:-1])
      else:
        print("host   : unknown")
      print("ap     : " + ap)
      print("victim : " + victim)
      print("press s and then enter for details, press enter to continue")
      if input() is "s":
        print()
        print(pkt.show())
        print()
  # If packet is beacon packet add it to a dictionary for converting mac adresses to SSIDs
  if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0x08 and hasattr(pkt, 'info'):
    ssid = ( len(pkt.info) > 0 and pkt.info != "\x00" ) and pkt.info or '<hidden>'
    mac = pkt.addr2
    hosts[mac] = {"ssid": ssid, "mac": mac}

print()
print("Started Sniffing")

sniff(iface=sys.argv[1], prn=sniffmgmt, monitor=True)

# Uncomment to save discovered APs to output.txt
# with open('output.txt', 'a') as f:
#   f.write(",".join(["ssid", "cli", "lastseen"]) + "\r\n")
#   for key in hosts:
#     f.write(",".join(['"%s"' % x for x in [ hosts[key]['ssid'], hosts[key]['cli'], hosts[key]['lastseen']]]) + "\r\n")
