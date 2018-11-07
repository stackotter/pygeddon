#!/usr/bin/env python
from scapy.all import *
from datetime import datetime
import sys
import time

found = {}

count = 0
threshold = 3
timeout = 1000
last = int(round(time.time() * 1000))

hosts = {}

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
    if count == threshold:
      print("Deauth Attack!!")
      print()
      if ap in hosts:
        print("host   : " + str(hosts[ap]["ssid"])[2:-1])
      else:
        print("host   : unknown")
      print("ap     : " + ap)
      print("victim : " + victim)
      print()
      if input() is "s":
        print()
        print(pkt.show())
        print()
  if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0x08 and hasattr(pkt, 'info'):
    ssid = ( len(pkt.info) > 0 and pkt.info != "\x00" ) and pkt.info or '<hidden>'
    mac = pkt.addr2
    hosts[mac] = {"ssid": ssid, "mac": mac}



if len(sys.argv) < 2:
  print("usage: sniff.py <iface>")
  sys.exit(-1)

sniff(iface=sys.argv[1], prn=sniffmgmt, monitor=True)

# when ctrl + c is pressed, write results to disk
with open('output.txt', 'a') as f:
  f.write(",".join(["ssid", "cli", "lastseen"]) + "\r\n")
  for key in found:
    f.write(",".join(['"%s"' % x for x in [ found[key]['ssid'], found[key]['cli'], found[key]['lastseen']]]) + "\r\n")
