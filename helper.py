from scapy.all import *
import os
import sys

found_aps = {}
found_clients = set()
selected_aps = []

def select_channel(iface):
  channel = ""
  while channel.isdigit() != True:
    channel = input("channel to use : ")

  if sys.platform.startswith('darwin'):
    os.system("nohup /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + iface + " sniff " + channel + " |tee &")
    time.sleep(0.5)

  if sys.platform.startswith('linux'):
    os.system("iwconfig " + conf.iface + " channel " + channel)

  return channel

def spoof_mac(iface, mac):
  cmd = "sudo ifconfig " + iface + " ether " + mac
  print("executing sudo command : " + cmd)
  os.system(cmd)
  print("mac address changed")

def sniff_aps(p):
  global found_aps
  stamgmtstypes = (0, 2, 4)
  if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
    ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
    probe = { "ssid": ssid, "cli": p.addr2 }
    key = "%s" % (p.addr2)
    found_aps[key] = probe

def sniff_clients(p):
  global found_clients
  if p.haslayer(Dot11):
    if p.addr1 and p.addr2:
      packet_ap = p.addr1.lower()
      packet_client = p.addr2.lower()
      if packet_ap in selected_aps:
        found_clients.add(packet_client)

def discover_aps(iface):
  global found_aps
  host_list = []
  aps = []

  # Capture n number of packets and use them to generate a list of available APs, their mac addresses and their SSIDs
  n = ""
  while n.isdigit() != True:
    n = input("number of packets to capture : ")
  n = int(n)

  if sys.platform.startswith('darwin'):
    sniff(iface=iface, prn=sniff_aps, monitor=True, count=n)
  else:
    sniff(iface=iface, prn=sniff_aps, count=n)

  # Make an array version of found_aps so that each AP has a number associated with it for the user to choose
  for key,probe in found_aps.items():
    item = [key,probe]
    host_list.append(item)

  # Print out the list of discovered APs and their index so that the user can choose one
  for i in range(len(host_list)):
    item = host_list[i]
    print(str(i) + " : " + str(item[1]["ssid"])[2:-1] + " : " + item[1]["cli"])

  # Get & process user input
  n = ""
  while n.replace(",", "").isdigit() != True:
    n = input("target AP (r - rescan, q - quit, use commas to seperate multiple APs) : ")
    if n == "r":
      return discover_aps(iface)
    elif n == "q":
      sys.exit()

  aps = list(map(int, n.replace(" ", "").split(",")))

  response = {
    "aps": aps,
    "host_list": host_list
  }
  return response

def discover_clients(iface, aps, count):
  global found_clients
  global selected_aps
  selected_aps = aps
  if sys.platform.startswith('darwin'):
    sniff(iface=iface, prn=sniff_clients, monitor=True, count=count)
  else:
    sniff(iface=iface, prn=sniff_clients, count=count)
  response = {
    "found_clients": found_clients
  }
  return response
