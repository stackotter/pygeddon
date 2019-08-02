import sys
from scapy.all import *
from helper import *

if len(sys.argv) < 2:
  print("usage: sniff.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

select_channel(conf.iface)

found = discover_aps(conf.iface)["found"]

for key in found:
  print("ssid : {} | mac : {}".format(found[key]['ssid'], found[key['cli']]))

write_results = input("write results to file? (Y/n) ").lower() == "y"

if write_results:
  with open('output.txt', 'a') as f:
    f.write(",".join(["ssid", "cli"]) + "\r\n")
    for key in found:
      f.write(",".join(['"%s"' % x for x in [ found[key]['ssid'], found[key]['cli'] ]]) + "\r\n")
