from scapy.all import *
from helper import *

if len(sys.argv) < 2:
  print("usage: deauth.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

select_channel(conf.iface)
data = selected_aps(conf.iface)
aps = [data["host_list"][index][0] for index in data["aps"]]

def scan():
  count = ""
  while count.isdigit() != True:
    count = input("number of packets to capture while discovering clients : ")
  count = int(count)

  print()
  print("discovering clients...\n")
  data = discover_clients(conf.iface, aps, count)

  clients = data["found_clients"]
  print("discovered {} clients\n".format(len(clients)))

  if len(clients) != 0:
    for client in clients:
      print(client)
  else:
    print("you might be too far away to pick up device signals")

  rescan = input("\ndo you want to search again? (y/n) : ").lower()
  if rescan == "y":
    scan()

scan()
