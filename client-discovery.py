# This does not work at the moment
import sys
print("\n!IMPORTANT! : This file does not work yet\n")
sys.exit()

from scapy.all import *

def sniffmgmt(p):
    stamgmtstypes = (0, 2, 4)
    if p.haslayer(Dot11):
        if p.type == 0 and p.subtype in stamgmtstypes:
            if p.addr2 not in CliList:
                print(p.addr2)
                CliList.append(p.addr2)

sniff(iface=conf.iface, prn=sniffmgmt, count=n)
