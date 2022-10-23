from scapy.layers.l2 import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import *
import socket

clients = []


# Get Address IP


# Scan address IP using scapy
def scanARPPING(ip):
    #My code
    print("Scanning...")
    arp_request=ARP(pdst=ip)
    brodcast=Ether(dst="ff:ff:ff:ff:ff:ff")
    arp=brodcast/arp_request
    answered=srp(arp, timeout=1,verbose=False)[0]
    for element in answered:
        print("IP:{}".format(element[1].psrc))
        print("MAC address: {}\n".format(element[1].hwsrc))

def scanARPPING2(ip):
    # Code from scapy documentation and it's also not detecting any devices
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2)
    ans.summary(lambda r,s: r.sprintf("%Ether.src% %ARP.psrc%"))


def TCPPing(ip):
    ans, unans = srp(IP(dst=ip)/TCP(dport=(1,1024), flags="S"), timeout=5)
    ans.show()

def DeterminateOs(ip):
    ans = sr1(IP(dst=ip)/ICMP(), timeout=5)
    ttl = ans[IP].ttl
    if ttl == 128:
        print("Os System ==> Windows")
    elif ttl == 64:
        print("Os System ==> Linux")
    else:
        print("Os System ==> Not Found")

def UPDPing(ip):
    ans, unans = srp(IP(dst=ip)/UDP(dport=(1,1024)), timeout=5)
    ans.show()


address = ""
mac = ""
arp = ""

for ping in range(102,254):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    Addrs = s.getsockname()[0]
    while Addrs[-1] != ".":
        Addrs = Addrs[:-1]
    Addresses = Addrs + str(ping)
    socket.setdefaulttimeout(1)
    try:
        hostname, alias, addresslist = socket.gethostbyaddr(Addresses)
        arping(Addresses)
        DeterminateOs(Addresses)
        print(addresslist, '=>', hostname)
    except socket.herror:
        hostname = None
        alias = None
        addresslist = None














