# coding=utf-8
from scapy.all import TCP, Ether, ARP
from scapy.sendrecv import sniff, srp
import socket
import time


def show(packet):
    packet[TCP].show()
    print "---------"


srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.211.55.254", hwsrc="00:1c:42:79:4b:d3"), verbose=0, timeout=0.05)

a = sniff(filter="tcp and ip dst 10.211.55.254", store=0, prn=show)
# sniff(filter="tcp and ip dst 10.60.118.75 and port 6666", store=0, prn=show)
