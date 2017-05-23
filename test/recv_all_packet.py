# coding=utf-8
from scapy.all import TCP, Ether, ARP
from scapy.sendrecv import sniff, srp
import socket
import time


def show(packet):
    packet[TCP].show()
    print "---------"


srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.211.55.253", hwsrc="00:1c:42:79:4b:d3"), verbose=0, timeout=0.05)

a = sniff(filter="tcp and  ip src 10.211.55.253", store=0, prn=show)
