# coding=utf-8
import time
from scapy.all import TCP, Ether, ARP
from scapy.sendrecv import sniff, srp

# 本机 MAC
mac = "c4:b3:01:cf:fd:5b"

# 虚拟机 MAC
# mac = "00:1c:42:79:4b:d3"

# 本机 IP
# ip = "10.60.201.177"

# 虚拟机 IP
ip = "10.60.201.253"

for _ in range(4):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.60.201.253", hwsrc=mac), verbose=0, timeout=0.05)
from mysocket import MySocket

port = 6666

server = MySocket()

server.bind(sport=port)
# 这个先暂时自己指定 IP，影响不大
server.bindIP(ip)

server.listen()
time.sleep(30)
# socket = server.accept()

# dat = socket.recv()
# print dat
# socket.send("Server say : hi")
# server.close()
# time.sleep(5)
# print server.states
