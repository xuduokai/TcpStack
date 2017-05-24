# coding=utf-8
import time
from scapy.all import TCP, Ether, ARP
from scapy.sendrecv import sniff, srp

# 本机 MAC
# mac = "c4:b3:01:cf:fd:5b"

# 虚拟机 MAC
mac = "00:1c:42:79:4b:d3"

# 本机 IP
# ip = "10.60.201.177"

# 虚拟机 IP
ip = "10.211.55.250"

for _ in range(4):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=ip, hwsrc=mac), verbose=0, timeout=0.05)
from mysocket import MySocket

port = 6666

server = MySocket(ip)

server.bind(sport=port)
# 这个先暂时自己指定 IP，影响不大
server.bindIP(ip)

server.listen()
time.sleep(30)
# socket = server.accept()
# time.sleep(8)

# data = server.recv(50)
# print data
# print socket.recv_buffer
# socket.send("Server say : hi")
# server.close()
# print server.states
