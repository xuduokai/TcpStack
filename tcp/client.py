# coding=utf-8
# from logging_tcp_socket import LoggingTCPSocket
"""本代码运行在虚拟机上"""
import time
from mysocket import MySocket
from scapy.all import TCP, Ether, ARP
from scapy.sendrecv import sniff, srp

# 客户端 IP 地址
src = "10.211.55.253"

# 虚拟机 MAC
mac = "00:1c:42:79:4b:d3"

# 进行 apr 欺骗，将 mac 和 ip 通过广播的方式写人 ARP 路由表中
for _ in range(4):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=src, hwsrc=mac), verbose=0, timeout=0.05)

# 百度 IP
# ip = "202.108.22.5"

# 本机 IP
# ip = "10.60.201.177"

# 虚拟机 IP
ip = "10.211.55.250"

# http 端口
# port = 80

# 本机端口
port = 6666

client = MySocket(src=src)
client.connect(dst=ip, dport=port)

# 要暂停8秒，因为连接有点慢
time.sleep(8)
data = "client say : Hello"
# data = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip

# client.send(data)
# 看看能不能收到 ACK
# time.sleep(10)

# data = client.recv()
# print data
# time.sleep(10)

# client.close()
# time.sleep(10)
print client.states
