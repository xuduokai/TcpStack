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
# 发送 S
client.connect(dst=ip, dport=port)

# 要暂停，接收 SA，然后发送 A，同时等待一段时间一遍 A 到达服务端，
# 然后才去发送 P，防止 P 比 A 先到达服务端。因为我们的代码目前还没有处理这样的情况
time.sleep(5)

data = "c"
# data = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip
client.send(data)
client.send(data)

# 等待接收 A
time.sleep(5)

# 等待接收服务器发来的 P
time.sleep(5)
data = client.recv(50)
print data

# 这里要暂停，为响应服务端发送的 P 而发送 ACK 挣取时间
time.sleep(10)

client.close()

# 等待接受服务端的 ACK 和 FIN
time.sleep(15)

print client.states
