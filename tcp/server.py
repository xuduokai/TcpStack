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
server.seq = 100
server.listen()
# 等待客户端发送的 S
# 等待客户端发送的 A
# 等待客户端发送的 P
# 等待客户端发送的 P

time.sleep(20)
# socket = server.accept()
# time.sleep(8)

data = server.recv(50)
print data
# print socket.recv_buffer
# 服务端发送 P
# server.send("a")
# server.send("b")
# server.send("c")
# server.send("d")
# server.send("e")

# 等待接收 A
# time.sleep(10)

# 等待接受客户端发送的 FIN
time.sleep(3)

server.close()

# 等待接受客户端发送对服务端 FIN 的 ACK
time.sleep(10)

print server.states
