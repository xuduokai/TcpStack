#!/usr/local/bin/python
# coding=utf-8

from scapy.all import *

# VARIABLES
from scapy.layers.inet import IP, TCP, ARP, Ether
# from tcp import TCPSocket
# from tcp_listener import TCPListener

# sr1发送一个包并且收到相应的返回包
# a = sr1(IP(dst="202.108.22.5") / TCP(dport=80, flags="S"))
# send 发送一个包
ip = "23.83.232.198"
a = send(IP(dst="202.108.22.5",src="10.211.55.254") / TCP(dport=80, flags="S", seq=2, sport=23450))

# 与 Google 交互
# baidu_ip = "202.108.22.5"
# listener = TCPListener(baidu_ip)
#
# conn = TCPSocket(listener)
# conn.connect(baidu_ip, 80)
# time.sleep(2)
# conn.close()
# time.sleep(2)
# print conn.state
# assert conn.state == "CLOSED"
