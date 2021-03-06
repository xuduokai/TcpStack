# coding=utf-8
import random
import threading
import Queue

import time
from scapy.layers.inet import TCP, IP, Padding
from scapy.sendrecv import sniff, send


def get_payload(packet):
    while not isinstance(packet, TCP):
        packet = packet.payload
    return packet.payload


class MySocket:
    dst = ""
    src = "10.211.55.253"
    dport = ""
    sport = ""
    ip_header = ""
    con = threading.Condition()

    # 以完成三次握手的连接
    already = []
    # 待处理的连接
    wait = []

    isServer = False

    TCPT_2MSL = 0
    TCPT_KEEP = 1
    TCPT_RESENT = 2

    def __init__(self, src):
        self.src = src
        self.states = []
        self.state = ""
        self.state_change("CLOSED")
        self.recv_buffer = ""
        self.new_so = False

        # 目的：确认是不是给我的包，只给服务器用，后面确认是不是给自己的包，不是发生 rst 的后来再说吧

        self.open_sockets = {}
        self.seq = self._generate_seq()
        # ack是我们下一个想要接收的报文
        self.ack = 0

        # 设置定时器
        self.timer = [0, 0, 0, 0]
        self.time_state = [False, False, False, False]
        self.lock = threading.Lock()

        # 保存发过的包但是有大小限制，比如只有10个包，超过就把最早的移除
        self.send_buffer = Queue.Queue(10)
        self.expect_ack = -1

    def connect(self, dst, dport):
        # 1、建立连接
        self.state_change("SYN_SENT")
        self.dst = dst
        self.dport = dport
        # self.src = self.__get_loacl_ip()
        self.sport = self.__get_random_port()

        # self.open_sockets[dst, dport] = self
        # self.open_sockets[self.src, self.sport] = self

        self.ip_header = IP(dst=self.dst, src=self.src)
        # 开始三次握手，发送建立连接的请求
        self.send_default("S")
        self.start_timers(self.TCPT_KEEP, 75 * 1000)
        # 2、开始抓包
        self.start_daemon()

    # bind 说明是一个服务器 sockets
    def bind(self, sport):
        self.sport = sport

    def listen(self):
        # 开始抓包
        self.state_change("LISTEN")
        self.start_daemon()

    # 三次握手完成后
    def accept(self):
        if self.con.acquire():
            while True:
                if self.already:
                    del self.already[0]
                    return self.create_new_socket()
                else:
                    self.con.wait()

    def create_new_socket(self):
        s = MySocket(self.src)
        s.sport = self.sport
        s.dst = self.dst
        s.dport = self.dport
        s.state_change("ESTABLISHED")
        s.new_so = True
        self.open_sockets[s.dst, s.dport] = s
        self.reset_state()
        s.start_daemon(is_new_socket=True)
        return s

    def close(self):
        # self.dst = ""
        # self.dport = 0
        # 被动关闭
        if self.state == "CLOSE_WAIT":
            self.send_default("F")
            self.state_change("LAST_ACK")
        else:
            # 主动关闭
            self.state_change("FIN_WAIT_1")
            # self.seq += 1
            self.send_default("F")

    def send(self, data):
        # Bolok
        while self.state != "ESTABLISHED":
            time.sleep(0.001)
        # Do the actual send
        self.send_default(load=data, flags="P")

    def recv(self, size, timeout=None):
        start_time = time.time()
        # Block until the connection is closed
        while len(self.recv_buffer) < size:
            time.sleep(0.001)
            if self.state in ["CLOSED", "LAST-ACK"]:
                break
            if timeout < (time.time() - start_time):
                break
        recv = self.recv_buffer[:size]
        self.recv_buffer = self.recv_buffer[size:]
        return recv

    def __get_loacl_ip(self):
        return "10.211.55.253"

    def __get_random_port(self):
        return random.randint(12345, 50000)
        # return 12345

    def start_daemon(self, is_new_socket=False):

        if is_new_socket:
            t = threading.Thread(target=self.get_new_packet)
        else:
            t = threading.Thread(target=self.getPacket)

        t.daemon = True
        t.start()

        # 500毫秒定时器
        timer500 = threading.Thread(target=self.timer500_dispatch)
        timer500.daemon = True
        timer500.start()

        # 200毫秒定时器
        timer200 = threading.Thread(target=self.timer200_dispatch)
        timer200.daemon = True
        timer200.start()

    def timer500_dispatch(self):
        while True:
            if self.time_state[self.TCPT_2MSL]:
                # 2MSL
                self.lock.acquire()
                if self.timer[self.TCPT_2MSL] > 0:
                    self.timer[self.TCPT_2MSL] -= 500
                elif self.timer[self.TCPT_2MSL] <= 0:
                    self.state_change("CLOSE")
                    self.close_timers(self.TCPT_2MSL)
                self.lock.release()

            if self.time_state[self.TCPT_KEEP]:
                # SYN
                self.lock.acquire()
                if self.timer[self.TCPT_KEEP] > 0:

                    self.timer[self.TCPT_KEEP] -= 500
                elif self.timer[self.TCPT_KEEP] <= 0:
                    # 这里是真正做事的地方
                    self.tcp_drop()
                    self.state_change("CLOSE")
                    self.close_timers(self.TCPT_KEEP)
                self.lock.release()

            if self.time_state[self.TCPT_RESENT]:
                # SYN
                self.lock.acquire()
                if self.timer[self.TCPT_RESENT] > 0:
                    print self.timer[self.TCPT_RESENT]
                    self.timer[self.TCPT_RESENT] -= 500
                    print self.timer[self.TCPT_RESENT]
                elif self.timer[self.TCPT_RESENT] <= 0:
                    # 重发之前的包
                    packet = self.send_buffer.get()
                    self.send_packet(packet)

                    # 不释放会造成线程阻塞
                    self.lock.release()
                    print "resent"
                    self.start_resent(packet, self.expect_ack)
                    self.lock.acquire()
                self.lock.release()

            time.sleep(0.5)

    def timer200_dispatch(self):
        """只用于延迟 ack"""
        while True:
            time.sleep(0.2)

    def getPacket(self):
        # 抓包肯定只抓目的IP地址 是我们当前 sockets 的 ip
        # filter_rule = "tcp and ip dst %s and port %s" % (self.src, self.sport)
        # 先只过滤 ip

        filter_rule = "tcp and ip dst %s " % self.src
        sniff(filter=filter_rule, store=0, prn=self.dispatch)

    def get_new_packet(self):

        filter_rule = "tcp and ip src %s " % self.dst
        sniff(filter=filter_rule, store=0, prn=self.dispatch)

    def dispatch(self, packet):
        # 不是 TCP 的包
        if not isinstance(packet.payload.payload, TCP):
            return

        ip, port = packet.payload.dst, packet.dport

        # 不是发给我的包
        if ip != self.src and port != self.sport:
            print "..."
            return

        # 已经建立连接，服务器不处理
        # src, sport = packet.payload.src, packet.sport
        # if (src, sport) in self.open_sockets:
        #     return

        packet[TCP].show()

        # 如果是服务器：


        # if (ip, port) not in self.open_sockets:
        #     print "%s:%s" % (ip, port)
        #     # 这里的 src 和 sport 我没有按照他的写，后面再看看，暂时先不管
        #     if self.state != "LISTEN":
        #         reset = IP(src=self.src, dst=packet.payload.src) / TCP(seq=packet.ack, sport=self.sport,
        #                                                                dport=packet.sport,
        #                                                                flags="R")
        #         self.send_packet(reset)
        #         print "send R %s" % ip

        self.handle_packet(packet)

    def send_packet(self, packet, verbose=0):
        send(packet, verbose=verbose)

    # 依据 state 的不同，处理接收的 packet
    def handle_packet(self, packet):

        # 应该在这里确定 ack 的值，但我现在只是握手，所以先不管
        self.ack = max(self.ack, self.next_seq(packet))
        recv_flags = packet.sprintf("%TCP.flags%")

        if "P" in recv_flags:
            self.recv_buffer += packet.payload.load
            self.send_default("A")
        elif "R" in recv_flags:
            pass
        # self.close()
        elif "S" in recv_flags:
            if self.state == "LISTEN":
                self.state_change("SYN_RCVD")

                self.dst = packet.payload.src
                self.dport = packet.payload.sport
                self.ip_header = IP(dst=self.dst, src=self.src)

                self.send_default("SA")
            elif self.state == "SYN_SENT":
                self.state_change("ESTABLISHED")
                print "ESTABLISHED"
                self.seq += 1
                self.send_default("A")
                # 关闭 SYN 的定时器
                self.close_timers(self.TCPT_KEEP)

                # time.sleep(1)
                # self.send_default("P")
        # elif "FA" in recv_flags:
        #     self.send_default("A")
        #     self.state_change("CLOSE")
        elif "F" in recv_flags:
            print "recv F"
            if self.state == "FIN_WAIT_2":
                self.send_default("A")
                self.state_change("TIME_WAIT")
            elif self.state == "ESTABLISHED":
                self.state_change("CLOSE_WAIT")
                self.send_default("A")
            elif self.state == "FIN_WAIT_1":
                if "A" in recv_flags:
                    self.state_change("TIME_WAIT")
                    self.send_default("A")
                else:
                    # 同时关闭
                    self.state_change("CLOSING")
                    self.send_default("A")

        elif "A" in recv_flags:
            if packet.ack == self.expect_ack:
                self.close_resent()

            # 第三次握手
            if self.state == "SYN_RCVD":
                self.state_change("ESTABLISHED")
                self.seq += 1
                print "ESTABLISHED"
                # 唤醒 accept
                # 返回一个新的 socket
                if self.con.acquire():
                    self.already.append(1)
                    self.con.notify()
                    # 因为 notify 不会释放锁，所以需要手动释放
                    self.con.release()
            elif self.state == "FIN_WAIT_1":
                self.state_change("FIN_WAIT_2")
            elif self.state == "LAST_ACK":
                self.state_change("CLOSE")
            elif self.state == "CLOSING":
                self.state_change("TIME_WAIT")

    def reset_state(self):
        """这里我是用条件变量的方式去创建一个新的 socket，会不会有性能问题？
            以后看一下书上是怎么实现的
            """
        self.state_change("LISTEN")
        self.dst = ""
        self.dport = -1
        self.seq += 64000

    def send_default(self, flags, load=None):
        packet = TCP(sport=self.sport, dport=self.dport, flags=flags, seq=self.seq, ack=self.ack)

        full_packet = self.ip_header / packet

        if load:
            full_packet = full_packet / load
        self.send_packet(full_packet)

        # todo：现在是发了 seq 就增加，那么万一对面只收到一部分怎么办，应该是收到 ack 后把 seq 增加吧，后面再看
        if load is not None:
            self.seq += len(load)

        # 是 S、F、P
        if "A" not in flags:
            self.start_resent(full_packet, self.seq)

    @staticmethod
    def _generate_seq():
        # return random.randint(0, 100000)
        return 1

    @staticmethod
    def next_seq(packet):
        # really not right.
        tcp_flags = packet.sprintf("%TCP.flags%")
        if MySocket._has_load(packet):
            """
            问题：为什么是发过来的 seq 加而不是本地的 ack 加？
            答：因为有可能是乱序的，同时，我这里没加乱序处理，应该是：
            如果收到的包 seq 大于本地 ack，放在缓冲队列里，等待之前的包，同时做一些处理
            等于：执行我们现在的方法，self.seq + len(packet.load)，只不过 packet 变为 self
            小于：丢弃，重复的包
            """
            return packet.seq + len(packet.load)
        elif 'S' in tcp_flags or 'F' in tcp_flags:
            return packet.seq + 1
        else:
            return packet.seq

    @staticmethod
    def _has_load(packet):
        payload = get_payload(packet)
        if isinstance(payload, Padding):
            return False
        return bool(payload)

    def state_change(self, new):
        self.state = new
        self.states.append(new)
        if new == "TIME_WAIT":
            # 给定时器设置一个值
            self.start_timers(self.TCPT_2MSL, 2 * 1000)

    def bindIP(self, ip):
        self.src = ip

    def isServer(self, isServer):
        self.isServer = isServer

    def start_timers(self, state, times):
        """设置各种各样的定时器"""
        self.lock.acquire()
        self.timer[state] = times
        self.time_state[state] = True
        self.lock.release()

    def close_timers(self, state):
        self.timer[state] = 0
        self.time_state[state] = False

    def start_resent(self, packet, expect_ack):
        self.start_timers(self.TCPT_RESENT, 2 * 1000)
        self.send_buffer.put(packet)
        self.expect_ack = expect_ack

    def close_resent(self):
        self.close_timers(self.TCPT_RESENT)
        self.send_buffer.get()
        self.expect_ack = 0

    """
    通用函数
    """

    def tcp_drop(self):
        self.send_default("R")
