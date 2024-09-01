import socket
import os
import struct
import threading
from ipaddress import ip_address, ip_network
import ctypes

#host to listen on
host = "192.168.1.217" #Example

#subnet to target
tgt_subnet = "192.168.0.0/24" #Example


tgt_message = "PYTHONRULES!" #Check message

def udp_sender(sub_net, msg):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in ip_network(sub_net).hosts():
        sender.sendto(msg.encode("utf-8"), (str(ip), 65212))

class IP(ctypes.Structure):
    _fields_= [
        ("ihl",          ctypes.c_ubyte, 4),
        ("version",      ctypes.c_ubyte, 4),
        ("tos",          ctypes.c_ubyte),
        ("len",          ctypes.c_ushort),
        ("id",           ctypes.c_ushort),
        ("offset",       ctypes.c_ushort),
        ("ttl",          ctypes.c_ubyte),
        ("protocol_num", ctypes.c_ubyte),
        ("sum",          ctypes.c_ushort),
        ("src",          ctypes.c_uint32),
        ("dst",          ctypes.c_uint32)
    ]
#IP Classes, internet research based xD
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer


        self.protocol_map = {1: "ICMP", 6: "TCP", 17:"UDP"} #mpa names

        
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst)) # ip

      
        try:
            self.protocol = self.protocol_map[self.protocol_num]   # protocl
        except IndexError:
            self.protocol = str(self.protocol_num)

class ICMP(ctypes.Structure): #icmp struct
    _fields_= [
        ("type",         ctypes.c_ubyte),
        ("code",         ctypes.c_ubyte),
        ("checksum",     ctypes.c_ushort),
        ("unused",       ctypes.c_ushort),
        ("next_hop_mtu", ctypes.c_ushort)
    ]

    def __new__(cls, socket_buffer):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.socket_buffer = socket_buffer


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP #win sock
else:
    socket_protocol = socket.IPPROTO_ICMP #unx sock
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind(("0.0.0.0", 6677)) # Example, could be ...(host, port)

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows we need to send IOCTL to send promiscuos mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# start sending packets
t = threading.Thread(target=udp_sender, args=(tgt_subnet, tgt_message))
t.start()

try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0] # single b

        ip_header = IP(raw_buffer[:20]) 

        print(f"Protocol: {ip_header.protocol}, {ip_header.src_address} -> {ip_header.dst_address}")

        if ip_header.protocol == "ICMP": # self expl, look for firt if icmmp
            offset = ip_header.ihl * 4 
            buf = raw_buffer[offset:offset + ctypes.sizeof(ICMP)]

            icmp_header = ICMP(buf)

            print(f"ICMP -> Type: {icmp_header.type}, {icmp_header.code}")


            if icmp_header.code == 3 and icmp_header.type == 3: # Check Code & Type 3 host ok no port

                if ip_address(ip_header.src_address) in ip_network(tgt_subnet):
                    if raw_buffer[len(raw_buffer)- len(tgt_message):] == tgt_message:
                        print(f"Host Up: {ip_header.src_address}")

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)