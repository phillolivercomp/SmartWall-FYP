import socket, struct, os, array, Queue
from scapy.all import *
import time
import sqlite3 as sql
import os
import binascii

class LightIPSniff:
 
    def __init__(self, interface, actionIn, actionOut):
 
        self.interface = interface
        self.actionIn = actionIn
        self.actionOut = actionOut
 
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface, ETH_P_ALL))
 
    def __process_ipframe(self, pkt_type, ip_header, payload):
 
        # Extract the 20 bytes IP header, ignoring the IP options
 
        fields = struct.unpack("!BBHHHBBHII", ip_header)
 
        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]
 
        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]
 
        if pkt_type == socket.PACKET_OUTGOING:
            if self.actionOut is not None:
                self.actionOut(ip_src, ip_dst, ip_frame)
 
        else:
            if self.actionIn is not None:
                self.actionIn(ip_src, ip_dst, ip_frame)
 
    def recv(self):
        while True:
 
            pkt, sa_ll = self.ins.recvfrom(MTU)
 
            if type == socket.PACKET_OUTGOING and self.actionOut is None:
                continue
            elif self.actionOut is None:
                continue
 
            if len(pkt) <= 0:
                break
 
            eth_header = struct.unpack("!6s6sH", pkt[0:14])
 
            dummy_eth_protocol = socket.ntohs(eth_header[2])
 
            if eth_header[2] != 0x800 :
                continue
            ip_header = pkt[14:34]
            payload = pkt[14:]
 
            self.__process_ipframe(sa_ll[2], ip_header, payload)
 
#Example code to use IPSniff
def test_incoming_callback(src, dst, frame):
  #pass
    print("incoming - src=%s, dst=%s, frame len = %d"
        %(socket.inet_ntoa(src), socket.inet_ntoa(dst), len(frame)))
 
def test_outgoing_callback(src, dst, frame):
  #pass
    print("outgoing - src=%s, dst=%s, frame len = %d"
        %(socket.inet_ntoa(src), socket.inet_ntoa(dst), len(frame)))
 
ip_sniff = LightIPSniff('eth1', test_incoming_callback, test_outgoing_callback)
ip_sniff.recv()