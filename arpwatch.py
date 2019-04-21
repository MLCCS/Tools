# -*- coding:utf-8 -*-
from scapy.all import sniff,ARP
from signal import signal,SIGINT
import sys
import argparse


ip_mac = {}
def watch_arp(pkt):
	#	print(pkt)
	# 如果是ARP响应包，打印
	if pkt[ARP].op == 2:
		print(pkt[ARP].hwsrc + "\t" + pkt[ARP].psrc)
	# 如果是新设备，则加入字典
	if ip_mac.get(pkt[ARP].psrc) == None:
		print("Found new device:%s\t%s" %(pkt[ARP].hwsrc,
			pkt[ARP].psrc))
		ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
	# 某ip对应的MAC地址更换了，有点不正常，提示一下
	elif ip_mac.get(pkt[ARP].psrc) and ip_mac[pkt[ARP].psrc] != pkt[ARP].hwsrc:
		print("[x] %s has got a new MAC:%s,it's old MAC is:%s" %(pkt[ARP].psrc,
			pkt[ARP].hwsrc,ip_mac.get(pkt[ARP].psrc)))
		ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc

if __name__ == '__main__':
	parser = argparse.ArgumentParser('MAC_Flood')
	parser.add_argument(dest='interface',metavar='interface')
	args = parser.parse_args()
	iface = args.interface
	sniff(prn=watch_arp,filter="arp",iface=iface,store=0)
