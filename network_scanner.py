#! /usr/bin/env python

import scapy.all as scap

def scan(ip):
    arp_request = scap.ARP(pdst=ip)
    broadcast = scap.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scap.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

scan("172.20.69.0/24")