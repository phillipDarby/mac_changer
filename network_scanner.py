#! /usr/bin/env python

import scapy.all as scap

def scan(ip):
    scap.arping(ip)

scan("172.20.69.50")