#! /usr/bin/env python

import scapy.all as scap
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target e.g. 192.168.2.0/24 , use --help for more info.")
    return options

def scan(ip):
    arp_request = scap.ARP(pdst=ip)
    broadcast = scap.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scap.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def print_result(results_list):
    print("IP Address\t\tMAC Address\n----------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

args = get_arguments()
scan_result = scan(args.target)
print_result(scan_result)