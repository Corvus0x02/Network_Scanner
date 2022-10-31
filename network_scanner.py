#!/usr/bin/env python3
# Python3 script for scanning a provided network or target, returns IP and MAC address(es)
# Requires root/admin privileges on the device

#Imports
import scapy.all as scapy
import argparse

#Function to intake user provided arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="The target IP or IP Range")
    options = parser.parse_args()
    target = options.target
    return options

#Scan function
def scan(ip):
    #Create ARP packet
    arp_request = scapy.ARP(pdst=ip)
    #Create an Ethernet object and set the destination to all hosts on the local network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Combine the broadcast and ARP request packets
    arp_request_broadcast = broadcast/arp_request
    #Send packets with a custom Ether part. Returns two lists answered and unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

#Print the results
def print_result(results_list):
    print("IP\t\t\t","MAC")
    print("-------------------------------------------------")
    for client in results_list:
        print(client["ip"],"\t\t",client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
