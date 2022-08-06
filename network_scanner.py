#!/usr/bin/env python3
import scapy.all as scapy

def scan(ip):
    #Create ARP packet
    arp_request = scapy.ARP(pdst=ip)
    #Create an Ethernet object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #Combine the broadcast and ARP request packets
    arp_request_broadcast = broadcast/arp_request
    #Send packets with a custom Ether part. Returns two lists answered and unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    #print(answered_list.summary())
    for element in answered_list:
        print(element)

scan("IP/Subnet")