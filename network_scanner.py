#!/usr/bin/env python3
import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)

scan("IP_or_IP_Range")