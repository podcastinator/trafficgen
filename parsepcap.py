#!/usr/bin/env python

from generator.gcm.gen import *
import sys
import scapy.all as scapy

if __name__ == '__main__':
    if len(sys.argv) < 2 :
        print("Usage: ./parsepcap.py <pcap>")
        exit(0)

    pcap = sys.argv[1]
    name = "out.pcap"
    enc_pkts = enc_packets(pcap)
    scapy.wrpcap(name, enc_pkts)
