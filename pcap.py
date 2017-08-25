#!/usr/bin/env python

from generator.gcm.gen import get_tun_payload
import sys
import scapy.all as scapy


def write(pkt, num, name):
    scapy.wrpcap(name, pkt*num)


if __name__ == '__main__':
    if len(sys.argv) < 5 :
        print("Usage: ./gen.py <size of plaintext> <num of packets> <enc(1 or 0)> <lpriv(1 or 0)>")
        exit(0)

    size = int(sys.argv[1])
    pkts = int(sys.argv[2])
    encf = int(sys.argv[3])
    lprf = int(sys.argv[4])

    if encf == 1:
        enc = True
        name = "traces/enc%db%d.pcap" % (size, pkts)
    else:
        enc = False
        name = "traces/tun%db%d.pcap" % (size, pkts)
    lpriv = True if lprf == 1 else False

    eth = scapy.Ether()
    ip = scapy.IP(src="10.0.0.1")
    tcp = scapy.TCP()
    payload = get_tun_payload(size, enc, lpriv)
    pkt = eth/ip/tcp/payload
    write(pkt, pkts, name)
