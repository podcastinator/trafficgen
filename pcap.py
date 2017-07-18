#!/usr/bin/env python

from generator.gcm.aes_gcm import AES_GCM
from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes
from scapy.utils import PcapWriter as pcap
import sys
import scapy.all as scapy

def get_enc_payload(size, pkts):
    eth = scapy.Ether()
    ip = scapy.IP(src="1.2.3.4")
    tcp = scapy.TCP()
    hdr = str(eth/ip/tcp)

    key = 0xdeadbeefdeadbeefdeadbeefdeadbeef
    iv = 0xcafebabecafebabecafebabe

    pt = hdr + '\x65' * (size - len(hdr))
    aad = ''
    cipher = AES_GCM(key)
    ct, tag = cipher.encrypt(iv, pt, aad)

    payload = long_to_bytes(iv) + long_to_bytes(tag) + ct

    ip.src="10.0.0.1"
    return eth/ip/tcp/payload

def write(pkt, num, name):
    f = pcap(name, append = True)
    scapy.wrpcap(name, pkt*num)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: ./gen.py <size of plaintext> <num of packets>")
        exit(0)

    size = int(sys.argv[1])
    pkts = int(sys.argv[2])
    pkt = get_enc_payload(size, pkts)
    write(pkt, pkts, "traces/enc%db%d.pcap" % (size, pkts))
