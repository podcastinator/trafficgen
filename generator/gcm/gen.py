#!/usr/bin/env python

"""
    Copyright (C) 2013 Bo Zhu http://about.bozhu.me

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""

from aes_gcm import AES_GCM
from Crypto.Util.number import long_to_bytes

import sys
import scapy.all as scapy


def get_tun_payload(size, enc=True, lpriv=False):
    eth = scapy.Ether()
    ip = scapy.IP(src="1.2.3.4")
    tcp = scapy.TCP()
    hdr = str(eth/ip/tcp)

    pt = hdr + '\x65' * (size - len(hdr))

    if enc:
        key = 0xdeadbeefdeadbeefdeadbeefdeadbeef
        iv = 0xcafebabecafebabecafebabe
        aad = ''
        cipher = AES_GCM(key)
        if not lpriv:
            ct, tag = cipher.encrypt(iv, pt, aad)
            payload = long_to_bytes(iv) + long_to_bytes(tag) + ct
        else:
            ct1, tag1 = cipher.encrypt(iv, hdr, aad)
            cipher = AES_GCM(key)
            ct2, tag2 = cipher.encrypt(iv, '\x65' * (size - len(hdr)), aad)
            payload = long_to_bytes(iv) + long_to_bytes(tag1) + ct1 + long_to_bytes(iv) + long_to_bytes(tag2) + ct2
    else:
        payload = pt
    print(''.join(x.encode('hex') for x in payload))
    return payload


def enc_packets(pcap):
    key = 0xdeadbeefdeadbeefdeadbeefdeadbeef
    iv = 0xcafebabecafebabecafebabe
    eth = scapy.Ether()
    ip = scapy.IP(src="10.0.0.1")
    udp = scapy.UDP()
    pkts = scapy.rdpcap(pcap)
    new_pkts = []
    for pkt in pkts:
        pt = str(pkt)
        aad = ''
        cipher = AES_GCM(key)
        ct, tag = cipher.encrypt(iv, pt, aad)
        payload = long_to_bytes(iv) + long_to_bytes(tag) + ct
        new_pkt = (eth/ip/udp/scapy.Packet(payload))
        new_pkts.append(new_pkt)
    return new_pkts


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ./gen.py <size of plaintext>")
        exit(0)

    get_tun_payload(int(sys.argv[1]))
