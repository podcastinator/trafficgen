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
from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes

import sys
import scapy.all as scapy

def get_enc_payload(size):
    eth = scapy.Ether()
    ip = scapy.IP()
    tcp = scapy.TCP()
    hdr = str(eth/ip/tcp)

    key = 0xdeadbeefdeadbeefdeadbeefdeadbeef
    iv = 0xcafebabecafebabecafebabe

    pt = hdr + '\x65' * (size - len(hdr))
    aad = ''
    cipher = AES_GCM(key)
    ct, tag = cipher.encrypt(iv, pt, aad)

    payload = long_to_bytes(iv) + long_to_bytes(tag) + ct
    print(''.join(x.encode('hex') for x in payload))
    print(len(long_to_bytes(iv)), len(long_to_bytes(tag)), len(ct), len(payload))
    return payload


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ./gen.py <size of plaintext>")
        exit(0)

    get_enc_payload(int(sys.argv[1]))
