#!/usr/bin/env python2

import hashlib
import json
import sys


def main():
    if(len(sys.argv) < 2):
        print('Usage: {} block.json'.format(sys.argv[0]))
        quit()

    with open(sys.argv[1]) as json_file:
        block = json.load(json_file)

    print('\n-- header data --')
    for k in block.keys():
        print('{} : {}'.format(k, block[k]))

    print('\n-- header (little endian) --')
    print('version + prev + merkle + time + target + nonce')
    header_hex = block['version'] + block['prev'] + block['merkle'] + block['time'] \
    + block['target'] + block['nonce']
    print(header_hex)

    print('\n-- header to int array --')
    for i in xrange(0,len(header_hex),8):
        print(int(header_hex[i:i+8],16))

    # hex to bin
    header_bin = header_hex.decode('hex')
    # sha256(sha256(x))
    hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
    # bin to hex
    hash.encode('hex_codec')

    print('\n-- hash little endian --')
    print(hash[:].encode('hex_codec'))

    # little endian to big endian
    print('\n-- hash big endian --')
    print(hash[::-1].encode('hex_codec'))

if __name__== "__main__":
  main()
