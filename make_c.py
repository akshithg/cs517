#!/usr/bin/env python2

import hashlib
import json
import sys


def make_c_file(c_array, nonce_range):
    with open('mine_template.c') as template_file:
        with open('mine.c', 'w+') as c_file:
            template = template_file.read()
            template = template[: template.find('+++input')] + c_array + template[template.find('---input')+8 : ]
            template = template[: template.find('+++range')] + nonce_range + template[template.find('---range')+8 : ]
            c_file.write(template)


def main():
    if(len(sys.argv) < 4):
        print('Usage: {} <json block_file> <bool sat> <int nonce_range>'.format(sys.argv[0]))
        quit()

    sat = True if (sys.argv[2] == "true") else False
    n_range = int(sys.argv[3])
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
    c_array = "unsigned int input[20] = {\n"
    for i in xrange(0,len(header_hex),8):
        x = int(header_hex[i:i+8],16)
        c_array = c_array + str(x) + ",\n"
        print(x)
    c_array = c_array[:-2] + "};"

    if(sat):
        low = "nonce - " + str(n_range/2)
        high = "nonce + " + str(n_range/2)
    else:
        low = "nonce - " + str(n_range)
        high = "nonce - 1 "

    nonce_range =  "__CPROVER_assume(*u_nonce > " + low + " && *u_nonce < " + high + ");\n"

    print('\n--- nonce range ---')
    print('low: {}'.format(low))
    print('high: {}'.format(high))


    make_c_file(c_array, nonce_range)

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
