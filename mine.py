#!/usr/bin/env python2

import hashlib

# block 125552
# values are in little endian format
block = {
    'v': '01000000',
    'prev': '81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000',
    'merkle': 'e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b',
    'time': 'c7f5d74d',
    'target': 'f2b9441a',
    'nonce': '42a14695'
}

header_hex = block['v'] + block['prev'] + block['merkle'] + block['time'] \
    + block['target'] + block['nonce']

# hex to bin
header_bin = header_hex.decode('hex')

# sha256(sha256(x))
hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()

# bin to hex
hash.encode('hex_codec')
# '1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000'

# little endian to big endian
print(hash[::-1].encode('hex_codec'))
# '00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d'
