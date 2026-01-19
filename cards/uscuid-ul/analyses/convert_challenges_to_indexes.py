#!/usr/bin/env python3

import sys
import json


# start point of index such that indexof(0x0001) = 500
x = 0x6015

i_fibonacci = [0] * (1 << 16)
s_fibonacci = [0] * (1 << 16)
x = 0x6015

for i in range(1, 1 << 16):
    i_fibonacci[x] = i
    s_fibonacci[i] = x
    x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
    x &= 0xffff


def nonce_distance_fibonacci(nt16from, nt16to):
    return (65535 + i_fibonacci[nt16to] - i_fibonacci[nt16from]) % 65535


def validate_nonce(nonce):
    a = (nonce_distance_fibonacci((nonce >> (0*16)) & 0xFFFF, (nonce >> (1*16)) & 0xFFFF) == 16)
    b = (nonce_distance_fibonacci((nonce >> (1*16)) & 0xFFFF, (nonce >> (2*16)) & 0xFFFF) == 16)
    c = (nonce_distance_fibonacci((nonce >> (2*16)) & 0xFFFF, (nonce >> (3*16)) & 0xFFFF) == 16)
    return a and b and c


def next_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 65535:
        index = 1
    else:
        index += 1
    return s_fibonacci[index]


def prev_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 1:
        index = 65535
    else:
        index -= 1
    return s_fibonacci[index]


def index_of_nonce(nonce):
    return i_fibonacci[nonce & 0xFFFF]


def get_index(challenge):
    return i_fibonacci[int(challenge[:4], 16)]


with open(sys.argv[1]) as f:
    collected_data = json.load(f)
    results = [get_index(x) for x in collected_data]
    with open('indexes_'+sys.argv[1], 'w') as f:
        json.dump(results, f)
