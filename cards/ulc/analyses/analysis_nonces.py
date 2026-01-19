#!/usr/bin/env python3

import sys
import json
import argparse

i_fibonacci = [0] * (1 << 16)
s_fibonacci = [0] * (1 << 16)


def initialize_fibonacci_mfc(start_x):
    global i_fibonacci, s_fibonacci
    x = start_x
    for i in range(1, 1 << 16):
        i_fibonacci[x] = i
        s_fibonacci[i] = x
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xffff


def initialize_fibonacci_ulcg(start_x):
    global i_fibonacci, s_fibonacci
    x = start_x
    x = (x << 15 | x >> 1) & 0xffff
    for i in range(0, 1 << 16):
        i_fibonacci[(x << 1 | x >> 15) & 0xffff] = i
        s_fibonacci[i] = (x << 1 | x >> 15) & 0xffff
        x = (x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15) & 0xffff


def nonce_distance_fibonacci(nt16from, nt16to):
    return (65535 + i_fibonacci[nt16to] - i_fibonacci[nt16from]) % 65535


def validate_nonce_mfc(nonce64):
    a = (nonce_distance_fibonacci((nonce64 >> (0*16)) & 0xFFFF, (nonce64 >> (1*16)) & 0xFFFF) == 16)
    b = (nonce_distance_fibonacci((nonce64 >> (1*16)) & 0xFFFF, (nonce64 >> (2*16)) & 0xFFFF) == 16)
    c = (nonce_distance_fibonacci((nonce64 >> (2*16)) & 0xFFFF, (nonce64 >> (3*16)) & 0xFFFF) == 16)
    return a and b and c


def validate_nonce_ulcg(nonce64):
    a = (nonce_distance_fibonacci((nonce64 >> (1*16)) & 0xFFFF, (nonce64 >> (0*16)) & 0xFFFF) == 1)
    b = (nonce_distance_fibonacci((nonce64 >> (2*16)) & 0xFFFF, (nonce64 >> (1*16)) & 0xFFFF) == 1)
    c = (nonce_distance_fibonacci((nonce64 >> (3*16)) & 0xFFFF, (nonce64 >> (2*16)) & 0xFFFF) == 1)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze nonces using Fibonacci LFSR.")
    parser.add_argument("-s", "--start_x", type=lambda x: int(x, 0), default=0x0001,
                        help="Starting value for the LFSR (default: 0x0001)")
    parser.add_argument("-j", "--json", required=True,
                        help="Input JSON file containing nonce data")
    parser.add_argument("--ulcg", action="store_true",
                        help="Use ULCG LFSR.")
    parser.add_argument("--mfc", action="store_true",
                        help="Use MFC LFSR.")
    parser.add_argument("--min-dups", type=int, default=0,
                        help="Minimum duplicates to consider (default: 0)")
    parser.add_argument("-b", "--bin", action="store_true",
                        help="Output nonces in binary format.")
    args = parser.parse_args()

    if args.ulcg == args.mfc:
        print("Error: You must specify either --ulcg or --mfc, but not both.")
        sys.exit(1)

    if args.ulcg:
        print("Using ULCG LFSR")
        initialize_fibonacci_ulcg(start_x=args.start_x)
        validate_nonce = validate_nonce_ulcg
    else:
        print("Using MFC LFSR")
        initialize_fibonacci_mfc(start_x=args.start_x)
        validate_nonce = validate_nonce_mfc

    with open(args.json, 'r') as file:
        data = json.load(file)

    data = data["challenges_0_sorted"]
    nonces = set(k for k, v in data.items() if v > args.min_dups)
    d = {}
    for nonce in nonces:
        if not validate_nonce(int(nonce, 16)):
            print(f"Invalid nonce detected: {nonce}")
            continue
        d[nonce] = get_index(nonce)
    sorted_nonces = sorted(d.items(), key=lambda item: item[1])
    for nonce, index in sorted_nonces:
        if args.bin:
            print(f"{int(nonce, 16):064b} {index}")
        else:
            print(f"Nonce: {nonce} Index: {index}")
