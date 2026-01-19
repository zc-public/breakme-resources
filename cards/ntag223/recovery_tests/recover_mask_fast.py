#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

"""Recover the mask used in NTAG 223."""

import sys
import argparse
import time
from itertools import combinations
import pm3
from suncmac import verify_suncmac, bruteforce_suncmac_low_hw

total_auth = 0


def console_debug(p, command, capture=True, debug=False):
    """Print debug messages to the console if debugging is enabled."""
    if debug:
        print(command)
        sys.stdout.flush()
    p.console(command, capture=capture)


def hamming_weight(n):
    """Compute the Hamming weight (number of set bits) of an integer."""
    return bin(n).count('1')


def hamming_distance(n, m):
    """Compute the Hamming distance between two integers."""
    return bin(n ^ m).count('1')


def construct_key(key_segment, segment):
    """Construct the full key from the segment and its value."""
    # FIXME: use real full key everywhere
    assert segment < 4
    if segment == 0:
        key = f'{key_segment:08x}000000000000000000000000'
    elif segment == 1:
        key = f'00000000{key_segment:08x}0000000000000000'
    elif segment == 2:
        key = f'0000000000000000{key_segment:08x}00000000'
    elif segment == 3:
        key = f'000000000000000000000000{key_segment:08x}'
    return key


def enumerate_words_with_k_bits_set(n_bits, max_bits_set, mask=0):
    """Generate all n-bit words with up to max_bits_set bits set, respecting a mask."""
    non_masked_positions = [pos for pos in range(n_bits) if not (mask & (1 << pos))]
    yield 0
    for k in range(1, max_bits_set + 1):
        # print(f"Enumerating words with {k} bits set: {len(list(combinations(non_masked_positions, k)))}")
        for bits in combinations(non_masked_positions, k):
            value = 0
            for pos in bits:
                value |= (1 << pos)
            yield value


def bruteforce_key(start_key, data, segment, bitflips=7):
    """Bruteforce the key by trying all combinations of bitflips up to max_bits_set."""
    # TODO: global total_auth
    full_start_key = construct_key(start_key, segment)
    return bruteforce_suncmac_low_hw(full_start_key, data, segment, bitflips=bitflips)


def insert_key(keys, newkey, initkey):
    """Insert a new key into the list of keys, ensuring no duplicates."""
    if newkey not in keys:
        keys.insert(0, newkey)
        keys.sort(key=lambda k: hamming_distance(k, initkey), reverse=True)
    bigflip = 0
    for key in keys:
        bigflip |= key ^ initkey
    bigkey = initkey ^ bigflip
    if bigkey not in keys:
        keys.insert(0, bigkey)
    return keys


def read_msg(p):
    """Read msg with SUNCMAC."""
    # TODO: SUNCMAC expected to be aligned at pages 0x11 to 0x14
    # hf 14a raw -kc a229983C083C
    # hf 14a raw -kc a22a80000000
    start_block, stop_block = 0x09, 0x14
    console_debug(p, f'hf 14a raw -sc 3a{start_block:02x}{stop_block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            return '0' + bytes.fromhex(''.join(parts[1].split('[')[0].strip().split())).decode()
    return None


def read_mac(p):
    """Read SUNCMAC."""
    # TODO: SUNCMAC expected to be aligned at pages 0x11 to 0x14
    # hf 14a raw -kc a229983C083C
    # hf 14a raw -kc a22a80000000
    start_block, stop_block = 0x11, 0x14
    console_debug(p, f'hf 14a raw -sc 3a{start_block:02x}{stop_block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            return bytes.fromhex(''.join(parts[1].split('[')[0].strip().split())).decode()
    return None


if __name__ == "__main__":
    p = pm3.pm3()
    parser = argparse.ArgumentParser(description="Recover the mask used in NTAG 223")
    parser.add_argument('--init', type=lambda x: int(x, 0), default=0x00000000, help='Initial key block value (hex)')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0x00000000, help='Final key block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) SUNCMAC_KEY:52-55')
    parser.add_argument('--tear1', type=int, default=280, help='First tearoff value (ms)')
    parser.add_argument('--tear2', type=int, default=245, help='Second tearoff value (ms)')
    parser.add_argument('--max_hd_diff', type=int, default=4, help='Maximum Hamming distance difference')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    init = args.init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    max_hd_diff = args.max_hd_diff
    debug = args.debug
    segment = 3 - ((block - 48) % 4)
    idx = (block - 48) // 4
    assert idx == 1
    initkey = int.from_bytes(init.to_bytes(4, 'big')[::-1], 'big')
    ntear2 = 0
    max_hd = 0
    keys = []
    start_time = time.time()

    # Erase the key
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    for i in range(48 + 4*idx, 52 + 4*idx):
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
    msg1 = read_msg(p)
    msg2 = read_msg(p)
    # Check no counter or TT is active
    assert msg1 == msg2
    mac = read_mac(p)
    assert msg1[-16:] == mac
    msg = msg1[:-16]
    assert verify_suncmac("00" * 16, msg + mac)

    while True:
        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)
        print(f"Testing with initial tearoff value: {tear1} ms")
        console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        key = initkey
        mac = read_mac(p)
        full_key = construct_key(key, segment)
        total_auth += 1
        if verify_suncmac(full_key, msg + mac):
            break
        tear1 -= 5
        # tear2 -= 5

    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    keys.insert(0, key)

    while True:
        print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
        print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        print(f"Max HD: {max(hamming_distance(k, initkey) for k in keys)}")
        sys.stdout.flush()
        nsame = 0
        while True:
            mac = read_mac(p)
            full_key = construct_key(key, segment)
            total_auth += 1
            if not verify_suncmac(full_key, msg + mac):
                break

            print(f"Testing with extra tearoff value: {tear2} ms")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
            ntear2 += 1
            nsame += 1
            if nsame >= 15:
                print(f"Stopping after {nsame} successful authentications with the same key.")
                print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
                print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms (last {nsame} tears just for confirmation)")
                print(f'Block {block:2} (0x{block:02x}) segment key mask probably found:'
                      f' {keys[0]:08X} '
                      f'(mask block value: {int.from_bytes(keys[0].to_bytes(4, 'big')[::-1], 'big'):08X})'
                      f' with HD={hamming_distance(keys[0], initkey):2d}')
                print(f"Total authentications: {total_auth}")
                current_time = time.time()
                elapsed_time = current_time - start_time
                minutes, seconds = divmod(elapsed_time, 60)
                print(f"Time spent since start: {int(minutes)} minutes {seconds:.2f} seconds")
                sys.stdout.flush()
                # Erase the key
                console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
                for i in range(48 + 4*idx, 52 + 4*idx):
                    console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
                exit(0)

        newkey = None
        mac = read_mac(p)
        for key in keys:
            if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                continue
            print(f"Trying known keys: {key:08X}")
            sys.stdout.flush()
            full_key = construct_key(key, segment)
            total_auth += 1
            if verify_suncmac(full_key, msg + mac):
                newkey = key
                break
        else:
            for key in keys:
                if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                    continue
                bitflips = 7
                print(f"Trying {bitflips} bitflips from key: {key:08X}")
                sys.stdout.flush()
                newkey = bruteforce_key(key, msg + mac, segment, bitflips=bitflips)
                if newkey is not None:
                    break
        assert newkey is not None
        print(f"Testing with extra tearoff value: {tear2} ms")
        sys.stdout.flush()
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        ntear2 += 1
        if newkey not in keys:
            keys = insert_key(keys, newkey, initkey=initkey)
            max_hd = max(hamming_distance(k, initkey) for k in keys)
            print(f"New key found: {newkey:08X} with HD={hamming_distance(newkey, initkey):02d}, "
                  f"max HD in keys: {max_hd:02d}")
            sys.stdout.flush()
        key = max(keys, key=lambda k: hamming_distance(k, initkey))
