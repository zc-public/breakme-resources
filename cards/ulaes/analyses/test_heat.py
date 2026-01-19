#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import sys
import argparse
import time
import pm3


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


if __name__ == "__main__":
    p = pm3.pm3()

    parser = argparse.ArgumentParser(description="Recover the mask used in Ultralight AES authentication")
    parser.add_argument('--init', type=lambda x: int(x, 0), default=0xffffffff, help='Initial block value (hex)')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0xa5a5a5a5, help='Final block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), default=0x10,
                        help='Block number (hex or int), between 4 and 39 inclusive')
    parser.add_argument('--tear1', type=int, default=462, help='First tearoff value (ms)')
    parser.add_argument('--tear2', type=int, default=430, help='Second tearoff value (ms)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--dry', action='store_true', help='Don\'t write')
    args = parser.parse_args()

    init = args.init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    dry = args.dry
    debug = args.debug

    initkey = int.from_bytes(init.to_bytes(4, 'big')[::-1], 'big')
    ntear2 = 0
    max_hd = 0
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    if not dry:
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)
        print(f"Testing with initial tearoff value: {tear1} ms")
        console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
    while True:
        b = read_block(p, block)
        if b is not None:
            print(f"Block {block}: {b:08x} HW: {hamming_weight(b)}")
        else:
            print(f"Block {block}: read error")
        time.sleep(0.2)


# cold does not affect read value, only heat
