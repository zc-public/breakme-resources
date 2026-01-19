#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import random
import pm3
from Crypto.Cipher import DES, DES3
from collections import Counter


def valid_lfsr_ulcg(nonce):
    x = (nonce >> (3*16)) & 0xFFFF
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    if (x != ((nonce >> (2*16)) & 0xFFFF)):
        return False
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    if (x != ((nonce >> (1*16)) & 0xFFFF)):
        return False
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    if (x != ((nonce >> (0*16)) & 0xFFFF)):
        return False
    return True


def generate_lfsr_ulcg(nonce16):
    x = nonce16
    nonce64 = x << (3*16)
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    nonce64 |= x << (2 * 16)
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    nonce64 |= x << (1 * 16)
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    nonce64 |= x
    return nonce64


def ulc_generate_auth_response(rndB, key, skip_rot=False, iv2=None):
    rndB_bytes = bytes.fromhex(rndB)
    key_bytes = bytes.fromhex(key)
    if iv2 is None:
        picc_ekRndB = encrypt_raw(rndB_bytes, key_bytes)
        iv2 = picc_ekRndB
    else:
        iv2 = bytes.fromhex(iv2)
    rndA = bytes.fromhex("A8AF3B256C75ED40")
    if skip_rot:
        rndB_prime = rndB_bytes
    else:
        rndB_prime = rndB_bytes[1:] + rndB_bytes[:1]
    rndA_rndB_prime = rndA + rndB_prime
    response = encrypt_raw(rndA_rndB_prime, key_bytes, iv_bytes=iv2)
    return response.hex().upper()


######################################################################################################
# Derived from https://github.com/Vipul97/des

BLOCK_SIZE = 64

KEY_PERMUTATION_TABLE = [
    56, 48, 40, 32, 24, 16, 8,
    0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26,
    18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
    6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3
]

COMPRESSION_PERMUTATION_TABLE = [
    13, 16, 10, 23, 0, 4,
    2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7,
    15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
]

S_BOX_TABLE = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

EXPANSION_PERMUTATION_TABLE = [
    31, 0, 1, 2, 3, 4,
    3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31, 0
]

P_BOX_TABLE = [
    15, 6, 19, 20, 28, 11, 27, 16,
    0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8,
    18, 12, 29, 5, 21, 10, 3, 24
]

INITIAL_PERMUTATION_TABLE = [
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
]

FINAL_PERMUTATION_TABLE = [
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
    32, 0, 40, 8, 48, 16, 56, 24
]


def hex_to_bin(hex_str):
    return f'{int(hex_str, 16):0{len(hex_str) * 4}b}'


def pad(bin_str):
    padding_length = (BLOCK_SIZE - len(bin_str) % BLOCK_SIZE) % BLOCK_SIZE
    return bin_str + '0' * padding_length


def split_block(block):
    mid = len(block) // 2
    return block[:mid], block[mid:]


def left_rotate(blocks, n_shifts):
    return [block[n_shifts:] + block[:n_shifts] for block in blocks]


def permute(block, table):
    return ''.join(block[i] for i in table)


def gen_subkeys(key):
    left_rotate_order = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    key_permutation = permute(key, KEY_PERMUTATION_TABLE)
    lk, rk = split_block(key_permutation)
    subkeys = []

    for n_shifts in left_rotate_order:
        lk, rk = left_rotate([lk, rk], n_shifts)
        compression_permutation = permute(lk + rk, COMPRESSION_PERMUTATION_TABLE)
        subkeys.append(compression_permutation)

    return subkeys


def xor(block_1, block_2):
    return f'{int(block_1, 2) ^ int(block_2, 2):0{len(block_1)}b}'


def s_box(block):
    output = ''
    for i in range(8):
        sub_str = block[i * 6:i * 6 + 6]
        row = int(sub_str[0] + sub_str[-1], 2)
        column = int(sub_str[1:5], 2)
        output += f'{S_BOX_TABLE[i][row][column]:04b}'
    return output


def round(input_block, subkey):
    l, r = split_block(input_block)
    expansion_permutation = permute(r, EXPANSION_PERMUTATION_TABLE)
    xor_with_subkey = xor(expansion_permutation, subkey)
    s_box_output = s_box(xor_with_subkey)
    p_box_output = permute(s_box_output, P_BOX_TABLE)
    xor_with_left = xor(p_box_output, l)
    output = r + xor_with_left
    return output


def des(input_block, subkeys, encrypt):
    initial_permutation = permute(input_block, INITIAL_PERMUTATION_TABLE)
    rounds = range(16) if encrypt else reversed(range(16))
    output = initial_permutation
    for i, j in enumerate(rounds, 1):
        output = round(output, subkeys[j])
    swap = output[BLOCK_SIZE // 2:] + output[:BLOCK_SIZE // 2]
    final_permutation = permute(swap, FINAL_PERMUTATION_TABLE)
    return final_permutation


def crypt_cbc(encrypt, key1_bits, key2_bits, in_bits, iv_bits):
    subkeys1 = gen_subkeys(key1_bits)
    subkeys2 = gen_subkeys(key2_bits)
    bin_out_str = ''
    last_block = iv_bits
    for i in range(0, len(in_bits), BLOCK_SIZE):
        block = in_bits[i:i + BLOCK_SIZE]
        if encrypt:
            block = xor(block, last_block)
        output = des(block, subkeys1, encrypt)
        output = des(output, subkeys2, not encrypt)
        output = des(output, subkeys1, encrypt)
        if encrypt:
            last_block = output
        else:
            output = xor(output, last_block)
            last_block = block
        bin_out_str += output
    return bin_out_str


def encrypt_raw(data_bytes, key_bytes, iv_bytes=b"\x00" * 8):
    key1_bits = hex_to_bin(key_bytes[:8].hex())
    key2_bits = hex_to_bin(key_bytes[8:].hex())
    in_bits = hex_to_bin(data_bytes.hex())
    iv_bits = hex_to_bin(iv_bytes.hex())
    out_bits = crypt_cbc(True, key1_bits, key2_bits, in_bits, iv_bits)
    out_bytes = bytes.fromhex(f'{int(out_bits, 2):0{len(out_bits) // 4}X}')
    return out_bytes


def decrypt_raw(data_bytes, key_bytes, iv_bytes=b"\x00" * 8):
    key1_bits = hex_to_bin(key_bytes[:8].hex())
    key2_bits = hex_to_bin(key_bytes[8:].hex())
    in_bits = hex_to_bin(data_bytes.hex())
    iv_bits = hex_to_bin(iv_bytes.hex())
    out_bits = crypt_cbc(False, key1_bits, key2_bits, in_bits, iv_bits)
    out_bytes = bytes.fromhex(f'{int(out_bits, 2):0{len(out_bits) // 4}X}')
    return out_bytes

######################################################################################################


def encrypt_crypto(data_bytes, key_bytes, iv_bytes=b"\x00" * 8):
    if key_bytes[:8] == key_bytes[8:]:
        cipher = DES.new(key_bytes[8:], DES.MODE_CBC, iv=iv_bytes)
    else:
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv_bytes)
    out_bytes = cipher.encrypt(data_bytes)
    return out_bytes


def decrypt_crypto(data_bytes, key_bytes, iv_bytes=b"\x00" * 8):
    if key_bytes[:8] == key_bytes[8:]:
        cipher = DES.new(key_bytes[8:], DES.MODE_CBC, iv=iv_bytes)
    else:
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=iv_bytes)
    out_bytes = cipher.decrypt(data_bytes)
    return out_bytes

######################################################################################################


p = pm3.pm3()
fdts = []
failed = 0
for i in range(1):
    for rndb in [None, "00"*8, "FF"*8]:
        for key in ["49454D4B41455242214E4143554F5946",
                    "00000000000000000000000000000000",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"]:
            for iv2 in [None, "00"*8, "FF"*8]:
                if rndb is None:
                    rndb = f"{generate_lfsr_ulcg(random.randint(1, 65535)):016X}"
                cmd = 'hf 14a raw -sc af'+ulc_generate_auth_response(rndB=rndb, key=key, iv2=iv2)
                assert len(cmd) == 49
                p.console(cmd, capture=False)
                p.console('trace list -t 14a --frame')
                step = 1
                fdt = None
                output = p.grabbed_output
                for line in output.split('\n'):
                    if "Rdr |AF" in line:
                        step = 3
                    if step == 3 and "Frame Delay Time" in line:
                        fdt = int(line[48:].rstrip())
                    if step == 3 and "Tag |00  " in line:
                        # Tag accepted our RndA|RndB'
                        print(line)
                if fdt is None:
                    failed += 1
                else:
                    fdts.append(fdt)
                    # remove last bit effect
                    if fdt > 1100:
                        fdt -= 64
                    if fdt > 2000:
                        print(i, cmd)
                        print(fdt, rndb)
                        print(output)
                if i % 1000 == 999:
                    print(i+1)

histogram = Counter(fdts)
for value, count in sorted(histogram.items()):
    print(f"FDT: {value:5}, Count: {count}")
print(f"Failed:        Count: {failed}")

# ULCG: trying immediately AF and trying to guess the initial state of the card without 1A00...
# The PICC runs an decipherment on the received token and thus gains RndA + RndB’.
# RndA + RndB’ = Dec(ERndARndB') with k=? and with IV=? (should be ErndB)
# => assume null round keys ??
#   - note: key=00* produces subkeys=0's; key=FF* produces subkeys=1's
# => assume IV=0 ??
# The PICC can now verify the sent RndB’ by comparing it with the RndB’ obtained by rotating the original RndB left by 8 bits internally.
# => assume stored rndB already rotated?

# 1A00 missing => what are internal states we're probably missing?
# - rndB or rotated rndB
# - IV=ErndB
# - key or subkeys

# Quick checks:
# rndB=00../FF.. + key=defined/00../FF.. + iv2=std/00../FF../ => failed

# Test1:
# - assume rndB is from LFSR16 AND key is the configured one
# => 200000 tests, never succeeded => wrong assumption

# Test2:
# - assume rndB is from LFSR16 but without rotation
# - assume default key

# TODO: 
# failed auth + select + AF
# success auth + AF
# and see how to adapt IV and rotated rndb
