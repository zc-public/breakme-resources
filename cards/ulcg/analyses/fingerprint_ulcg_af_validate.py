#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

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


key = "49454D4B41455242214E4143554F5946"

p = pm3.pm3()
fdts = []
failed = 0
for i in range(20):
    # We'll do a standard auth but pretend we don't known ErndB
    p.console('hf 14a raw -sck 1a00')
    Erndb = None
    for line in p.grabbed_output.split('\n'):
        if "AF" in line:
            Erndb = line[7:7+3*8].replace(' ', '')
    if Erndb is None:
        continue

    rndb = decrypt_raw(bytes.fromhex(Erndb), bytes.fromhex(key)).hex().upper()
    # instead of decrypting Erndb, let's pick a random rndb from the LFSR
    #rndb = f"{generate_lfsr_ulcg(random.randint(1, 65535)):016X}"
    cmd = 'hf 14a raw -c af'+ulc_generate_auth_response(rndb, key=key)
    assert len(cmd) == 48
    # Truncate command. ULCG accepts AF with only 15 data bytes
    #  => that works when the first byte CRC matches the missing byte
    # p.console(cmd[:-2], capture=False)
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
            print(fdt, rndb, Erndb, decrypt_raw(bytes.fromhex(Erndb), bytes.fromhex(key)).hex().upper())
            print(output)
    if i % 1000 == 999:
        print(i+1)

histogram = Counter(fdts)
for value, count in sorted(histogram.items()):
    print(f"FDT: {value:5}, Count: {count}")
print(f"Failed:        Count: {failed}")

# Validating that under normal circumstances, we can
# - assume rndB is from LFSR16
# - assume default key
# => successful auth with probability 1/65534 ? here more like 2.5/65534...

# print(i, cmd)
# print(fdt, rndb, Erndb, decrypt(Erndb))

# 21489 hf 14a raw -c afA56850CF21AF30FD51AB3E542C3EEEAD
# 11412 d105e8827441ba21 9AA8D6919018965E D105E8827441BA21

# 69130 hf 14a raw -c af1ED0C574F18C70605B1BF94C89322EF5
# 11348 1edd8f6fc7b7e3da A42931DA78E0B2B6 1EDD8F6FC7B7E3DA

# 69317 hf 14a raw -c afA986C8DAEB60289062502322DC7900FE
# 11412 22b6115a08ac0457 8A6813CF0C00E5B3 22B6115A08AC0457

# 105010 hf 14a raw -c af9A7FF97543EFD06F598FEC888DC4FDC7
# 11412 2ca39651cb286595 8F3893A51D5B01F8 2CA39651CB286595

# 127042 hf 14a raw -c af6A235CC789D9C536B67503D08BE08E1A
# 11412 b0445823ac11d609 C0A66202B629C8C2 B0445823AC11D609


# funny bug in ULCG :
# from last 2 lines of the ULCG fingerprinting table, you can see it replies NAK to AF+16 bytes OR AF+15 bytes...
# So I wanted to see if we could have a successful auth with a truncated AF and... yes you can.

# 2 examples:
# ```
#      432436 |     445236 | Tag |00  0F  16  78  59  51  EE  A2  48  71  80                               |  ok | 
# 155 hf 14a raw -c af0EA2BC066148DD4340B8AD5032D1CE DF
# 12564 2C7F963E4B1FA58F A54CD63E65667B50 2C7F963E4B1FA58F
# [+] Recorded activity ( 217 bytes )
# [=] start = start of start frame. end = end of frame. src = source of transfer.
# [=] ISO14443A - all times are in carrier periods (1/13.56MHz)

#       Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation
# ------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------
#           0 |        992 | Rdr |52(7)                                                                    |     | WUPA
#         992 |       2100 |     |Frame Delay Time 1108
#        2100 |       4468 | Tag |44  00                                                                   |     | 
#        7040 |       9504 | Rdr |93  20                                                                   |     | ANTICOLL
#        9504 |      10548 |     |Frame Delay Time 1044
#       10548 |      16436 | Tag |88  04  B6  C1  FB                                                       |     | 
#       19456 |      29920 | Rdr |93  70  88  04  B6  C1  FB  B0  BD                                       |  ok | SELECT_UID
#       29920 |      31028 |     |Frame Delay Time 1108
#       31028 |      34548 | Tag |04  DA  17                                                               |  ok | 
#       35840 |      38304 | Rdr |95  20                                                                   |     | ANTICOLL-2
#       38304 |      39348 |     |Frame Delay Time 1044
#       39348 |      45236 | Tag |11  01  15  89  8C                                                       |     | 
#       48384 |      58848 | Rdr |95  70  11  01  15  89  8C  76  8B                                       |  ok | SELECT_UID-2
#       58848 |      59956 |     |Frame Delay Time 1108
#       59956 |      63540 | Tag |00  FE  51                                                               |  ok | 
#       72064 |      76832 | Rdr |1A  00  41  76                                                           |  ok | AUTH-1 
#       76832 |      88244 |     |Frame Delay Time 11412
#       88244 |     100980 | Tag |AF  A5  4C  D6  3E  65  66  7B  50  3B  2D                               |  ok | 
#      398976 |     419808 | Rdr |AF  0E  A2  BC  06  61  48  DD  43  40  B8  AD  50  32  D1  CE  DF  A6   |  ok | 
#      419808 |     432436 |     |Frame Delay Time 12628
#      432436 |     445236 | Tag |00  0F  16  78  59  51  EE  A2  48  71  80                               |  ok | 

#      432180 |     444916 | Tag |00  D9  DE  79  86  92  C5  7C  66  62  5F                               |  ok | 
# 234 hf 14a raw -c af342C9DD6F7D89D09E2A844B4C7CD11 1E
# 12500 C9A264D1B2685934 D2CD9C278236AE7A C9A264D1B2685934
# [+] Recorded activity ( 217 bytes )
# [=] start = start of start frame. end = end of frame. src = source of transfer.
# [=] ISO14443A - all times are in carrier periods (1/13.56MHz)

#       Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation
# ------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------
#           0 |        992 | Rdr |52(7)                                                                    |     | WUPA
#         992 |       2100 |     |Frame Delay Time 1108
#        2100 |       4468 | Tag |44  00                                                                   |     | 
#        7040 |       9504 | Rdr |93  20                                                                   |     | ANTICOLL
#        9504 |      10548 |     |Frame Delay Time 1044
#       10548 |      16436 | Tag |88  04  B6  C1  FB                                                       |     | 
#       19456 |      29920 | Rdr |93  70  88  04  B6  C1  FB  B0  BD                                       |  ok | SELECT_UID
#       29920 |      31028 |     |Frame Delay Time 1108
#       31028 |      34548 | Tag |04  DA  17                                                               |  ok | 
#       35840 |      38304 | Rdr |95  20                                                                   |     | ANTICOLL-2
#       38304 |      39348 |     |Frame Delay Time 1044
#       39348 |      45236 | Tag |11  01  15  89  8C                                                       |     | 
#       48384 |      58848 | Rdr |95  70  11  01  15  89  8C  76  8B                                       |  ok | SELECT_UID-2
#       58848 |      59956 |     |Frame Delay Time 1108
#       59956 |      63540 | Tag |00  FE  51                                                               |  ok | 
#       73472 |      78240 | Rdr |1A  00  41  76                                                           |  ok | AUTH-1 
#       78240 |      89652 |     |Frame Delay Time 11412
#       89652 |     102388 | Tag |AF  D2  CD  9C  27  82  36  AE  7A  EC  21                               |  ok | 
#      398720 |     419616 | Rdr |AF  34  2C  9D  D6  F7  D8  9D  09  E2  A8  44  B4  C7  CD  11  1E  FB   |  ok | 
#      419616 |     432180 |     |Frame Delay Time 12564
#      432180 |     444916 | Tag |00  D9  DE  79  86  92  C5  7C  66  62  5F                               |  ok | 
# ```
# So e.g. the first command, instead of `hf 14a raw -c af0EA2BC066148DD4340B8AD5032D1CEDF` I'm sending `hf 14a raw -c af0EA2BC066148DD4340B8AD5032D1CE` and it works.. because the CRC starts with `DF` identical to the missing byte :)
