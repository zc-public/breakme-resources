#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pycryptodome",
# ]
# ///

import sys
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

if len(sys.argv) != 4:
    print("python3 valid_key_check.py <auth1 response> <auth2 response> <key>")
    print("python3 valid_key_check.py D5F0DBE7B58CC4D2 8EAB9317B33A3004402CB2BFEBCB0E28 C83AB68E68F8C48CFE1052E8782416B6")
    sys.exit(1)

"""
encoder:
   15585532 |   15590300 | Rdr |1A  00  41  76                                                           |  ok | AUTH-1
   15601856 |   15614656 | Tag |AF  D5  F0  DB  E7  B5  8C  C4  D2  1C  43                               |  ok |
   15883724 |   15905708 | Rdr |AF  8E  AB  93  17  B3  3A  30  04  40  2C  B2  BF  EB  CB  0E  28  22   |     |
            |            |     |3A                                                                       |  ok | AUTH-2
   15917328 |   15930064 | Tag |00  7F  57  91  E8  6D  FD  7F  65  E8  06                               |  ok | 
"""
"""
output:
53F3A9F9D4FDEA7F -> F3A9F9D4FDEA7F53 (correct, expected)

"""

# Given parameters
ciphertext = bytes.fromhex(sys.argv[1])
iv = bytes(8)  # IV of 0 (8 bytes of zero)
key = bytes.fromhex(sys.argv[3])

# Create the 3DES cipher in CBC mode
cipher = DES3.new(key, DES3.MODE_CBC, iv)

# Decrypt and remove padding
decrypted_data = cipher.decrypt(ciphertext)

# --

# Given parameters for the second decryption
ciphertext_2 = bytes.fromhex(sys.argv[2])
iv_2 = bytes.fromhex(sys.argv[1])  # New IV from previous ciphertext

# Create the 3DES cipher in CBC mode with the new IV
cipher_2 = DES3.new(key, DES3.MODE_CBC, iv_2)

# Decrypt and remove padding
decrypted_data_2 = cipher_2.decrypt(ciphertext_2)

# Un-rotate
decrypted_hex_2 = decrypted_data_2[8:]
rot_decrypted_hex_2 = decrypted_hex_2[-1:] + decrypted_hex_2[:-1]

# Print result
print(decrypted_data == rot_decrypted_hex_2)
