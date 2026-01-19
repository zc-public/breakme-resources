#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pycryptodome",
# ]
# ///

import sys
from Crypto.Cipher import AES

if len(sys.argv) != 4:
    print("python3 valid_key_check_aes.py <auth1 response> <auth2 response> <key>")
    print("python3 valid_key_check_aes.py C910D1EADCB1A0A087E82C85710E1A63 E14D5D0EE27715DF08B4152BA23DA8E0225DD5BA7D26B14E0942495655BEC6CC 00000000000000000000000000000000")
    sys.exit(1)

auth1_resp = bytes.fromhex(sys.argv[1])
auth2_resp = bytes.fromhex(sys.argv[2])
key = bytes.fromhex(sys.argv[3])

if len(key) != 16:
    print("Key must be 16 bytes (32 hex characters) for AES-128")
    sys.exit(1)

zero_iv = bytes(16)

# Decrypt auth1 response
cipher1 = AES.new(key, AES.MODE_CBC, zero_iv)
decrypted1 = cipher1.decrypt(auth1_resp)

# Decrypt auth2 response
cipher2 = AES.new(key, AES.MODE_CBC, zero_iv)
decrypted2 = cipher2.decrypt(auth2_resp)

# Grab second 16-byte block from auth2
second_block = decrypted2[16:32]

# Rotate second block right by 1 byte
rotated_block = second_block[-1:] + second_block[:-1]

# Compare with decrypted auth1
if decrypted1 == rotated_block:
    print("True")
else:
    print("False")
