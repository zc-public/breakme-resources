#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import pm3
import sys
from Crypto.Cipher import AES

CHECK_REPLY = False

zero_key = bytes.fromhex("00000000000000000000000000000000")
p = pm3.pm3()

# Wake up, time to give us some random numbers
p.console("hf 14a raw -skc 3000", capture=False)

for i in range(1000):
    p.console("hf 14a raw -ck 1A00")
    cmd_output = p.grabbed_output
    if cmd_output == "":
        sys.exit(1)
    output = cmd_output.splitlines()[0]
    PICC_ekRndB = bytes.fromhex((''.join(filter(str.isalnum, output)))[2:][:-4])
    # print("Encrypted")
    # print(PICC_ekRndB.hex().upper())

    # Decrypt PICC_ekRndB to get RndB
    # First encryption/decryption uses an all-zero IV
    zero_iv = b"\x00" * 16  # AES block size is 16 bytes

    # Create AES cipher in CBC mode
    cipher = AES.new(zero_key, AES.MODE_CBC, iv=zero_iv)

    # Decrypt the input
    rndB = cipher.decrypt(PICC_ekRndB)
    # print("Decrypted")
    print(rndB.hex().upper())
    rndB_prime = rndB[1:] + rndB[:1]
    # print("Rotated")
    # print(rndB_prime.hex().upper())
    # print("Encrypted")
    cipher = AES.new(zero_key, AES.MODE_CBC, iv=zero_iv)
    reply = cipher.encrypt(zero_key + rndB_prime)  # lol
    # print(reply.hex().upper())
    if CHECK_REPLY:
        p.console(f"hf 14a raw -ck AF{reply.hex().upper()}")
        cmd_output = p.grabbed_output
        if cmd_output == "":
            sys.exit(1)
        output = cmd_output.splitlines()[0]
        PICC_ekRndAp = bytes.fromhex((''.join(filter(str.isalnum, output)))[2:][:-4])
        # print(PICC_ekRndAp.hex().upper())
        # more lol
        assert PICC_ekRndAp == reply[:16]
    else:
        p.console(f"hf 14a raw -ck AF{reply.hex().upper()}", capture=False)
