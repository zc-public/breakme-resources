#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pycryptodome",
# ]
# ///

import sys
from Crypto.Cipher import DES3

def parse_bytes(name, hex_str, length=None):
    """
    Parses a hex string into bytes, optionally enforcing a fixed length.
    """
    data = bytes.fromhex(hex_str)
    if length is not None and len(data) != length:
        raise ValueError(f"{name} must be {length} bytes (got {len(data)}).")
    return data

def des_ede_cbc_decrypt(key, data, iv):
    """
    Decrypts data using the specified 16-byte 2-key 3DES key in CBC mode.
    """
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return cipher.decrypt(data)

def des_ede_cbc_encrypt(key, data, iv):
    """
    Encrypts data using the specified 16-byte 2-key 3DES key in CBC mode.
    """
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return cipher.encrypt(data)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} PICC_ekRndB_HEX")
        sys.exit(1)

    # Get PICC_ekRndB from command-line argument
    PICC_ekRndB_hex = sys.argv[1]
    PICC_ekRndB = parse_bytes("PICC_ekRndB", PICC_ekRndB_hex, 8)

    # Default key (big-endian) used by MIFARE Ultralight C
    # "49454D4B41455242214E4143554F5946" -> "IEMKAERB!NACUOYF" in ASCII
    keyBE_hex = "49454D4B41455242214E4143554F5946"
    #keyBE_hex = "FFFFFFFFFFFFFFFF214E4143FFFFFFFF"
    keyBE = parse_bytes("default_key", keyBE_hex, 16)

    # Decrypt PICC_ekRndB to get RndB
    # First encryption/decryption always uses an all-zero IV
    zero_iv = b"\x00" * 8
    rndB = des_ede_cbc_decrypt(keyBE, PICC_ekRndB, zero_iv)

    # From the numerical example, let's reuse the same RndA:
    # "A8AF3B256C75ED40"
    PCD_RndA = parse_bytes("PCD_RndA", "A8AF3B256C75ED40", 8)

    # Rotate RndB left by 1 byte to get RndB'
    rndB_prime = rndB[1:] + rndB[:1]

    # Concatenate RndA || RndB'
    pcd_rndA_rndB_prime = PCD_RndA + rndB_prime

    # Encrypt that concatenation using PICC_ekRndB as the IV:
    # The result is PCD_ekRndARndB2
    pcd_ekRndARndB2 = des_ede_cbc_encrypt(keyBE, pcd_rndA_rndB_prime, PICC_ekRndB)

    # Print the resulting ciphertext as uppercase hex, with the leading AF byte
    print("AF"+pcd_ekRndARndB2.hex().upper())

if __name__ == "__main__":
    main()
