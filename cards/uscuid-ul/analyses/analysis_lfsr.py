#!/usr/bin/env -S uv run --with pycryptodome --script

try:
    from Crypto.Cipher import DES, DES3
except ModuleNotFoundError:
    print("MISSING: pip install pycryptodome")
    exit()

i_fibonacci = [0] * (1 << 16)
s_fibonacci = [0] * (1 << 16)
x = 0x6015
# x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
# x &= 0xffff

for i in range(1, 1 << 16):
    i_fibonacci[x] = i
    s_fibonacci[i] = x
    x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
    x &= 0xffff


def nonce_distance_fibonacci(nt16from, nt16to):
    return (65535 + i_fibonacci[nt16to] - i_fibonacci[nt16from]) % 65535


def validate_nonce(nonce):
    a = (nonce_distance_fibonacci((nonce >> (0*16)) & 0xFFFF, (nonce >> (1*16)) & 0xFFFF) == 16)
    b = (nonce_distance_fibonacci((nonce >> (1*16)) & 0xFFFF, (nonce >> (2*16)) & 0xFFFF) == 16)
    c = (nonce_distance_fibonacci((nonce >> (2*16)) & 0xFFFF, (nonce >> (3*16)) & 0xFFFF) == 16)
    return a and b and c


def validate_nonce2(nonce):
    x = (nonce >> (0*16)) & 0xFFFF
    for i in range(16):
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xffff
    if x != ((nonce >> (1*16)) & 0xFFFF):
        return False
    for i in range(16):
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xffff
    if x != ((nonce >> (2*16)) & 0xFFFF):
        return False
    for i in range(16):
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15
        x &= 0xffff
    if x != ((nonce >> (3*16)) & 0xFFFF):
        return False
    return True


def next_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 65535:
        index = 1
    else:
        index += 1
    return s_fibonacci[index]


def prev_fibonacci_state(nonce16):
    index = i_fibonacci[nonce16]
    if index == 1:
        index = 65535
    else:
        index -= 1
    return s_fibonacci[index]


def index_of_nonce(nonce):
    return i_fibonacci[nonce & 0xFFFF]


def decrypt_rndb(PICC_ekRndB, key="49454D4B41455242214E4143554F5946"):
    key = bytes.fromhex(key)
    zero_iv = b"\x00" * 8
    PICC_ekRndB = PICC_ekRndB.to_bytes(8, byteorder='big')
    if key[:8] == key[8:]:
        rndB = DES.new(key[:8], DES.MODE_CBC, iv=zero_iv).decrypt(PICC_ekRndB)
    else:
        rndB = DES3.new(key, DES3.MODE_CBC, iv=zero_iv).decrypt(PICC_ekRndB)
    return int.from_bytes(rndB, byteorder='big')


# nonce stream was constructed by considering nonces to be generated from MSWord to LSWord
# but actually this is the inverse. Nonce is generated from the LFSR from LSWord to MSWord
x = 0x6015
chal = ""
for i in range(36):
    chal += f"{x:04X}"
#    print(f"{x:04X}")
    for _ in range(16):
        x = prev_fibonacci_state(x)
print(chal)
print(chal == "6015248150013332727357C4DDED4D7504F0B8386D85966259EAE9E1BCBCFA9CA32A3B4BE05617EF53F20357A2BBFD86B2F3B4F721A732DD313C48680BAAA26FD235A3B2D8646DC2")

print(validate_nonce(0x6015248150013332))
print(validate_nonce2(0x6015248150013332))

print(index_of_nonce(0x6015))

# tests from 1A00+CRC, 1A00, 1A, post-auth 1A00+CRC, 1A00, 1A
print(validate_nonce(decrypt_rndb(0xB12DB22B6B6D2B22)))
print(validate_nonce(decrypt_rndb(0x1E153F7201BA75FD)))
print(validate_nonce(decrypt_rndb(0xBC868CBB8C337F5C)))
print(validate_nonce(decrypt_rndb(0x3780D68CD4E79D4D)))
print(validate_nonce(decrypt_rndb(0x244AB29D3700A26A)))
print(validate_nonce(decrypt_rndb(0x92D37042FE4A57A6)))
print(validate_nonce(decrypt_rndb(0x8755706D78EC1EC9)))

print(decrypt_rndb(0xB12DB22B6B6D2B22).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0x1E153F7201BA75FD).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0xBC868CBB8C337F5C).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0x3780D68CD4E79D4D).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0x244AB29D3700A26A).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0x92D37042FE4A57A6).to_bytes(8, byteorder='big').hex().upper())
print(decrypt_rndb(0x8755706D78EC1EC9).to_bytes(8, byteorder='big').hex().upper())
