#!/usr/bin/env python3

def crc16_a(buf, init_crc=0x6363):
    binbuf = bytes.fromhex(buf)
    crc = init_crc

    for i in range(len(binbuf)):
        crc ^= binbuf[i]

        for j in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return f"{crc & 0xFF:02X}{(crc >> 8) & 0xFF:02X}"


def append_crc16_a(buf):
    crc = crc16_a(buf)
    return (buf+crc).upper()


def brute_force_crc(chal):
    for i1 in range(256):
        for i2 in range(256):
            c = chal[:-4][4:] + f"{i1:02X}{i2:02X}"
            calculated_crc = append_crc16_a(c)[-4:]
            if calculated_crc == chal[-4:]:
                print(f"Reply: {chal}, Compute over {c[:-4]}-{c[-4:]} "
                      f"CRC Match: {calculated_crc == chal[-4:]}, Calculated CRC: {calculated_crc}")


def brute_force_crc2(chal):
    for i1 in range(256):
        for i2 in range(256):
            c = f"{i1:02X}{i2:02X}" + chal[:-4][:-4]
            calculated_crc = append_crc16_a(c)[-4:]
            if calculated_crc == chal[-4:]:
                print(f"Reply: {chal}, Compute over {c[:4]}-{c[4:]} "
                      f"CRC Match: {calculated_crc == chal[-4:]}, Calculated CRC: {calculated_crc}")


def brute_force_crc3(chal):
    for i1 in range(256):
        for i2 in range(256):
            c = f"{i1:02X}{i2:02X}" + chal[:-4]
            calculated_crc = append_crc16_a(c)[-4:]
            if calculated_crc == chal[-4:]:
                print(f"Reply: {chal}, Compute over {c[:4]}-{c[4:]} "
                      f"CRC Match: {calculated_crc == chal[-4:]}, Calculated CRC: {calculated_crc}")


def brute_force_crc4(chal):
    for i1 in range(256):
        c = f"{i1:02X}" + chal[:-4]
        calculated_crc = append_crc16_a(c)[-4:]
        if calculated_crc == chal[-4:]:
            print(f"Reply: {chal}, Compute over {c[:4]}-{c[4:]} "
                  f"CRC Match: {calculated_crc == chal[-4:]}, Calculated CRC: {calculated_crc}")


print("Phil card")
# Proper commands, correct CRC
# Cmd 1a00+CRC: AFB12DB22B6B6D2B22[425A] clear: 9A454B8AFCC53DEC
c1 = "AFB12DB22B6B6D2B22425A"
# Cmd 1a00+CRC: AF3780D68CD4E79D4D[7953] clear: 5A0F02F99BBCD3B8
c2 = "AF3780D68CD4E79D4D7953"
# Checking Commands NOCRC
# Cmd 1a00:     AF1E153F7201BA75FD[8E58] clear: E1976C607F8E5382
c3 = "AF1E153F7201BA75FD8E58"
# Cmd 1a  :     AFBC868CBB8C337F5C[B51E] clear: 1A16C5F80442F19B
c4 = "AFBC868CBB8C337F5CB51E"
# Checking Commands Post-Auth NOCRC
# Cmd 1a00:     AF244AB29D3700A26A[DC85] clear: AFCB4FA97739F9AB
c5 = "AF244AB29D3700A26ADC85"
# Cmd 1a  :     AF92D37042FE4A57A6[62EF] clear: A15CE2B3FD8D6246
c6 = "AF92D37042FE4A57A662EF"

# hf 14a raw -s 1a
c7 = "AFE0FB3B14D4B0B023926B"

# hf 14a raw -skc 3000;hf 14a raw 1a
c8 = "AF803BCE02080A19445E5B"


# [=]   0/0x00 | 04 26 D6 7C |   | .&.|
# [=]   1/0x01 | F5 2A 71 80 |   | .*q.
# [=]   2/0x02 | 2E 48 00 00 |   | .H..
# [=]   3/0x03 | 00 00 00 00 | 0 | ....
# [=]   4/0x04 | 02 00 00 10 | 0 | ....
# [=]   5/0x05 | 00 06 01 10 | 0 | ....
# [=]   6/0x06 | 11 FF 00 00 | 0 | ....
for c in [c1, c2, c3, c4, c5, c6, c7, c8]:
    calculated_crc = append_crc16_a(c[:-4])
    diff = f"{int(calculated_crc[-4:], 16) ^ int(c[-4:], 16):04X}"
    print(f"Reply: {c}, CRC Match: {calculated_crc == c}, Calculated CRC: {calculated_crc}, Diff: {diff}")
    if diff != "0000":
        for init_crc in range(1 << 16):
            if crc16_a(c[:-4], init_crc) == c[-4:]:
                init_crc_hex = f"{init_crc & 0xFF:02X}{(init_crc >> 8) & 0xFF:02X}"
                diff = init_crc ^ 0x6363
                diff_hex = f"{diff & 0xFF:02X}{(diff >> 8) & 0xFF:02X}"
                print(f"Reply: {c}, Init CRC: {init_crc_hex} Init CRC diff: {diff_hex}")
                break

# Reply: AFB12DB22B6B6D2B22425A, CRC Match: True,  Calculated CRC: AFB12DB22B6B6D2B22425A, Diff: 0000
# Reply: AF3780D68CD4E79D4D7953, CRC Match: True,  Calculated CRC: AF3780D68CD4E79D4D7953, Diff: 0000
# Reply: AF1E153F7201BA75FD8E58, CRC Match: False, Calculated CRC: AF1E153F7201BA75FDE2AB, Diff: 6CF3
# Reply: AF1E153F7201BA75FD8E58, Init CRC: C173 Init CRC diff: A210
# Reply: AFBC868CBB8C337F5CB51E, CRC Match: False, Calculated CRC: AFBC868CBB8C337F5CD9ED, Diff: 6CF3
# Reply: AFBC868CBB8C337F5CB51E, Init CRC: C173 Init CRC diff: A210
# Reply: AF244AB29D3700A26ADC85, CRC Match: False, Calculated CRC: AF244AB29D3700A26AB076, Diff: 6CF3
# Reply: AF244AB29D3700A26ADC85, Init CRC: C173 Init CRC diff: A210
# Reply: AF92D37042FE4A57A662EF, CRC Match: False, Calculated CRC: AF92D37042FE4A57A60E1C, Diff: 6CF3
# Reply: AF92D37042FE4A57A662EF, Init CRC: C173 Init CRC diff: A210

# these bruteforce can't work as the diff is independent of the nonce,
# so full nonce has to be covered in crc computation
# brute_force_crc(c3)
# brute_force_crc(c4)
# brute_force_crc(c5)
# brute_force_crc(c6)
# Reply: AF1E153F7201BA75FD8E58, Compute over 153F7201BA75FD-334B CRC Match: True, Calculated CRC: 8E58
# Reply: AFBC868CBB8C337F5CB51E, Compute over 868CBB8C337F5C-9A86 CRC Match: True, Calculated CRC: B51E
# Reply: AF244AB29D3700A26ADC85, Compute over 4AB29D3700A26A-8926 CRC Match: True, Calculated CRC: DC85
# Reply: AF92D37042FE4A57A662EF, Compute over D37042FE4A57A6-6B39 CRC Match: True, Calculated CRC: 62EF

# brute_force_crc2(c3)
# brute_force_crc2(c4)
# brute_force_crc2(c5)
# brute_force_crc2(c6)
# Reply: AF1E153F7201BA75FD8E58, Compute over 0D04-AF1E153F7201BA CRC Match: True, Calculated CRC: 8E58
# Reply: AFBC868CBB8C337F5CB51E, Compute over 30CB-AFBC868CBB8C33 CRC Match: True, Calculated CRC: B51E
# Reply: AF244AB29D3700A26ADC85, Compute over A5A4-AF244AB29D3700 CRC Match: True, Calculated CRC: DC85
# Reply: AF92D37042FE4A57A662EF, Compute over 86ED-AF92D37042FE4A CRC Match: True, Calculated CRC: 62EF

brute_force_crc3(c3)
brute_force_crc3(c4)
brute_force_crc3(c5)
brute_force_crc3(c6)
# Reply: AF1E153F7201BA75FD8E58, Compute over 6737-AF1E153F7201BA75FD CRC Match: True, Calculated CRC: 8E58
# Reply: AFBC868CBB8C337F5CB51E, Compute over 6737-AFBC868CBB8C337F5C CRC Match: True, Calculated CRC: B51E
# Reply: AF244AB29D3700A26ADC85, Compute over 6737-AF244AB29D3700A26A CRC Match: True, Calculated CRC: DC85
# Reply: AF92D37042FE4A57A662EF, Compute over 6737-AF92D37042FE4A57A6 CRC Match: True, Calculated CRC: 62EF
brute_force_crc4(c3)
brute_force_crc4(c4)
brute_force_crc4(c5)
brute_force_crc4(c6)
# nothing found

print("Nathan card")
# Cmd 1a00?+CRC: AFBCFD2520CC9E7525[C266] clear: 0676DC10470B8856
cn1 = "AFBCFD2520CC9E7525C266"
# Cmd 1a00?+CRC: AF4870A8A6CC7B1863[66D8] clear: 94A321EBFE41ADE9
cn2 = "AF4870A8A6CC7B186366D8"
# Cmd 1a00?+CRC: AFA1311399C2F427A5[161B] clear: 59CAE9CEFE6A7D73
cn3 = "AFA1311399C2F427A5161B"

for c in [cn1, cn2, cn3]:
    calculated_crc = append_crc16_a(c[:-4])
    diff = f"{int(calculated_crc[-4:], 16) ^ int(c[-4:], 16):04X}"
    print(f"Reply: {c}, CRC Match: {calculated_crc == c}, Calculated CRC: {calculated_crc}, Diff: {diff}")
    if diff != "0000":
        for init_crc in range(1 << 16):
            if crc16_a(c[:-4], init_crc) == c[-4:]:
                init_crc_hex = f"{init_crc & 0xFF:02X}{(init_crc >> 8) & 0xFF:02X}"
                diff = init_crc ^ 0x6363
                diff_hex = f"{diff & 0xFF:02X}{(diff >> 8) & 0xFF:02X}"
                print(f"Reply: {c}, Init CRC: {init_crc_hex} Init CRC diff: {diff_hex}")
                break

# Reply: AFBCFD2520CC9E7525C266, CRC Match: False, Calculated CRC: AFBCFD2520CC9E752576A3, Diff: B4C5
# Reply: AFBCFD2520CC9E7525C266, Init CRC: E5A1 Init CRC diff: 86C2
# Reply: AF4870A8A6CC7B186366D8, CRC Match: False, Calculated CRC: AF4870A8A6CC7B1863D21D, Diff: B4C5
# Reply: AF4870A8A6CC7B186366D8, Init CRC: E5A1 Init CRC diff: 86C2
# Reply: AFA1311399C2F427A5161B, CRC Match: False, Calculated CRC: AFA1311399C2F427A5A2DE, Diff: B4C5
# Reply: AFA1311399C2F427A5161B, Init CRC: E5A1 Init CRC diff: 86C2

# these bruteforce can't work as the diff is independent of the nonce,
# so full nonce has to be covered in crc computation
# brute_force_crc(cn1)
# brute_force_crc(cn2)
# brute_force_crc(cn3)
# brute_force_crc2(cn1)
# brute_force_crc2(cn2)
# brute_force_crc2(cn3)

brute_force_crc3(cn1)
brute_force_crc3(cn2)
brute_force_crc3(cn3)
# Reply: AFBCFD2520CC9E7525C266, Compute over 3AC3-AFBCFD2520CC9E7525 CRC Match: True, Calculated CRC: C266
# Reply: AF4870A8A6CC7B186366D8, Compute over 3AC3-AF4870A8A6CC7B1863 CRC Match: True, Calculated CRC: 66D8
# Reply: AFA1311399C2F427A5161B, Compute over 3AC3-AFA1311399C2F427A5 CRC Match: True, Calculated CRC: 161B
brute_force_crc4(cn1)
brute_force_crc4(cn2)
brute_force_crc4(cn3)
# nothing found


# related to the card but not related to the key...
