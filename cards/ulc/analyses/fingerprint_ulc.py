#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

from fingerprint import mypm3

MFUINFO = True
ATS = True
FDT = False
FDT_AVG = False
SF = False
SHORTCUT = False
CMD00 = True
CMD00MIDAUTH = False
CMD00POSTAUTH = True
WRITE_AUTH0 = False
# Only test known commands:
QUICKCMD00 = True

KEY = "49454D4B41455242214E4143554F5946"
# KEY = "00" * 16

cmd_list = None
if QUICKCMD00:
    cmd_list = ["1A", "1C", "30", "40", "50", "51", "63", "93", "95", "A0", "A2", "AF"]


def add_backquotes_to_hex_ranges(hex_string):
    # Split the input string by commas
    parts = hex_string.split(',')

    # Process each part
    processed_parts = []
    for part in parts:
        # If the part contains a range (indicated by '-')
        if '-' in part:
            # Split the range into start and end
            start, end = part.split('-')
            # Add backquotes and reassemble the range
            processed_part = f"`{start}`-`{end}`"
        else:
            # Otherwise, simply add backquotes to the part
            processed_part = f"`{part}`"
        # Add the processed part to the list
        processed_parts.append(processed_part)

    # Join the processed parts back with commas
    result = ','.join(processed_parts)
    return result


p = mypm3()

width = 16

p.read_14a()
if p.uid is None:
    print("Error getting UID!!")
    p.stop_session()
    exit()

if MFUINFO:
    print('\n'.join(p.run("hf mfu info")))

print(f"{'UID:':{width}} {p.uid:0{len(p.buid)*2}X}")
print(f"{'ATQA anticol:':{width}} {p.atqa}")
print(f"{'SAK anticol:':{width}} {p.sak}")

if ATS:
    ats = p.check_ats()
    print(f"{'Answer to RATS:':{width}} {ats}")

if FDT:
    fdt1, fdt2 = p.check_fdt()
    print(f"{'FDT to 1A00          : ':{width}} {fdt1:5} = {fdt1/13.56:5.2f} us")
    print(f"{'FDT to AF*  (bad key): ':{width}} {fdt2:5} = {fdt2/13.56:5.2f} us")
    fdt1, fdt2 = p.check_fdt(key=KEY)
    print(f"{'FDT to AF*  (def key): ':{width}} {fdt2:5} = {fdt2/13.56:5.2f} us")

if FDT_AVG:
    fdt1min = 100000
    fdt1max = 0
    fdt2badmin = 100000
    fdt2badmax = 0
    fdt2goodmin = 100000
    fdt2goodmax = 0
    for _ in range(20):
        fdt1, fdt2 = p.check_fdt()
        if fdt1 is None or fdt2 is None:
            continue
        print(f"{'FDT to 1A00          : ':{width}} {fdt1:5} = {fdt1/13.56:5.2f} us")
        print(f"{'FDT to AF*  (bad key): ':{width}} {fdt2:5} = {fdt2/13.56:5.2f} us")
        fdt1min = min(fdt1min, fdt1)
        fdt1max = max(fdt1max, fdt1)
        fdt2badmin = min(fdt2badmin, fdt2)
        fdt2badmax = max(fdt2badmax, fdt2)
        fdt1, fdt2 = p.check_fdt(key=KEY)
        if fdt1 is None or fdt2 is None:
            continue
        print(f"{'FDT to AF*  (def key): ':{width}} {fdt2:5} = {fdt2/13.56:5.2f} us")
        fdt1min = min(fdt1min, fdt1)
        fdt1max = max(fdt1max, fdt1)
        fdt2goodmin = min(fdt2goodmin, fdt2)
        fdt2goodmax = max(fdt2goodmax, fdt2)
    mean = (fdt1min + fdt1max) / 2
    delta = (fdt1max - fdt1min) / 2
    print(f"{'FDT to 1A00           min/max: ':{width}} {fdt1min:5}/{fdt1max:5} = "
          f"{fdt1min/13.56:5.2f}/{fdt1max/13.56:5.2f} us = {round(mean / 13.56)} +- {round(delta / 13.56)} us")
    mean = (fdt2badmin + fdt2badmax) / 2
    delta = (fdt2badmax - fdt2badmin) / 2
    print(f"{'FDT to AF*  (bad key) min/max: ':{width}} {fdt2badmin:5}/{fdt2badmax:5} = "
          f"{fdt2badmin/13.56:5.2f}/{fdt2badmax/13.56:5.2f} us = {round(mean / 13.56)} +- {round(delta / 13.56)} us")
    mean = (fdt2goodmin + fdt2goodmax) / 2
    delta = (fdt2goodmax - fdt2goodmin) / 2
    print(f"{'FDT to AF*  (def key) min/max: ':{width}} {fdt2goodmin:5}/{fdt2goodmax:5} = "
          f"{fdt2goodmin/13.56:5.2f}/{fdt2goodmax/13.56:5.2f} us = {round(mean / 13.56)} +- {round(delta / 13.56)} us")


if SF:
    print("Checking ShortFrames...")
    sf = ""
    for cmd, resp, extra in p.check_shortframes():
        print(f"ShortFrame {cmd:02x}:{'':{width-14}} {resp} {extra}")
        if cmd not in [0x26, 0x52]:
            if len(sf) == 0:
                sf += f"`{cmd:02x}`:`{resp}`"
            else:
                sf += f", `{cmd:02x}`:`{resp}`"
    if len(sf) > 0:
        sf = f", a_sf:[{sf}]"
else:
    sf = ", a_sf:[SKIPPED]"

if SHORTCUT:
    sf = 0x26
    for param, crc in [("00", True), ("  ", True), ("00", False), ("  ", False)]:
        # for i in range(256):
        #   for param, crc in [(f"{i:02x}", True), (f"{i:02x}", False)]:
        print(f"Checking Shortcut Commands {sf:02x};**{param}{['', '+CRC'][crc]} ...")
        results = p.check_shortcut_commands(sf=sf, param=param, crc=crc)
        for cmd, resp in results:
            if resp:
                print(f"Cmd {sf:02x};{cmd:02x}{param}:{'':{width-4}} {resp}")

# ULCG reply to shortcut 26;40xx (no CRC) always with FD!FFFFFF13!0202 (bad parity, no CRC)
# ULCG reply to shortcut 52;40xx (no CRC) always with FD!FFFFFF13!0202 (bad parity, no CRC)
# 40xx can be chained while card is halted after one 3000
# sf = 0x26
# cmd = "40"
# crc = False
# print(f"Checking Shortcut Command Params {sf:02x};{cmd}**{['', '+CRC'][crc]} ...")
# results = p.check_shortcut_params(sf=sf, cmdbyte=cmd, crc=crc)
# for param, resp in results:
#     if resp:
#         print(param, resp)
#         print(f"Cmd {sf:02x};{cmd}{param:02x}:{'':{width-4}} {resp}")

if CMD00:
    sf = 0x52
    for param, crc in [("00", True), ("  ", True), ("00", False), ("  ", False)]:
        # for i in range(256):
        #   for param, crc in [(f"{i:02x}", True), (f"{i:02x}", False)]:
        # for param, crc in [("08", True), ("08"*2, True), ("08"*3, True), ("08"*4, True), ("08"*5, True), ("08"*6, True), ("08"*7, True), ("08"*8, True), ("08"*9, True), ("08"*10, True), ("08"*11, True), ("08"*12, True), ("08"*13, True), ("08"*14, True), ("08"*15, True), ("08"*16, True), ("08"*17, True)]:
        print(f"Checking Commands **{param}{['', '+CRC'][crc]} ...")
        results = p.check_commands(sf=sf, cmd_list=cmd_list, param=param, crc=crc)
        for cmd, resp in results:
            if resp not in ['00', '01', '04']:
                print(f"Cmd {cmd:02x}{param}:{'':{width-12}} {resp}")
                response = ''.join(filter(str.isalnum, resp))
                if response[:2] == 'AF':
                    leaked_data = p.crc_leak(response[:-4], response[-4:])
                    if (leaked_data != '0') and (not (response == '00' and leaked_data == '6363')):
                        print(f"{'':{width-2}}Wrong CRC, diff: {leaked_data}")
        a_00 = ""
        a_01 = ""
        a_04 = ""
        if '00' in [r for _, r in results]:
            a_00 = p.repr_range([c for c, r in results if r == '00'])
            print(f"Cmd **{param}=00:{'':{width-15}} " + a_00)
        if '01' in [r for _, r in results]:
            a_01 = p.repr_range([c for c, r in results if r == '01'])
            print(f"Cmd **{param}=01:{'':{width-15}} " + a_01)
        if '04' in [r for _, r in results]:
            a_04 = p.repr_range([c for c, r in results if r == '04'])
            print(f"Cmd **{param}=04:{'':{width-15}} " + a_04)

if CMD00MIDAUTH:
    sf = 0x52
    for param, crc in [("00", True), ("  ", True), ("00", False), ("  ", False)]:
        print(f"Checking Commands Mid-Auth  **{param}{['', '+CRC'][crc]} ...")
        key = KEY
        results = p.check_commands(sf=sf, cmd_list=cmd_list, param=param, crc=crc, mid=True)
        for cmd, resp in results:
            if resp not in ['00', '01', '04']:
                print(f"Cmd {cmd:02x}{param}:{'':{width-12}} {resp}")
        a_00 = ""
        a_01 = ""
        a_04 = ""
        if '00' in [r for _, r in results]:
            a_00 = p.repr_range([c for c, r in results if r == '00'])
            print(f"Cmd **{param}=00:{'':{width-15}} " + a_00)
        if '01' in [r for _, r in results]:
            a_01 = p.repr_range([c for c, r in results if r == '01'])
            print(f"Cmd **{param}=01:{'':{width-15}} " + a_01)
        if '04' in [r for _, r in results]:
            a_04 = p.repr_range([c for c, r in results if r == '04'])
            print(f"Cmd **{param}=04:{'':{width-15}} " + a_04)

if CMD00POSTAUTH:
    sf = 0x52
    for param, crc in [("00", True), ("  ", True), ("00", False), ("  ", False)]:
        # for i in range(0x1b, 256):
        #   for param, crc in [(f"{i:02x}", True), (f"{i:02x}", False)]:
        print(f"Checking Commands Post-Auth **{param}{['', '+CRC'][crc]} ...")
        key = KEY
        results = p.check_commands(sf=sf, cmd_list=cmd_list, param=param, crc=crc, key=key)
        for cmd, resp in results:
            if resp not in ['00', '01', '04']:
                print(f"Cmd {cmd:02x}{param}:{'':{width-12}} {resp}")
                response = ''.join(filter(str.isalnum, resp))
                if response[:2] == 'AF':
                    leaked_data = p.crc_leak(response[:-4], response[-4:])
                    if (leaked_data != '0') and (not (response == '00' and leaked_data == '6363')):
                        print(f"{'':{width-2}}Wrong CRC, diff: {leaked_data}")
        a_00 = ""
        a_01 = ""
        a_04 = ""
        if '00' in [r for _, r in results]:
            a_00 = p.repr_range([c for c, r in results if r == '00'])
            print(f"Cmd **{param}=00:{'':{width-15}} " + a_00)
        if '01' in [r for _, r in results]:
            a_01 = p.repr_range([c for c, r in results if r == '01'])
            print(f"Cmd **{param}=01:{'':{width-15}} " + a_01)
        if '04' in [r for _, r in results]:
            a_04 = p.repr_range([c for c, r in results if r == '04'])
            print(f"Cmd **{param}=04:{'':{width-15}} " + a_04)


if WRITE_AUTH0:
    for _ in range(1):
        success = False
        for line in p.run(f"hf mfu wrbl -b 42 -d 00000000 -k {KEY}"):
            if "Write ( ok )" in line:
                success = True
        if not success:
            print("Error writing auth0 block!!")
            break
        success = False
        for line in p.run(f"hf mfu rdbl -b 42 -k {KEY}"):
            if "42/0x2A | 00 00 00 00" in line:
                success = True
        if not success:
            print("Error writing auth0 block didn't actually occur!!")
            break
        error = False
        for line in p.run("hf mfu rdbl -b 0"):
            if "Read block error" in line:
                error = True
        print(f"AUTH0=00 Read0     : {['allowed', 'denied'][error]}")
        # for line in p.run("hf mfu rdbl -b 0"):
        #     if "Read block error" in line:
        #         success = True
        # print(f"Read 0 with AUTH0=0  : {['allowed', 'denied'][success]}")

        p.run("hf 14a raw -ak -b7 26")
        success = False
        for line in p.run("hf 14a raw -c 3000"):
            if "[+] " in line:
                success = True
        print(f"AUTH0=00 Fast Read0: {['denied', 'allowed'][success]}")

        p.run(f"hf mfu wrbl -b 42 -d 30000000 -k {KEY}")

p.stop_session()
