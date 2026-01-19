#!/usr/bin/env python3

import time


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


def valid_lfsr_uscuidul(nonce):
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


class mypm3():
    interrupt_requested = False

    def signal_handler(self, sig, frame):
        print('You pressed CTRL+C!')
        self.interrupt_requested = True

    def __init__(self):
        import pm3
        import signal
        # Setting up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        self.start_time = time.time()
        self.p = pm3.pm3()

    def stop_session(self):
        elapsed_time = time.time() - self.start_time
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        print(f"--- {minutes} minutes {seconds} seconds ---")

    def run(self, cmds):
        DEBUG = False
        if type(cmds) is not list:
            cmds = [cmds]
        if DEBUG:
            for cmd in cmds:
                print(cmd)
        for cmd in cmds:
            self.p.console(cmd)
        grabbed_output = self.p.grabbed_output
        if DEBUG:
            print(grabbed_output)
        return grabbed_output.split('\n')

    uid = None
    buid = None
    atqa = None
    sak = None

    def read_14a(self):
        for line in self.run(["hf 14a read"]):
            if "UID:" in line:
                self.uid = int(line[10:].replace(' ', ''), 16)
                if len(line) > 31:
                    self.buid = self.uid.to_bytes(10, byteorder='big')
                elif len(line) > 22:
                    self.buid = self.uid.to_bytes(7, byteorder='big')
                else:
                    self.buid = self.uid.to_bytes(4, byteorder='big')
            if "ATQA:" in line:
                self.atqa = line[10:15]
            if "SAK:" in line:
                self.sak = line[10:12]
        return self.uid

    block0 = None
    block0_direct = False
    auth = None
    auth_desc = None

    ats = None

    def check_ats(self):
        for line in self.run(["hf 14a raw -s3c e000"]):
            if len(line) > 0:
                self.ats = line[4:].replace(' ', '').replace('[', '').replace(']', '')
        return self.ats

    fdt1 = None
    fdt2 = None

    def check_fdt(self, key=None):
        step = 0
        self.fdt1, self.fdt2 = None, None
        if key is not None:
            for line in self.run([f"hf mfu cauth --key {key}",
                                  "trace list -t mf --frame"]):
                if "Rdr |1A  00" in line:
                    step = 1
                if step == 1 and "Frame Delay Time" in line:
                    self.fdt1 = int(line[48:].rstrip())
                    step = 2
                if "Rdr |AF" in line:
                    step = 3
                if step == 3 and "Frame Delay Time" in line:
                    self.fdt2 = int(line[48:].rstrip())
            return self.fdt1, self.fdt2
        else:
            for line in self.run(["hf 14a raw -s3ck 1A00",
                                  "trace list -t mf --frame"]):
                if "Rdr |1A  00" in line:
                    step = 1
                if step == 1 and "Frame Delay Time" in line:
                    self.fdt1 = int(line[48:].rstrip())
                    step = 2
            for line in self.run(["hf 14a raw -c AF00000000000000000000000000000000",
                                  "trace list -t mf --frame"]):
                if "Rdr |AF" in line:
                    step = 3
                if step == 3 and "Frame Delay Time" in line:
                    self.fdt2 = int(line[48:].rstrip())
            return self.fdt1, self.fdt2

    checkparity = None

    shortframes = None

    def check_shortframes(self):
        cmds = []
        for cmd in range(128):
            cmds.append(f"rem {cmd:02x}")
            cmds.append(f"hf 14a raw -a -b7 {cmd:02x}")
        self.shortframes = []
        for line in self.run(cmds):
            if 'remark:' in line:
                cmd = int(line[33:], 16)
            elif len(line) > 0:
                resp = line[4:].replace(' ', '')
                if cmd == 0x26:
                    extra = "(REQA)"
                elif cmd == 0x52:
                    extra = "(WUPA)"
                else:
                    extra = "(???)"
                self.shortframes.append((cmd, resp, extra))
        return self.shortframes

    def check_shortcut_commands(self, sf=0x26, param="00", crc=True):
        # Add REQA to possibly CHECK_SF list
        cmds = []
        for cmd in range(256):
            cmds.append("rem SF")
            cmds.append(f"hf 14a raw -ak -b7 {sf:02x}")
            cmds.append(f"rem {cmd:02x}")
            if crc:
                cmds.append(f"hf 14a raw -c {cmd:02x}{param}")
            else:
                cmds.append(f"hf 14a raw {cmd:02x}{param}")
        results = []
        for line in self.run(cmds):
            if 'remark: SF' in line:
                cmd = None
            elif 'remark:' in line:
                cmd = int(line[33:], 16)
            elif len(line) > 0 and cmd is not None:
                resp = line[4:].replace(' ', '')
                results.append((cmd, resp))
        return results

    def check_shortcut_params(self, sf=0x26, cmdbyte="40", crc=True):
        # Add REQA to possibly CHECK_SF list
        cmds = []
        for param in range(256):
            cmds.append("rem SF")
            cmds.append(f"hf 14a raw -ak -b7 {sf:02x}")
            cmds.append(f"rem {param:02x}")
            if crc:
                cmds.append(f"hf 14a raw -c {cmdbyte}{param:02x}")
            else:
                cmds.append(f"hf 14a raw {cmdbyte}{param:02x}")
        results = []
        for line in self.run(cmds):
            if 'remark: SF' in line:
                param = None
            elif 'remark:' in line:
                param = int(line[33:], 16)
            elif len(line) > 0 and param is not None:
                resp = line[4:].replace(' ', '')
                results.append((param, resp))
        return results

    def check_commands(self, sf=0x52, cmd_list=None, param="00", crc=True, key=None, mid=False):
        results = []
        if cmd_list is None:
            cmd_list = [f"{i:02x}" for i in range(256)]
        for cmd_hex in cmd_list:
            cmds = []
            if key is not None:
                cmds.append(f"hf mfu cauth --key {key} -k")
                if crc:
                    cmds.append(f"hf 14a raw -c {cmd_hex}{param}")
                else:
                    cmds.append(f"hf 14a raw {cmd_hex}{param}")
            elif mid:
                self.select(sf, keep=True)
                cmds.append("hf 14a raw -ck 1A00")
                if crc:
                    cmds.append(f"hf 14a raw -c {cmd_hex}{param}")
                else:
                    cmds.append(f"hf 14a raw {cmd_hex}{param}")
            else:
                if sf == 0x52:
                    if crc:
                        cmds.append(f"hf 14a raw -s3c {cmd_hex}{param}")

                    else:
                        cmds.append(f"hf 14a raw -s3 {cmd_hex}{param}")
                else:
                    self.select(sf, keep=True)
                    if crc:
                        cmds.append(f"hf 14a raw -c {cmd_hex}{param}")
                    else:
                        cmds.append(f"hf 14a raw {cmd_hex}{param}")
            for line in self.run(cmds):
                if len(line) > 0 and 'Authentication 3DES key' not in line:
                    if mid and '[+] AF ' in line:
                        continue
                    resp = line[4:].replace(' ', '')
                    results.append((int(cmd_hex, 16), resp))
        return results

    @staticmethod
    def repr_range(vals):
        s = ""
        if len(vals) > 0:
            prev = None
            rang = False
            for i in vals:
                if prev is None:
                    s += f"{i:02x}"
                    prev = i
                else:
                    if i == prev + 1:
                        if rang is False:
                            s += "-"
                            rang = True
                        prev = i
                    else:
                        if rang is True:
                            s += f"{prev:02x},{i:02x}"
                        else:
                            s += f",{i:02x}"
                        prev = i
                        rang = False
            if rang is True:
                s += f"{prev:02x}"
        return s

    uidx = None
    uidx2 = None

    def select(self, sf=0x26, keep=False):
        if self.uidx is None:
            cmds = [f"hf 14a raw -ak -b7 {sf:02x}",
                    "hf 14a raw 9320"]
            for line in self.run(cmds):
                if len(line) >= 22:
                    self.uidx = line[4:].replace(' ', '').replace('[', '').replace(']', '')
        if self.uidx is None:
            print(f"Failed selecting the card with {sf:02x}(7);9320")
            return
        if self.uidx[:2] == "88" and self.uidx2 is None:
            cmds = [f"hf 14a raw -ak -b7 {sf:02x}",
                    # "hf 14a raw -k 9320",
                    f"hf 14a raw -kc 9370{self.uidx}",
                    "hf 14a raw 9520"]
            for line in self.run(cmds):
                if len(line) >= 22:
                    self.uidx2 = line[4:].replace(' ', '').replace('[', '').replace(']', '')
            if self.uidx2 is None:
                print(f"Failed L2 selecting the card with {sf:02x}(7);9520")
                return
        if keep:
            cmds = [f"hf 14a raw -ak -b7 {sf:02x}",
                    f"hf 14a raw -kc 9370{self.uidx}"]
            if self.uidx[:2] == "88" and self.uidx2 is not None:
                cmds.append(f"hf 14a raw -kc 9570{self.uidx2}")
            self.run(cmds)

    @staticmethod
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
