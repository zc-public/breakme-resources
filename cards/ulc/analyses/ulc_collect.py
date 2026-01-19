#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import argparse
import sys
import json
import time
import random
import pm3
try:
    from Crypto.Cipher import DES, DES3
except ModuleNotFoundError:
    print("MISSING: pip install pycryptodome")
    exit()

required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()


def expand_challenges(dict_chal):
    list_chals = []
    for key in dict_chal:
        list_chals.extend([key] * dict_chal[key])
    random.shuffle(list_chals)
    return list_chals


def compress_challenges(list_chals):
    dict_chal = {}
    for chal in list_chals:
        if type(chal) is tuple:
            # Challenge with CRC
            chal = chal[0]
        if chal in dict_chal:
            dict_chal[chal] += 1
        else:
            dict_chal[chal] = 1
    return dict_chal


def resample_challenges(collected_data):
    challenges_0 = compress_challenges(collected_data)
    challenges_0_sorted_desc = dict(sorted(challenges_0.items(), key=lambda item: item[1], reverse=True))
    results = {"challenges_0_sorted": challenges_0_sorted_desc}
    return results


def collect(num_challenges: int, p, key_value=None, with_timestamp=False) -> list:
    """
    Collect a specified number of challenge plaintexts from an Ultralight C card using a Proxmark device.

    Args:
        num_challenges (int): The number of challenge plaintexts to collect.
        p: An instance of the Proxmark client interface.
        key_value: Optional hexadecimal string representing the key to use for decryption.

    Returns:
        list: A list of collected challenge plaintexts in hexadecimal string format.

    Raises:
        RuntimeError: If an Ultralight C card is not detected or if the key cannot be found.
    """
    # Sanity check: make sure an Ultralight C is on the Proxmark
    p.console("hf 14a info")
    if "MIFARE Ultralight C" not in p.grabbed_output:
        print("[-] Error: \033[1;31mUltralight C not placed on Proxmark\033[0m")
        return []
    else:
        print("[+] Ultralight C detected. Keep stable on Proxmark during the attack.")

    # Find key
    if key_value is None:
        p.console("hf mfu cauth")
        result = p.grabbed_output
        if "ok" not in result:
            print("[-] Error: \033[1;31mUnknown key\033[0m")
            return []
        else:
            result_line = next((line for line in result.splitlines() if "ok" in line), None)
            if result_line:
                key_value = result_line.split("...")[1].split("(")[0].strip()
                print(f"[+] Detected key: {key_value}")
    else:
        # test provided key
        p.console(f"hf mfu cauth --key {key_value}")
        result = p.grabbed_output
        if "ok" not in result:
            print("[-] Error: \033[1;31mWrong key\033[0m")
            return []

    assert key_value is not None
    key = bytes.fromhex(key_value)
    zero_iv = b"\x00" * 8
    # Collect challenge plaintexts
    challenges_collected = 0
    challenges = []

    def parse_1a00_output(p):
        challenge = p.grabbed_output.split()
        if (len(challenge) > 8) and (challenge[1] == "AF"):
            hex_challenge = "".join(challenge[2:10])
            hex_crc = "".join(challenge[11:13])
            return hex_challenge, hex_crc
        return None, None

    def parse_trace_output(p):
        p.console("trace list -t 14a")
        for line in p.grabbed_output.split('\n'):
            if "Tag |AF" in line:
                data = [x.strip() for x in line.split("|")]
                timestamp = int(data[0])
                challenge = data[3].split()
                hex_challenge = "".join(challenge[1:9])
                hex_crc = "".join(challenge[9:11])
                return hex_challenge, hex_crc, timestamp
        return None, None, 0

    while challenges_collected < num_challenges:
        hex_challenge = None
        timestamp = 0
        if mode == "STABLE":
            # key does not matter here
            p.console(f"hf mfu cauth --key {key_value} -n", capture=False)
            hex_challenge, hex_crc, timestamp = parse_trace_output(p)

        elif mode == "RAW":
            # more jitter
            p.console("hf 14a raw -sc 1A00")
            hex_challenge, hex_crc = parse_1a00_output(p)

        elif mode == "RAW_NOCRC":
            p.console("hf 14a raw -s 1A00")
            hex_challenge, hex_crc = parse_1a00_output(p)

        elif mode == "RAW_POSTAUTH":
            p.console(f"hf mfu cauth --key {key_value} -k")
            assert 'ok' in p.grabbed_output
            time.sleep(0.02)
            p.console("hf 14a raw 1A00")
            hex_challenge, hex_crc = parse_1a00_output(p)

        elif mode == "RAW_TEST":
            DELAY_REQA = 0
            REDO_REQA = 0
            DELAY_FASTSELECT = 0
            ADD_INSTRUCTION = 0
            DELAY_AUTH = 0
            p.console("hf 14a raw -a -k -r 00", capture=False)
            if DELAY_REQA > 0:
                time.sleep(DELAY_REQA)
            p.console("hf 14a raw -b 7 -k 26", capture=False)
            time.sleep(0.002)
            for _ in range(REDO_REQA):
                p.console("hf 14a raw -k -r 00", capture=False)
                p.console("hf 14a raw -b 7 -k 26", capture=False)
                time.sleep(0.002)
            if DELAY_FASTSELECT > 0:
                time.sleep(DELAY_FASTSELECT)
            # Fast select
            p.console("hf 14a raw -ck 3000", capture=False)
            time.sleep(0.002)
            for _ in range(ADD_INSTRUCTION):
                p.console("hf 14a raw -ck 3000", capture=False)
                time.sleep(0.002)
            if DELAY_AUTH > 0:
                time.sleep(DELAY_AUTH)
            # Auth command
            p.console("hf 14a raw -c 1a00")
            hex_challenge, hex_crc = parse_1a00_output(p)

        if hex_challenge is None:
            continue
        PICC_ekRndB = bytes.fromhex(hex_challenge)
        if key[:8] == key[8:]:
            rndB = DES.new(key[:8], DES.MODE_CBC, iv=zero_iv).decrypt(PICC_ekRndB).hex().upper()
        else:
            rndB = DES3.new(key, DES3.MODE_CBC, iv=zero_iv).decrypt(PICC_ekRndB).hex().upper()
        # USCUID-UL produces some challenges with wrong CRC?
        # if rndB in ["0676DC10470B8856", "94A321EBFE41ADE9", "59CAE9CEFE6A7D73"]:
        #     print(f"[-] Found a challenge with wrong CRC: {rndB} {hex_crc}")
        if with_timestamp:
            challenges.append((rndB, hex_crc, timestamp))
        else:
            challenges.append((rndB, hex_crc))
        challenges_collected += 1
        print(f"\r[+] Challenge plaintexts collected: \033[96m{challenges_collected}\033[0m", end="")

    print("\n[+] Collection complete")
    return challenges


def blind_collect(num_challenges: int, p) -> list:
    """
    Collect a specified number of challenge ciphertexts from an Ultralight C card using a Proxmark device.

    Args:
        num_challenges (int): The number of challenge ciphertexts to collect.
        p: An instance of the Proxmark client interface.

    Returns:
        list: A list of collected challenge ciphertexts in hexadecimal string format.

    Raises:
        RuntimeError: If an Ultralight C card is not detected.
    """
    # Sanity check: make sure an Ultralight C is on the Proxmark
    p.console("hf 14a info")
    if "MIFARE Ultralight C" not in p.grabbed_output:
        print("[-] Error: \033[1;31mUltralight C not placed on Proxmark\033[0m")
        return []
    else:
        print("[+] Ultralight C detected. Keep stable on Proxmark during the attack.")

    # Collect challenge ciphertexts
    challenges_collected = 0
    challenges = []
    while challenges_collected < num_challenges:
        if mode == "STABLE":
            # key does not matter here
            p.console("hf mfu cauth --key 49454D4B41455242214E4143554F5946 -n", capture=False)
            p.console("trace list -t 14a")
            hex_challenge = None
            for line in p.grabbed_output.split('\n'):
                if "Tag |AF" in line:
                    challenge = line.split("Tag |AF")[1].strip().split()[:8]
                    hex_challenge = "".join(challenge)
                    break
            if hex_challenge is None:
                continue

        elif mode == "RAW":
            # jitter because 14a raw -s emits 2 USB commands
            p.console("hf 14a raw -sc 1A00")
            challenge = p.grabbed_output.split()
            if (len(challenge) > 8) and (challenge[1] == "AF"):
                hex_challenge = "".join(challenge[2:10])
                break
            if hex_challenge is None:
                continue

        assert hex_challenge is not None
        challenges.append(hex_challenge)
        challenges_collected += 1
        print(f"\r[+] Challenge ciphertexts collected: \033[96m{challenges_collected}\033[0m", end="")
    print("\n[+] Collection complete")
    return challenges


def main():
    """
    Collect ULC challenges.

    This function parses command-line arguments to determine the number of challenges to collect,
    and the path to the JSON file where collected data will be saved.
    It then collects the specified number of challenges and saves them to the JSON file.

    Command-line arguments:
    -c, --challenges: Set number of challenges to collect (default: 1000)
    -b, --blind: Key unknown, collect only ciphertexts
    -j, --json: Path to JSON file with collected data (default: "challenges.json")

    Returns:
    None
    """
    parser = argparse.ArgumentParser(description='A script to collect ULC challenges.')
    parser.add_argument('-c', '--challenges', help='Set number of challenges to collect', type=int, default=1000)
    parser.add_argument('-b', '--blind', help='Key unknown, collect only ciphertexts', action='store_true')
    parser.add_argument('-j', '--json', help='Path to JSON file with collected data')
    parser.add_argument('-k', '--key', help='Key in hexadecimal format (optional)', type=str)
    parser.add_argument('-m', '--mode', help='Set mode of operation', type=str,
                        choices=["STABLE", "RAW", "RAW_NOCRC", "RAW_POSTAUTH", "RAW_TEST"], default="STABLE")
    parser.add_argument('-t', '--with-timestamp',
                        help='Include timestamp in collected challenges (only with STABLE mode)', action='store_true')
    args = parser.parse_args()
    global mode
    mode = args.mode
    num_challenges = args.challenges
    jsonfile = args.json
    if jsonfile is None:
        jsonfile = "challenges.json"
    key = args.key

    p = pm3.pm3()
    if args.blind:
        challenges = blind_collect(num_challenges, p)
    else:
        challenges = collect(num_challenges, p, key, args.with_timestamp)
    if len(challenges) == 0:
        return

    if not args.with_timestamp:
        challenges = resample_challenges(challenges)

    with open(jsonfile, "w") as f:
        json.dump(challenges, f)
        print(f"[+] Challenges saved to {jsonfile}")


if __name__ == '__main__':
    main()
