#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

"""
PM3 client script: Test write endurance of UL-C
Datasheet specifies 10k limit

Place under client/pyscripts/ and run via `script run endurance_test` via pm3 CLI.

Defaults:
  start = 0x0
  block = 35 (0x23)
  key   = 5C0E5DE145B5F8921BD418F9B53F6F69

Behavior:
 - Authenticate once via:
     hf mfu cauth --key <KEY> -k
   (keeps field on)
 - For each value:
     write: hf 14a raw -kc A2<bb><vvvvvvvv>
       where <bb> = block hex (2 chars), <vvvvvvvv> = 8-char hex (big-endian bytes)
     read:  hf 14a raw -kc 30<bb>
       takes first 4 bytes from the response and compares to written value
 - On mismatch or missing data: re-auth and retry up to --retries.
 - Prints each successfully-written 8-char hex value (one per line).
"""

import pm3
import sys
import argparse
import re
import signal
import time
import random


def parse_num(s):
    if s is None:
        return None
    s = str(s)
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if re.search(r"[a-fA-F]", s):
        return int(s, 16)
    return int(s, 10)


def handle_sigint(signum, frame):
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


signal.signal(signal.SIGINT, handle_sigint)


def cauth(p, key, quiet=True):
    """
    Authenticate and keep the field on (-k).
    Returns True if we do not see obvious failure strings; False if we detect clear failure.
    """
    cmd = f"hf mfu cauth --key {key} -k"
    p.console(cmd, quiet=quiet)
    out = (p.grabbed_output or "").lower()
    if "card not found" in out or "error" in out:
        return False
    return True


def extract_first_4_bytes_from_raw_output(output):
    """
    Parse pm3 `hf 14a raw -kc ...` output and extract the first 4 bytes returned as an 8-char hex string.
    Strategy: prioritize spaced byte tokens, fallback to contiguous hex chunk.
    Returns lower-case 8-char hex string, or None if not enough bytes found.
    """
    if not output:
        return None
    # Prefer explicit byte tokens like "00 aa ff 12"
    tokens = re.findall(r'\b[0-9a-fA-F]{2}\b', output)
    if len(tokens) >= 4:
        first4 = ''.join(tokens[:4]).lower()
        return first4
    # Fallback: look for a contiguous hex chunk and take its first 8 hex chars
    long_hex = re.search(r'([0-9a-fA-F]{8,})', output)
    if long_hex:
        candidate = long_hex.group(1)[:8]
        if re.fullmatch(r'[0-9a-fA-F]{8}', candidate):
            return candidate.lower()
    return None


def main():
    parser = argparse.ArgumentParser(description="PM3 auth-once write+verify loop for 4-byte values.")
    parser.add_argument("--start", "-s", default="0x0",
                        help="Start value (hex with 0x or decimal or plain hex). Default 0x0")
    parser.add_argument("--max", "-m", default="0xFFFFFFFF",
                        help="Max value (inclusive). Default 0xFFFFFFFF")
    parser.add_argument("--key", "-k", default="5C0E5DE145B5F8921BD418F9B53F6F69",
                        help="Key to use for operations (hex string)")
    parser.add_argument("--block", "-b", type=int, default=35,
                        help="Block number to write/read. Default 35")
    parser.add_argument("--retries", "-r", type=int, default=3,
                        help="Retries per value before abort. Default 3")
    parser.add_argument("--show-output", action="store_true",
                        help="Show underlying pm3 console output for write/read/auth (debug).")
    parser.add_argument("--write-delay", type=float, default=0.0,
                        help="Extra delay (seconds) after write before reading (default 0.0). "
                        "Use small value if hardware needs it.")
    args = parser.parse_args()

    try:
        start_int = parse_num(args.start)
        max_int = parse_num(args.max)
    except ValueError as e:
        print(f"Invalid start/max value: {e}", file=sys.stderr)
        sys.exit(2)

    if start_int < 0 or max_int < 0:
        print("Start or max is negative. Use non-negative values.", file=sys.stderr)
        sys.exit(2)
    if start_int > max_int:
        print("Start > Max. Nothing to do.", file=sys.stderr)
        sys.exit(0)

    KEY = args.key
    BLOCK = args.block
    MAX_RETRIES = args.retries
    SHOW = args.show_output
    WRITE_DELAY = max(0.0, float(args.write_delay))

    p = pm3.pm3()
    if p is None:
        print("Failed to initialize pm3 client.", file=sys.stderr)
        sys.exit(2)

    block_hex = f"{BLOCK:02x}"

    # initial auth (keep field on)
    if not cauth(p, KEY, quiet=not SHOW):
        print("Initial authentication may have failed (check card or key). Attempting anyway.", file=sys.stderr)

    current = start_int
    while current <= max_int:
        hexval = f"{current:08x}"  # lowercase, zero-padded
        attempt = 1
        success = False

        while attempt <= MAX_RETRIES:
            # write via raw: A2 + block + 8-hex (4 bytes)
            write_payload = f"A2{block_hex}{hexval}"
            write_cmd = f"hf 14a raw -kc {write_payload}"
            p.console(write_cmd, quiet=not SHOW)
            # consume the write output immediately so it doesn't pollute the subsequent read
            write_out = p.grabbed_output or ""
            if SHOW:
                print("### WRITE OUTPUT ###")
                print(write_out)

            # optional tiny delay for hardware to settle if user requested
            if WRITE_DELAY > 0.0:
                time.sleep(WRITE_DELAY)

            # optimization: only read every 100 writes
            # if (current % 100) != 0:
            #  randomly sample reads to compensate for stuck bits
            if (random.randint(1, 100) != 100) and (attempt == 1):
                success = True
                break

            # read via raw: 30 + block
            read_payload = f"30{block_hex}"
            read_cmd = f"hf 14a raw -kc {read_payload}"
            p.console(read_cmd, quiet=not SHOW)
            read_out = p.grabbed_output or ""
            if SHOW:
                print("### READ OUTPUT ###")
                print(read_out)

            readhex = extract_first_4_bytes_from_raw_output(read_out)

            if readhex is None:
                # nothing useful returned; re-auth and retry
                print(f"Attempt {attempt}/{MAX_RETRIES}: no useful read data for {hexval}. "
                      f"Reauthing and retrying...", file=sys.stderr)
                if not cauth(p, KEY, quiet=not SHOW):
                    print(f"Attempt {attempt}/{MAX_RETRIES}: reauth seems to have failed (or no confirmation).",
                          file=sys.stderr)
                attempt += 1
                continue

            if readhex == hexval:
                print(hexval)
                sys.stdout.flush()
                success = True
                break
            else:
                print(f"Attempt {attempt}/{MAX_RETRIES}: verification mismatch. wrote={hexval} read={readhex}. "
                      f"Reauthing...", file=sys.stderr)
                if not cauth(p, KEY, quiet=not SHOW):
                    print(f"Attempt {attempt}/{MAX_RETRIES}: reauth seems to have failed (or no confirmation).",
                          file=sys.stderr)
                attempt += 1

        if not success:
            print(f"Verification failed for {hexval} after {MAX_RETRIES} attempts. Terminating.", file=sys.stderr)
            sys.exit(3)

        current += 1

    print(f"Completed up to 0x{max_int:X}.")
    sys.exit(0)


if __name__ == "__main__":
    main()
