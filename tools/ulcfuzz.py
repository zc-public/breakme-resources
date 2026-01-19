#!/usr/bin/env -S uv run --with pycryptodome pm3 -y

import base64
import argparse
import os
import sys
import re
import traceback
from Crypto.Cipher import DES3


class PM3Client:
    """Class for interacting with Proxmark3 device using the pm3 API"""

    def __init__(self, debug=False):
        self.debug = debug
        # Import pm3 module
        try:
            import pm3
            self.pm3 = pm3.pm3()
        except ImportError:
            print("Error: Could not import pm3 module. Make sure it's installed.")
            sys.exit(1)

    def console(self, cmd: str) -> str:
        """Run a Proxmark3 command and return the output"""
        if self.debug:
            print(f"Running: {cmd}")
        self.pm3.console(cmd)
        output = self.pm3.grabbed_output
        if self.debug:
            print(f"Output: {output}")
        return output

    def reset_field(self) -> None:
        """Reset the RF field properly"""
        pass

    def ulc_extract_challenge(self, output: str) -> str:
        """Extract the authentication challenge from Proxmark output"""
        parts = output.strip().split()
        if len(parts) > 8 and parts[1] == "AF":
            # The challenge is the 8 bytes after "AF"
            return ''.join(parts[2:10])
        return ""


class UltraLightEnumerator:
    """Class to enumerate all commands for an Ultralight C/AES card"""

    def __init__(self, key: str, debug=False):
        self.key = key
        self.pm3 = PM3Client(debug)
        self.debug = debug
        self.results = {}
        self.card_type = None
        self.temp_save_filename = None

    def authenticate(self) -> None:
        if self.card_type == "ULC":
            # auth_output = self.pm3.console("hf 14a raw -skc 1A00")
            # challenge = self.pm3.ulc_extract_challenge(auth_output)
            # auth_response = self.ulc_generate_auth_response(challenge)
            # self.pm3.console(f"hf 14a raw -kc {auth_response}")
            output = self.pm3.console(f"hf mfu cauth --key {self.key} -k")
            if "ok" not in output:
                raise Exception("Error authenticating to Ultralight C card")
        elif self.card_type == "ULAES":
            output = self.pm3.console(f"hf mfu aesauth --key {self.key} --index 0 -k")
            if "ok" not in output:
                raise Exception("Error authenticating to Ultralight AES card")

    def ulc_generate_auth_response(self, challenge: str) -> str:
        """Generate authentication response for the given challenge using the key"""
        try:
            # Parse challenge
            picc_ekRndB = bytes.fromhex(challenge)
            if len(picc_ekRndB) != 8:
                if self.debug:
                    print(f"Invalid challenge length: {len(picc_ekRndB)} bytes")
                return ""

            # Parse key
            key_bytes = bytes.fromhex(self.key)
            if len(key_bytes) != 16:
                if self.debug:
                    print(f"Invalid key length: {len(key_bytes)} bytes")
                return ""

            # Decrypt PICC_ekRndB to get RndB using zero IV
            zero_iv = b"\x00" * 8
            cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=zero_iv)
            rndB = cipher.decrypt(picc_ekRndB)

            # Use static RndA
            rndA = bytes.fromhex("A8AF3B256C75ED40")

            # Rotate RndB left by 1 byte to get RndB'
            rndB_prime = rndB[1:] + rndB[:1]

            # Concatenate RndA || RndB'
            rndA_rndB_prime = rndA + rndB_prime

            # Encrypt using PICC_ekRndB as IV
            cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv=picc_ekRndB)
            response = cipher.encrypt(rndA_rndB_prime)

            # Return response with AF prefix
            return "AF" + response.hex().upper()

        except Exception as e:
            if self.debug:
                print(f"Error generating auth response: {e}")
            return ""

    def verify_card_presence(self) -> bool:
        """Verify that an Ultralight C/AES card is present"""
        output = self.pm3.console("hf mfu info")
        if "MIFARE Ultralight C" in output:
            self.card_type = "ULC"
            self.temp_save_filename = "ulc_commands.txt"
            if self.key == "AUTO":
                self.key = "49454D4B41455242214E4143554F5946"
            elif len(self.key) != 32:
                print("Error: Key must be 16 bytes for Ultralight C cards")
                return False
            return True
        elif "MIFARE Ultralight AES" in output:
            self.card_type = "ULAES"
            self.temp_save_filename = "ulaes_commands.txt"
            if self.key == "AUTO":
                self.key = "00" * 16
            elif len(self.key) != 32:
                print("Error: Key must be 16 bytes for Ultralight AES cards")
                return False
            return True
        print("Error: No Ultralight C/AES card detected on the Proxmark3.")
        return False

    def test_wakeup_commands(self) -> None:
        """Test commands in wakeup state"""
        print("Testing wakeup state commands...")

        # Test 1-byte commands without CRC
        ran = False
        for cmd in range(128):
            test_id = f"WAKEUP-1B-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            print(f"Testing {test_id}")
            result = self.pm3.console(f"hf 14a raw -a -b 7 {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

    def test_ready1_commands(self) -> None:
        """Test commands in READY1 state"""
        print("Testing READY1 state commands...")

        # Test 1-byte commands without CRC
        ran = False
        for cmd in range(256):
            test_id = f"READY1-1B-NOCRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            print(f"Testing {test_id}")
            self.pm3.console("hf 14a raw -ak -b 7 52")
            result = self.pm3.console(f"hf 14a raw {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 1-byte commands with CRC
        ran = False
        for cmd in range(256):
            test_id = f"READY1-1B-CRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            print(f"Testing {test_id}")
            self.pm3.console("hf 14a raw -ak -b 7 52")
            result = self.pm3.console(f"hf 14a raw -c {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 2-byte commands without CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"READY1-2B-NOCRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                print(f"Testing {test_id}")
                self.pm3.console("hf 14a raw -ak -b 7 52")
                result = self.pm3.console(f"hf 14a raw {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

        # Test 2-byte commands with CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"READY1-2B-CRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                print(f"Testing {test_id}")
                self.pm3.console("hf 14a raw -ak -b 7 52")
                result = self.pm3.console(f"hf 14a raw -c {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

    def test_active_commands(self) -> None:
        """Test commands in ACTIVE state"""
        print("Testing ACTIVE state commands...")

        # Test 1-byte commands without CRC
        ran = False
        for cmd in range(256):
            test_id = f"ACTIVE-1B-NOCRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            print(f"Testing {test_id}")
            result = self.pm3.console(f"hf 14a raw -s {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 1-byte commands with CRC
        ran = False
        for cmd in range(256):
            test_id = f"ACTIVE-1B-CRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            print(f"Testing {test_id}")
            result = self.pm3.console(f"hf 14a raw -sc {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 2-byte commands without CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"ACTIVE-2B-NOCRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                print(f"Testing {test_id}")
                result = self.pm3.console(f"hf 14a raw -s {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

        # Test 2-byte commands with CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"ACTIVE-2B-CRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                print(f"Testing {test_id}")
                result = self.pm3.console(f"hf 14a raw -sc {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

    def test_authenticated_commands(self) -> None:
        """Test commands in AUTHENTICATED state"""
        print("Testing AUTHENTICATED state commands...")

        # Test 1-byte commands without CRC
        ran = False
        for cmd in range(256):
            test_id = f"AUTH-1B-NOCRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            # First authenticate
            self.authenticate()
            # Then test command
            print(f"Testing {test_id}")
            result = self.pm3.console(f"hf 14a raw {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 1-byte commands with CRC
        ran = False
        for cmd in range(256):
            test_id = f"AUTH-1B-CRC-{cmd:02X}"
            if test_id in self.results:
                continue
            self.pm3.reset_field()
            # First authenticate
            self.authenticate()
            # Then test command
            print(f"Testing {test_id}")
            result = self.pm3.console(f"hf 14a raw -c {cmd:02X}")
            self.results[test_id] = result
            ran = True
        if ran:
            self.save_results()

        # Test 2-byte commands without CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"AUTH-2B-NOCRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                # First authenticate
                self.authenticate()
                # Then test command
                print(f"Testing {test_id}")
                result = self.pm3.console(f"hf 14a raw {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

        # Test 2-byte commands with CRC
        for cmd1 in range(256):
            ran = False
            for cmd2 in range(256):
                test_id = f"AUTH-2B-CRC-{cmd1:02X}-{cmd2:02X}"
                if test_id in self.results:
                    continue
                self.pm3.reset_field()
                # First authenticate
                self.authenticate()
                # Then test command
                print(f"Testing {test_id}")
                result = self.pm3.console(f"hf 14a raw -c {cmd1:02X}{cmd2:02X}")
                self.results[test_id] = result
                ran = True
            if ran:
                self.save_results()

    def save_results(self, filename=None):
        """Save results to a file"""
        if filename is None:
            filename = self.temp_save_filename
        with open(filename, "w+") as f:
            for test_id, result in sorted(self.results.items()):
                f.write(f"{test_id}: {base64.b64encode(bytes(result.encode())).decode()}\n")
        print(f"Results saved to {filename}")

    def run_all_tests(self):
        """Run all command tests"""
        self.test_wakeup_commands()
        self.test_ready1_commands()
        self.test_active_commands()
        self.test_authenticated_commands()


def main():
    """Main function"""
    OUT_TEMPLATE = "(ulc|ulaes)_commands.txt"
    parser = argparse.ArgumentParser(description='Enumerate Ultralight C/AES card commands')
    parser.add_argument('key', nargs='?', default="AUTO", help='Key for authenticated state (16 bytes in hex)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-o', '--output', default=OUT_TEMPLATE, help='Output file name')
    parser.add_argument('-c', '--cont', action='store_true',
                        help=f'Continue from last test, using existing {OUT_TEMPLATE}')
    args = parser.parse_args()

    # Validate key format
    if args.key != "AUTO":
        if not re.match(r'^[0-9A-Fa-f]{32}$', args.key):
            print("Error: Key must be 16bytes (32 hex characters)")
            sys.exit(1)
    enumerator = UltraLightEnumerator(args.key, args.debug)
    # First verify that an Ultralight C/AES card is present
    if not enumerator.verify_card_presence():
        sys.exit(1)
    if enumerator.card_type == "ULC":
        print(f"Starting Ultralight C command enumeration with key: {args.key}")
        if args.output == OUT_TEMPLATE:
            args.output = "ulc_commands.txt"
    elif enumerator.card_type == "ULAES":
        print(f"Starting Ultralight AES command enumeration with key: {args.key}")
        if args.output == OUT_TEMPLATE:
            args.output = "ulaes_commands.txt"
    if args.cont and os.path.exists(args.output):
        with open(args.output, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    test_id = parts[0]
                    result = base64.b64decode(parts[1]).decode()
                    enumerator.results[test_id] = result
    try:
        enumerator.run_all_tests()
    except Exception as e:
        print(f"Error during command enumeration: {e}")
        if args.debug:
            traceback.print_exc()
        sys.exit(1)
    enumerator.save_results(args.output)
    print("Command enumeration completed successfully")


if __name__ == '__main__':
    main()
