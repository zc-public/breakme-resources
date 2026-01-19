#!/usr/bin/env python3

import sys

# From Proxmark3 code


def ul_print_nxp_silicon_info(card_uid):
    if card_uid[0] != 0x04:
        return "UID manuf is not NXP"

    uid = card_uid[:7]

    waferCoordX = ((uid[6] & 3) << 8) | uid[1]
    waferCoordY = ((uid[6] & 12) << 6) | uid[2]
    waferCounter = (
        (uid[4] << 5) |
        ((uid[6] & 0xF0) << 17) |
        (uid[5] << 13) |
        (uid[3] >> 3)
    )
    testSite = uid[3] & 7

    print("--- Tag Silicon Information")
    print(f"       Wafer Counter: {waferCounter} ( 0x{waferCounter:02X} )")
    print(f"   Wafer Coordinates: x {waferCoordX}, y {waferCoordY} (0x{waferCoordX:02X}, 0x{waferCoordY:02X})")
    print(f"           Test Site: {testSite}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <card_uid>")
        sys.exit(1)

    card_uid = bytes.fromhex(sys.argv[1])
    ul_print_nxp_silicon_info(card_uid)
