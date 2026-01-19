#!/usr/bin/env python3

# Target ASCII values: 'B', 'R', 'D', '@'
target = "@DRB"

# Convert each character to its ASCII value, then reverse the shift operation
b3 = (ord(target[0]) >> 1) & 0x7F  # 'B' -> 0x42 -> 0x21
b2 = (ord(target[1]) >> 1) & 0x7F  # 'R' -> 0x52 -> 0x29
b1 = (ord(target[2]) >> 1) & 0x7F  # 'D' -> 0x44 -> 0x22
b0 = (ord(target[3]) >> 1) & 0x7F  # '@' -> 0x40 -> 0x20

# Combine the 7-bit chunks into the 32-bit index
current_key_index = (b3 << 21) | (b2 << 14) | (b1 << 7) | b0

print(f"The current_key_index is: {current_key_index}")
