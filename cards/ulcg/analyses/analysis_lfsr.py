#!/usr/bin/env python3

# Produce same sequence as lfsr.py starting from D5226A91B549DAA4

def next_fibonacci_state_optimized(x):
    x = x << 15 | (x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)
    x &= 0xffff
    return x


def next_fibonacci_state_detailed(x):
    # ROTR 1
    x = (x << 15 | x >> 1) & 0xffff
    # LFSR MFC
    x = (x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15) & 0xffff
    # ROL 1
    x = (x << 1 | x >> 15) & 0xffff
    return x


x = 0xD522
chal = ""
chals_detailed = []
for i in range(4):
    chal += f"{x:04X}"
    x = next_fibonacci_state_detailed(x)

for i in range(1000):
    chals_detailed.append(chal)
    chal = chal[4:] + f"{x:04X}"
    x = next_fibonacci_state_detailed(x)

x = 0xD522
chal = ""
chals_optimized = []
for i in range(4):
    chal += f"{x:04X}"
    x = next_fibonacci_state_optimized(x)

for i in range(1000):
    chals_optimized.append(chal)
    chal = chal[4:] + f"{x:04X}"
    x = next_fibonacci_state_optimized(x)

assert chals_detailed == chals_optimized
for chal in chals_optimized:
    print(chal)
