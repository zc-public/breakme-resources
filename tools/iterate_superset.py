#!/usr/bin/env python3

def print_binary(number, width=32):
    print(f"{number:0{width}b}")


def iterate_supersets(base_mask):
    zero_positions = ~base_mask & 0xFFFFFFFF
    subset = 0
    while True:
        print_binary(base_mask | subset)
        if subset == zero_positions:
            break
        subset = (subset - zero_positions) & zero_positions


# Example usage:
iterate_supersets(0xFF00FF00)
