#!/usr/bin/env python3

from enumerate_low_hw_candidates import enumerate_words_with_k_bits_set

for hw in [1, 2, 3]:
    with open(f"mfulc_segment_hw{hw}.dic", "w") as f:
        for word in enumerate_words_with_k_bits_set(32, hw, 0x01010101):
            f.write(f"{word:08x}\n")
    with open(f"mfulaes_segment_hw{hw}.dic", "w") as f:
        for word in enumerate_words_with_k_bits_set(32, hw):
            f.write(f"{word:08x}\n")
for hw in [1, 2]:
    with open(f"mfulc_hw{hw}.dic", "w") as f:
        for word in enumerate_words_with_k_bits_set(128, hw, 0x01010101010101010101010101010101):
            f.write(f"{word:032x}\n")
    with open(f"mfulaes_hw{hw}.dic", "w") as f:
        for word in enumerate_words_with_k_bits_set(128, hw):
            f.write(f"{word:032x}\n")
