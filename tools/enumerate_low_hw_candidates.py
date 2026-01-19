#!/usr/bin/env python3

from itertools import combinations


def enumerate_words_with_k_bits_set(n_bits, max_bits_set, mask=0):
    """Generate all n-bit words with up to max_bits_set bits set, respecting a mask."""
    non_masked_positions = [pos for pos in range(n_bits) if not (mask & (1 << pos))]
    yield 0
    for k in range(1, max_bits_set + 1):
        # print(f"Enumerating words with {k} bits set: {len(list(combinations(non_masked_positions, k)))}")
        for bits in combinations(non_masked_positions, k):
            value = 0
            for pos in bits:
                value |= (1 << pos)
            yield value


if __name__ == '__main__':
    # Print all 32-bit words with HW<=3 for ULC = masking lsb
    for word in enumerate_words_with_k_bits_set(32, 3, 0x01010101):
        print(f"{word:032b}")
        # print(f"{word:08x}")
        # print(f"hf mfu cauth --key 000000000000000000000000{word:08x}")
    # => 3683

    # Print all 32-bit words with HW<=2 for ULC = masking lsb
    # for word in enumerate_words_with_k_bits_set(32, 2, 0x01010101):
        # print(f"{word:032b}")
    # => 407

    # ULC HW3 all segments at once
    # for word in enumerate_words_with_k_bits_set(128, 3, 0x01010101010101010101010101010101):
        # print(f"{word:0128b}")
    # => 234249

    # ULC HW2 all segments at once
    # for word in enumerate_words_with_k_bits_set(128, 2, 0x01010101010101010101010101010101):
        # print(f"{word:0128b}")
    # => 6329

    # When comparing with iterate_superset, need to set masked bits:
    # for word in enumerate_words_with_k_bits_set(32, 16, 0xFF00FF00):
        # print(f"{word|0xFF00FF00:032b}")
        # print(f"{word:08x}")
    # Then sort outputs of enumerate_low_hw_candidates.py and iterate_superset and diff => same

    # Print all 32-bit words with HW<=3 for ULAES
    # for word in enumerate_words_with_k_bits_set(32, 3):
        # print(f"{word:032b}")
        # ulaes_segment_hw3.dic:
        # print(f"{word:08x}")
        # print(f"hf mfu aesauth --key 000000000000000000000000{word:08x}")
    # => 5489

    # Print all 32-bit words with HW<=2 for ULAES
    # for word in enumerate_words_with_k_bits_set(32, 2):
        # ulaes_segment_hw2.dic:
        # print(f"{word:08x}")
    # => 529

    # ULAES HW3 all segments at once
    # for word in enumerate_words_with_k_bits_set(128, 3):
        # print(f"{word:0128b}")
    # => 349633

    # ULAES HW2 all segments at once
    # for word in enumerate_words_with_k_bits_set(128, 2):
        # print(f"{word:0128b}")
    # => 8257
