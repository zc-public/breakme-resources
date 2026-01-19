#!/usr/bin/env python3

import math


def estimate(n, m):
    """Estimate the number of candidates with HW <= m for a n-bit key.

    Args:
        n (int): Number of bits in the key.
        m (int): Maximum number of bits in the hardware candidates.
    Returns:
        float: Estimated number of candidates.
    """
    num = math.comb(n, 0)
    for i in range(1, m + 1):
        num += math.comb(n, i)
    return num


def print_estimate(desc, n, m, speed):
    e = estimate(n, m)
    if e > 10000:
        e_string = f"2**{math.log2(e):.2f}"
    else:
        e_string = f"{e:8}"
    if e/speed > 3600*24*365.25:
        t_string = f"{e/speed/3600/24/365.25:8.2f} years"
    elif e/speed > 3600*24:
        t_string = f"{e/speed/3600/24:8.2f} days ({e/speed/3600/100:8.2f} hours on 100 GPUs)"
    elif e/speed > 3600:
        t_string = f"{e/speed/3600:8.2f} hours"
    else:
        t_string = f"{e/speed:8.2f} seconds"
    print(f"{desc:6s} estimate({n:3}, {m:3}): {e_string:>9} in {t_string}")


# Time estimation to cover the entire keyspace
speed = 137  # keys/second
print(f"At {speed} keys/s (theoretical limit)")
for desc, n, m in [('ULC', 28, 2), ('ULC', 28, 3), ('ULC', 28, 4),
                   ('ULC', 112, 2), ('ULC', 112, 3)]:
    print_estimate(desc, n, m, speed)

speed = 100  # keys/second
print(f"At {speed} keys/s (practical bruteforce on Proxmark3)")
for desc, n, m in [('ULC', 28, 2), ('ULC', 28, 3), ('ULC', 28, 4),
                   ('ULC', 112, 2), ('ULC', 112, 3)]:
    print_estimate(desc, n, m, speed)

speed = 86  # keys/second
print(f"At {speed:3} keys/s (practical bruteforce with tearing on Proxmark3)")
for desc, n, m in [('ULC', 28, 2), ('ULC', 28, 3), ('ULC', 28, 4),
                   ('ULC', 112, 2), ('ULC', 112, 3)]:
    print_estimate(desc, n, m, speed)

speed = 100  # keys/second
print(f"At {speed:3} keys/s (theoretical limit)")
for desc, n, m in [('ULAES', 32, 2), ('ULAES', 32, 3),
                   ('ULAES', 128, 2), ('ULAES', 128, 3)]:
    print_estimate(desc, n, m, speed)

speed = 88  # keys/second
print(f"At {speed} keys/s (practical bruteforce on Proxmark3)")
for desc, n, m in [('ULAES', 32, 2), ('ULAES', 32, 3), ('ULAES', 32, 4),
                   ('ULAES', 128, 2), ('ULAES', 128, 3)]:
    print_estimate(desc, n, m, speed)

speed = 81  # keys/second
print(f"At {speed:3} keys/s (practical bruteforce with tearing on Proxmark3)")
for desc, n, m in [('ULAES', 32, 2), ('ULAES', 32, 3), ('ULAES', 32, 4), ('ULAES', 32, 6),
                   ('ULAES', 128, 2), ('ULAES', 128, 3),
                   ('ULAES', 27, 3), ('ULAES', 27, 4), ('ULAES', 43, 5), ('ULAES', 53, 6), ('ULAES', 59, 7)]:
    print_estimate(desc, n, m, speed)

speed = 10*10**9  # keys/second
print(f"At {speed:3} keys/s (offline bruteforce of reader nonce on GPU)")
# regular tearing recovery
recovered_bits_per_segment_opposite_mask = 6
print(f"Assuming {recovered_bits_per_segment_opposite_mask} bits already recovered per segment")
print_estimate('ULAES', 128-recovered_bits_per_segment_opposite_mask*4,
               64-recovered_bits_per_segment_opposite_mask*4, speed)
recovered_bits_per_segment_opposite_mask = 8
print(f"Assuming {recovered_bits_per_segment_opposite_mask} bits already recovered per segment")
print_estimate('ULAES', 128-recovered_bits_per_segment_opposite_mask*4,
               64-recovered_bits_per_segment_opposite_mask*4, speed)
recovered_bits_per_segment_opposite_mask = 12
print(f"Assuming {recovered_bits_per_segment_opposite_mask} bits already recovered per segment")
print_estimate('ULAES', 128-recovered_bits_per_segment_opposite_mask*4,
               64-recovered_bits_per_segment_opposite_mask*4, speed)

# regular tearing recovery
recovered_bits_per_segment_opposite_mask = 6
# extra recovery
recovered_bits_per_segment_equal_mask = 6
print(f"Assuming {recovered_bits_per_segment_opposite_mask}+{recovered_bits_per_segment_equal_mask} "
      "bits already recovered")
print_estimate('ULAES', 128-recovered_bits_per_segment_equal_mask*4-recovered_bits_per_segment_opposite_mask*4,
               64-recovered_bits_per_segment_opposite_mask*4-recovered_bits_per_segment_equal_mask*4, speed)
