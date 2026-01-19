#!/usr/bin/env python3

import json
import random
import sys
from functools import lru_cache


def expand_challenges(dict_chal):
    list_chals = []
    for key in dict_chal:
        list_chals.extend([key] * dict_chal[key])
    return list_chals


if len(sys.argv) != 2:
    print("Usage: analysis_duplicates.py <input_file>")
    sys.exit(1)

input_file = sys.argv[1]

with open(input_file) as f:
    collected_data = json.load(f)

chals = expand_challenges(collected_data["challenges_0_sorted"])


@lru_cache(maxsize=None)
def analyze_duplicates(n, chals_tuple, ntests=10000):
    chals = list(chals_tuple)  # Convert tuple back to list
    dups = 0
    max_counts = []
    for _ in range(ntests):
        sample = random.sample(chals, n)
        has_duplicate = len(sample) != len(set(sample))
        max_count = max(sample.count(x) for x in set(sample))
        if has_duplicate:
            dups += 1
        max_counts.append(max_count)
    prob = dups / ntests
    avg_max_count = sum(max_counts) / ntests
    return prob, avg_max_count


def target_probability(chals, target_prob=0.5, ntests=1000, init_max=200):
    """Calculate the number of samples needed to reach a target probability of at least one duplicate."""
    old_min = 0
    old_max = min(len(chals), init_max)
    prob, _ = analyze_duplicates(old_max, tuple(chals), ntests)
    if prob < target_prob:
        print(f"Initial max {init_max} too low (prob={prob:.4f}), you need to increase it...")
        exit(1)

    n = (old_min + old_max) // 2
    while n != old_min and n != old_max:
        prob, _ = analyze_duplicates(n, tuple(chals), ntests)
        print(f"n={n}, prob={prob:.4f}, target={target_prob}, old_min={old_min}, old_max={old_max}")
        if prob >= target_prob:
            old_max = n
            n = (old_min + old_max) // 2
        else:
            old_min = n
            n = (old_min + old_max) // 2
    return n + 1


def target_maxcount(chals, target_max=3, ntests=1000, init_max=200):
    """Calculate the number of samples needed to reach a target probability of at least one duplicate."""
    old_min = 0
    old_max = min(len(chals), init_max)
    _, avg_max_count = analyze_duplicates(old_max, tuple(chals), ntests)
    if avg_max_count < target_max:
        print(f"Initial max {init_max} too low (avg_max_count={avg_max_count:.4f}), you need to increase it...")
        exit(1)

    n = (old_min + old_max) // 2
    while n != old_min and n != old_max:
        _, avg_max_count = analyze_duplicates(n, tuple(chals), ntests)
        print(f"n={n}, avg_max_count={avg_max_count:.4f}, target={target_max}, old_min={old_min}, old_max={old_max}")
        if avg_max_count >= target_max:
            old_max = n
            n = (old_min + old_max) // 2
        else:
            old_min = n
            n = (old_min + old_max) // 2
    return n + 1


ntests = 10000
print("\nCalculating samples needed for 50% probability of at least one duplicate:")
samples_needed = target_probability(chals, 0.5, ntests=ntests)
print(f"Samples needed: {samples_needed}")
print("\nCalculating samples needed for 99.99% probability of at least one duplicate:")
samples_needed = target_probability(chals, 0.9999, ntests=ntests)
print(f"Samples needed: {samples_needed}")
print("\nCalculating samples needed for average max count of duplicates = 3")
samples_needed = target_maxcount(chals, 3, ntests=ntests)
print(f"Samples needed: {samples_needed}")
