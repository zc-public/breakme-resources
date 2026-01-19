#!/usr/bin/env python3

import json
import random


def expand_challenges(dict_chal):
    list_chals = []
    for key in dict_chal:
        list_chals.extend([key] * dict_chal[key])
    random.shuffle(list_chals)
    return list_chals


def compress_challenges(list_chals):
    dict_chal = {}
    for chal in list_chals:
        if chal in dict_chal:
            dict_chal[chal] += 1
        else:
            dict_chal[chal] = 1
    return dict_chal


def resample_challenges(collected_data, n, n0=None):
    if n0 is None:
        n0 = n
    challenges_0 = collected_data["challenges_0_sorted"]
    challenges_25 = collected_data["challenges_25_sorted"]
    challenges_50 = collected_data["challenges_50_sorted"]
    challenges_75 = collected_data["challenges_75_sorted"]
    challenges_100 = collected_data["challenges_100_sorted"]
    challenges_0 = compress_challenges(expand_challenges(challenges_0)[:n0])
    challenges_25 = compress_challenges(expand_challenges(challenges_25)[:n])
    challenges_50 = compress_challenges(expand_challenges(challenges_50)[:n])
    challenges_75 = compress_challenges(expand_challenges(challenges_75)[:n])
    challenges_100 = compress_challenges(expand_challenges(challenges_100)[:n])

    challenges_0_sorted_desc = dict(sorted(challenges_0.items(), key=lambda item: item[1], reverse=True))
    challenges_25_sorted_desc = dict(sorted(challenges_25.items(), key=lambda item: item[1], reverse=True))
    challenges_50_sorted_desc = dict(sorted(challenges_50.items(), key=lambda item: item[1], reverse=True))
    challenges_75_sorted_desc = dict(sorted(challenges_75.items(), key=lambda item: item[1], reverse=True))
    challenges_100_sorted_desc = dict(sorted(challenges_100.items(), key=lambda item: item[1], reverse=True))
    results = {"challenges_100_sorted": challenges_100_sorted_desc,
               "challenges_75_sorted": challenges_75_sorted_desc,
               "challenges_50_sorted": challenges_50_sorted_desc,
               "challenges_25_sorted": challenges_25_sorted_desc,
               "challenges_0_sorted": challenges_0_sorted_desc}
    return results


with open('challenges_1000_default_key.json') as f:
    collected_data = json.load(f)

for n in [50, 100, 250, 500, 750]:
    results = resample_challenges(collected_data, n)
    with open(f'challenges_{n}_default_key.json', 'w') as f:
        json.dump(results, f)

for n in [20, 30, 40]:
    n0 = 200
    results = resample_challenges(collected_data, n, n0)
    with open(f'challenges_{n}_{n0}_default_key.json', 'w') as f:
        json.dump(results, f)
