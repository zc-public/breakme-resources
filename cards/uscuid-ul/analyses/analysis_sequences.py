#!/usr/bin/env python3

import sys
import json

STOP = False
SHOW_STATES = True
SHOW_STATES_BITS = False

def print_state(chal):
    if SHOW_STATES:
        print(f"{chal}{'.' * (16 - len(chal))}")
    elif SHOW_STATES_BITS:
        print(f"{int(chal[:4], 16):016b}")
    else:
        print(int(chal[:4], 16) & 1, end="")


with open(sys.argv[1]) as f:
    data = json.load(f)

chals = set(data["challenges_0_sorted"].keys())
print(f"Total challenges: {len(chals)}")

# Random start:
# chal0 = chals.pop()
# Longest chain:
chal0 = '6015248150013332'
chals.remove(chal0)
# how many bytes to offset challenges to find a match? 1..4
overlap = 1

if SHOW_STATES:
    print(f"{chal0}")
else:
    print(int(chal0[:4], 16) & 1, end="")
n = 0
intermediate_chals = []
while len(chals) > 0:
    for chal in chals:
        if chal.startswith(chal0[overlap:]):
            for c in intermediate_chals:
                print_state(c)
            intermediate_chals = []
            chal0 = chal
            chals.remove(chal)
            n += 1
            print_state(chal0)
            break
    else:
        chal0 = chal0[overlap:]
        intermediate_chals.append(chal0)
        if len(chal0) == 4:
            if (STOP):
                break
            else:
                if n > 0:
                    print(f"Sequence length: {n}")
                    if SHOW_STATES:
                        print("================")
                    else:
                        print("\n================")
                chal0 = chals.pop()
                n = 0
                intermediate_chals = [chal0]
