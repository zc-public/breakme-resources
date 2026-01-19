#!/bin/bash

# Proxmark3 client path
pm3=pm3

tear1=400
hws=(2 3)
blocks=(44 45 46 47)
patterns=(0xFF00FF00 0x00FF00FF 0xF0F0F0F0 0x0F0F0F0F 0xAAAAAAAA 0x55555555 0xA5A5A5A5 0x5A5A5A5A 0xC3C3C3C3 0x3C3C3C3C)

function recover_key_bit {
    $pm3 -c "script run recover_key_bits.py $*" --incognito
}

uid=$(pm3 -c "hf 14a read" | grep "UID:" | awk '{print $3$4$5$6$7$8$9}')

if [[ -z "$uid" ]]; then
    echo "Error: tag not found." >&2
    exit 1
fi

for hw in "${hws[@]}"; do
    for block in "${blocks[@]}"; do
        for pattern in "${patterns[@]}"; do
            recover_key_bit --block $block --eeprom-init $pattern --bitflips $hw --tear1 $tear1
        done
    done | tee recover_key_bits_tests_${uid}_hw${hw}.log
done
exit 0

blocks=(8 9 10 11)
for hw in "${hws[@]}"; do
    for block in "${blocks[@]}"; do
        for pattern in "${patterns[@]}"; do
            recover_key_bit --block $block --eeprom-init $pattern --bitflips $hw --tear1 $tear1
        done
    done | tee recover_key_bits_tests_${uid}_rfu_hw${hw}.log
done
