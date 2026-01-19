#!/bin/bash

# Proxmark3 client path
pm3=pm3

tear1=380
tear2=240
retries=0
hw=2
k1=0x42524541
k2=0x4B4D4549
k3=0x46594F55
k4=0x43414E21

function recover_key_bit {
    $pm3 -c "script run recover_key_bits.py $*" --incognito
}

uid=$(pm3 -c "hf 14a read" | grep "UID:" | awk '{print $3$4$5$6$7$8$9}')

if [[ -z "$uid" ]]; then
    echo "Error: tag not found." >&2
    exit 1
fi
(
    recover_key_bit --block 44 --eeprom-init $k1 --bitflips $hw --tear1 $tear1 --tear2 $tear2 --retries $retries
    recover_key_bit --block 45 --eeprom-init $k2 --bitflips $hw --tear1 $tear1 --tear2 $tear2 --retries $retries
    recover_key_bit --block 46 --eeprom-init $k3 --bitflips $hw --tear1 $tear1 --tear2 $tear2 --retries $retries
    recover_key_bit --block 47 --eeprom-init $k4 --bitflips $hw --tear1 $tear1 --tear2 $tear2 --retries $retries
) | tee recover_key_bits_tests_fast_${uid}_hw${hw}.log
