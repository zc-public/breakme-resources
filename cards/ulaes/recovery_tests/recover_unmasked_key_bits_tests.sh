
#!/bin/bash

# Beware, long tests! Pick what you need...
# Proxmark3 client path
pm3=pm3


# Once the 6-7 bits extracted, I redo a "mask recovery" starting from opposite of mask and at every tear I BF which bit(s) flipped, from the anti-mask to the mask.
# => this gives the order in which bits flipped
# => any bit that flipped later than the 6-7 recovered bits can then be assumed to be 0 (so key bit = mask bit)

declare -A uid_mask_table=(
    # build key from segment key masks from blocks 33/32/31/30
    ["043C67C2451390"]="23FCA2EAE700ACF0B3970A790EBD95A0"
    ["04D863C2451390"]="DE8E111E711C960021E74CE901026D56"
    ["04619CC2451390"]="B98F1C52C75A5C41925E662F220742C6"
    ["04772FC2451390"]="A2B17ECEDB7E8152E496842DF1FE673F"
    ["04AF34C2451390"]="257EF5382D670AA02E6EE48C13C54C07"
    ["048E69C2451390"]="71C7BCCEC24EE4EE0EE6F7DCA2FC7762"
    ["043667C2451390"]="5854E2220BE53D4A2504CB04561F4608"
    ["04B266C2451390"]="D9B1B7A4471142D680DD72945A65AB42"
    ["04A234C2451390"]="419F3C9AED52F7D2ECCFD9C69266EEDF"
    ["0494A2C2451390"]="D6E2504F710466D74B15E8B4B86E40A9"
    ["04DA69C2451390"]="A7E604D82BBAA2AEB6D46BBBA388699B"
    ["04329CC2451390"]="7D15EE6B6A5BB147230F2E4410AEBA9E"
    ["04629CC2451390"]="5D2454B19AAE64EA1FF836DF2C4FECCD"
)
tear1=285
blocks=(48 49 50 51 52 53 54 55)

function recover_unmasked_key_bit {
    $pm3 -c "script run recover_unmasked_key_bits.py $*" --incognito
}

uid=$($pm3 -c "hf 14a read" | grep "UID:" | awk '{print $3$4$5$6$7$8$9}')

if [[ -z "$uid" ]]; then
    echo "Error: tag not found." >&2
    exit 1
fi
if [[ -z "${uid_mask_table[$uid]}" ]]; then
    echo "Error: UID $uid not found in mask table." >&2
    exit 1
fi

mask="${uid_mask_table[$uid]}"
hd=2
antimask=$(printf "%032X" $((~0x$mask & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)))

# From recover_masked_key_bits_tests_04772FC2451390_b48_0x00FF00FF_hw2_with_heat_20251020_182329.log
block=48
# OR of all "Masked key bits found"
masked_key_bits=0xB0000200
eeprom_init=0x00FF00FF
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b48_0xFF00FF00_hw2_with_heat_20251020_180800.log
block=48
# OR of all "Masked key bits found"
masked_key_bits=0x002800c5
eeprom_init=0xFF00FF00
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b49_0x00FF00FF_hw2_with_heat_20251020_184916.log
block=49
# OR of all "Masked key bits found"
masked_key_bits=0x00001B00
eeprom_init=0x00FF00FF
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b49_0xFF00FF00_hw2_with_heat_20251020_183819.log
block=49
# OR of all "Masked key bits found"
masked_key_bits=0x001C0021
eeprom_init=0xFF00FF00
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b50_0x00FF00FF_hw2_with_heat_20251020_191113.log
block=50
# OR of all "Masked key bits found"
masked_key_bits=0x28006A00
eeprom_init=0x00FF00FF
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b50_0xFF00FF00_hw2_with_heat_20251020_190300.log
block=50
# OR of all "Masked key bits found"
masked_key_bits=0x008100C7
eeprom_init=0xFF00FF00
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b51_0x00FF00FF_hw2_with_heat_20251020_192846.log
block=51
# OR of all "Masked key bits found"
masked_key_bits=0x8B008500
eeprom_init=0x00FF00FF
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log

# From recover_masked_key_bits_tests_04772FC2451390_b51_0xFF00FF00_hw2_with_heat_20251020_192235.log
block=51
# OR of all "Masked key bits found"
masked_key_bits=0x008F0045
eeprom_init=0xFF00FF00
pattern=${antimask:((block-48)*8):8}
recover_unmasked_key_bit --block $block --max_hd_diff $hd --mask 0x$mask --tear1 $tear1 --masked_key_bits $masked_key_bits --eeprom_init $eeprom_init | tee recover_unmasked_key_bits_tests_${uid}_b${block}_${eeprom_init}_hd${hd}.log
