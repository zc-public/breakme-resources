
#!/bin/bash

# Proxmark3 client path
pm3=pm3

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
hws=(2 3)
blocks=(48 49 50 51 52 53 54 55)
rfu_blocks=(56 57 58 59)
patterns=(0xFF00FF00 0x00FF00FF 0xF0F0F0F0 0x0F0F0F0F 0xAAAAAAAA 0x55555555 0xA5A5A5A5 0x5A5A5A5A 0xC3C3C3C3 0x3C3C3C3C)

function recover_masked_key_bit {
    $pm3 -c "script run recover_masked_key_bits.py $*" --incognito
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

for hw in "${hws[@]}"; do
    for block in "${blocks[@]}"; do
        for pattern in "${patterns[@]}"; do
            recover_masked_key_bit --block $block --eeprom-init $pattern --bitflips $hw --mask 0x$mask --tear1 $tear1
        done
    done | tee recover_masked_key_bits_tests_${uid}_hw${hw}.log
done

# simulation with RFU
for hw in "${hws[@]}"; do
    for block in "${rfu_blocks[@]}"; do
        for pattern in "${patterns[@]}"; do
            recover_masked_key_bit --block $block --eeprom-init $pattern --bitflips $hw --mask 0x$mask --tear1 $tear1
        done
    done | tee recover_masked_key_bits_tests_${uid}_rfu_hw${hw}.log
done
