#!/bin/bash

# Proxmark3 client path
pm3=pm3

uid=$($pm3 -c "hf 14a read" | grep "UID:" | awk '{print $3$4$5$6$7$8$9}')

if [[ -z "$uid" ]]; then
    echo "Error: tag not found." >&2
    exit 1
fi

for b in 48 49 50 51; do
    bx=$(printf "%02X" $b)
    if [[ ! -f "recover_mask_${uid}_block${bx}_fast.log" ]]; then
        while ! grep -q probably recover_mask_${uid}_block${bx}_fast.log; do
            $pm3 -c "script run mfulaes_mask_recovery.py  --block ${b}" --incognito | tee recover_mask_${uid}_block${bx}_fast.log
        done
    fi
done

M1=$(grep probably recover_mask_${uid}_block33_fast.log| sed 's/[^:]*: //;s/ .*//')
M2=$(grep probably recover_mask_${uid}_block32_fast.log| sed 's/[^:]*: //;s/ .*//')
M3=$(grep probably recover_mask_${uid}_block31_fast.log| sed 's/[^:]*: //;s/ .*//')
M4=$(grep probably recover_mask_${uid}_block30_fast.log| sed 's/[^:]*: //;s/ .*//')
echo "[\"${uid}\"]=\"$M1$M2$M3$M4\""
