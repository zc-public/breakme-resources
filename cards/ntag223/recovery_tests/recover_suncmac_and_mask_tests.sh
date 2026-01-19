#!/bin/bash

# Proxmark3 client path
PM3=pm3

UID=$($PM3 -c "hf 14a read" | grep "UID:" | awk '{print $3$4$5$6$7$8$9}')

if [[ -z "$UID" ]]; then
    echo "Error: tag not found." >&2
    exit 1
fi

$PM3 -c "script run ntag22x_suncmac_recovery --format --initkey 0x2b7e151628aed2a6abf7158809cf4f3c --json recover_suncmac_and_mask_${UID}_mac_data.json" --incognito | tee recover_suncmac_and_mask_${UID}.log
