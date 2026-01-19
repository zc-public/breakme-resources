#!/bin/bash

# Proxmark3 client path
PM3=pm3

# C0 is READ_CONFIG, C1 is WRITE_CONFIG
#$PM3 --incognito -c 'hf 15 raw -a -k -c -d 22C0040D78EB00180104E0BBNN'
# Where BB is block and NN is the number of consecutive pages to read
#$PM3 --incognito -c 'hf 15 raw -a -k -c -d 00c0041003'

block=$1
pagedata=$2

# Original value of 0x10, 0x12, and 0x14: 07 81 00 00 rfu NFC_KHx rfu rfu
#IFS=$'\n'; for i in `seq 600 800`; do
IFS=$'\n'; for i in `seq $3 2000`; do
  echo "--- Tearing off write of ${pagedata} to config block ${block} at ${i}us --"
  $PM3 --incognito -c 'hf 15 raw -a -k -c -d 260100' 2>&1 > /dev/null;
  $PM3 --incognito -c "hw tearoff --delay ${i}; msleep -t 100; hw tearoff --on; hf 15 raw -a -k -c -d 00c104${block}${pagedata}" 2>&1 > /dev/null;
  echo "Memory contents of block ${block}:"
  $PM3 --incognito -c "hf 15 raw -a -k -c -d 00c004${block}01" 2>&1 | grep ')' | cut -d ')' -f2 | sed 's/^.\{4\}//' | grep -oE '^.{11}';
done

# WRITE CONFIG format
# Flags 8 bits | WRITE_CONFIG 8 bits | Manuf. code 8 bits | UID 64 bits (optional) | Block address 8 bits | Data 32 bits | CRC16 16 bits
#$PM3 --incognito -c 'hf 15 raw -a -k -c -d  22C1040D78EB00180104E0BBDDDDDDDD'
