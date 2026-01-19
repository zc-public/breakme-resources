# Conducting realistic recovery over 12 NXP ULC tags sharing the same default key.

```
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -m 1 42524541
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -A1 42524541|grep Rec
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -nm1 4B4D4549
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -A1 4B4D4549|grep Rec
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -m 1 46594F55
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -A1 46594F55|grep Rec
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -m 1 43414E21
grep -B1 Recovered recover_key_bits_tests_fast_combined_hw2.log|grep -A1 43414E21|grep Rec
```
Merging recovered bits...
```
     EEPROM bits init:   42524541 (01000010010100100100010101000001)
 Recovered block bits:             .1....1-.1.1...-.1...1.-.1.....-
   Missing block bits:             .......-......1-.......-.......-
     EEPROM bits init:   4B4D4549 (01001011010011010100010101001001)
 Recovered block bits:             .1..1.1-.1..11.-.1...1.-....1..-
   Missing block bits:             .......-.......-.......-.1.....-
     EEPROM bits init:   46594F55 (01000110010110010100111101010101)
 Recovered block bits:             .1...11-.1.11..-.1..111-.......-
   Missing block bits:             .......-.......-.......-.1.1.1.-
     EEPROM bits init:   43414E21 (01000011010000010100111000100001)
 Recovered block bits:             .1....1-.1.....-.1..111-..1....-
   Missing block bits:             .......-.......-.......-.......-
```

=> after 12 cards, we recovered 34 bits of the key, we're missing 5 bits.

Note that we're reusing the same 12 cards for each segment.
In reality this would require 48 different cards.

Key BREAKMEIFYOUCAN! has a quite low HW, not statistically representative...


Total time:
```
grep Time recover_key_bits_tests_fast_combined_hw2.log |grep -o "  ."| paste -sd+ - | bc -l
25
grep Time recover_key_bits_tests_fast_combined_hw2.log |grep -o "[0-9]\+\.[0-9]\+"| paste -sd+ - | bc -l
1152.75
```
25*60 + 1152.75 = 2652.75 = 44 min 12 seconds

Brute-force speed        : 85.96 auths/s

Auths: 228028 = 2**17.7

Tears: 345 = 2**8.43

=> params for the table:

* "kps_tear": 86
* "auths_tear_factor": 1.9
* "segment_ntears_hw": {1.52: 7.19}
* "tear_bf_retries": 0
