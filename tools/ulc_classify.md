# ulc_classify.py

Classifies a MIFARE Ultralight C fingerprint capture as genuine NXP or a known
counterfeit (Giantec GT23SC4489 / ULCG, Feiju FJ8010, USCUID-UL) and prints the
evidence behind the verdict. It turns the fingerprint data in this repo into a
decision, closing the `TODO: fingerprint in the table` note in
`cards/ulc/analyses/fingerprinting.txt`.

## The point: timing alone catches only half the counterfeits

| Card | FDT AF (bad key) | Caught by timing? | What catches it |
|------|------------------|-------------------|-----------------|
| Genuine NXP ULC | ~842 us | n/a | broad command map, TRNG nonces |
| Giantec GT23SC4489 | ~78 us | yes | FDT (LFSR bails ~10x early) |
| USCUID-UL v1 | ~3645 us | yes | FDT (several times slow) |
| Feiju FJ8010 | ~843 us | no, looks genuine | command map (ACKs only 0xA0) |
| USCUID-UL v2 | ~842 us | no, looks genuine | command map / PRNG nonce test |

So the classifier runs the checks in order and falls through: FDT bucket, then
the command-response map (genuine NXP ACKs ~200 commands to `XX00`, ULCG and
FJ8010 ACK a tiny set; USCUID has a `0x50-0x5F` gap), then the PRNG nonce test.

## Usage

```
python3 tools/ulc_classify.py capture.txt            # verdict + evidence
python3 tools/ulc_classify.py capture.txt --json
python3 tools/ulc_classify.py --nonces nonces.txt    # PRNG collision test
```

A capture is the output of `cards/ulc/analyses/fingerprint_ulc.py` (or any
capture carrying the same `FDT to ...`, `Cmd **00=00: ...`, `Cmd 1a00: ...`
lines).

### `--nonces`

The Giantec/USCUID RndB is a 16-bit LFSR (poly `x^16 + x^14 + x^13 + x^11 + 1`,
the MIFARE Classic LFSR, state stored rotated left one bit) seeded by wakeup
timing, which concentrates the observed pool to ~2^6.5 (about 95 values), so
RndB repeats within ~12 captures. A genuine NXP TRNG draws from 2^64, where a
single duplicate across any realistic batch is statistically impossible, so one
collision is proof of a counterfeit. Feed `--nonces` a batch of `1A00`
responses (one per line, or a capture's `Cmd 1a00:` lines).

## Tests

`tools/test_ulc_classify.py` validates against the in-repo reference captures
(`cards/*/analyses/fingerprint_ulc_*.txt`), so the classifier is pinned to the
paper's ground truth:

```
python3 -m pytest tools/test_ulc_classify.py -q
```
