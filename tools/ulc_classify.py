#!/usr/bin/env python3
"""Classify a MIFARE Ultralight C card as genuine NXP or a known counterfeit.

Input is the text output of the BREAKMEIFYOUCAN fingerprint_ulc.py probe (or a
compatible capture): frame-delay timings (FDT), the command-response map, short
frames, and the ATS. This tool turns that raw capture into a verdict with the
evidence behind it.

The ordering of the checks matters and is the point of the tool. Timing (FDT)
is cheap and flags two of the four counterfeits loudly, but FJ8010 and one
USCUID-UL variant answer with genuine-looking timing, so a timing-only check
passes them as real. The command-response map catches those: a genuine NXP ULC
ACKs almost the whole command range, while FJ8010 and ULCG ACK almost nothing.
The weak-PRNG tell (repeated or wrong-CRC-but-valid RndB) is the last layer and
is the only one that needs a nonce capture.

Reference signatures and the fixture captures are derived from the paper
"BREAKMEIFYOUCAN!" (eprint.iacr.org/2026/100) and its resource repository
(github.com/zc-public/breakme-resources, GPLv3). See README for attribution.
"""

from __future__ import annotations

import argparse
import logging
import math
import re
import sys
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("ulc-classify")

# Proxmark3 reports FDT in carrier ticks; one tick is 1/13.56 microseconds.
TICKS_PER_US = 13.56

# FDT bucket centres (ticks) with tolerance, taken from the reference captures.
# The discriminating value is the AF response to a *bad* key: genuine silicon
# runs the full 2TDEA round (~11.4k ticks, ~842 us) before the NAK, the Giantec
# LFSR part bails out an order of magnitude sooner, and the USCUID-UL part is
# several times slower.
FDT_AF_BAD_NXP = 11420       # ~842 us, genuine-looking
FDT_AF_BAD_ULCG = 1052       # ~78 us, Giantec GT23SC4489
FDT_AF_BAD_USCUID = 49436    # ~3645 us, USCUID-UL variant 1
FDT_TOL = 400                # ticks; buckets are far apart, a wide tol is safe


class Verdict(Enum):
    GENUINE = "genuine NXP MIFARE Ultralight C"
    ULCG = "counterfeit: Giantec GT23SC4489 (ULCG)"
    FJ8010 = "counterfeit: Feiju FJ8010"
    USCUID = "counterfeit: USCUID-UL"
    SUSPECT = "suspect: counterfeit indicators, family not pinned"
    INCONCLUSIVE = "inconclusive: insufficient evidence in capture"


@dataclass
class Fingerprint:
    """Parsed, structured view of one fingerprint capture."""
    uid: str | None = None
    atqa: str | None = None
    sak: str | None = None
    rats: str | None = None
    fdt_1a00: int | None = None          # first value, ticks
    fdt_af_badkey: int | None = None
    fdt_af_defkey: int | None = None
    # command-response map: the set of command bytes that return 00/ACK to XX00+CRC
    cmd00_ack: set[int] | None = None
    prng_weak: bool = False              # repeated or wrong-CRC-but-valid RndB seen
    rnd_b_samples: list[str] = field(default_factory=list)


@dataclass
class Result:
    verdict: Verdict
    confidence: str                      # high | medium | low
    evidence: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)


# The Giantec/USCUID challenge is a 16-bit LFSR seeded by wakeup timing, so RndB
# repeats fast. The paper observes a >50% duplicate chance within 12 nonces and
# 99.99% within 39, which inverts (birthday bound) to an effective pool of only
# ~2^6.5 values, not the LFSR's full 2^16. A genuine NXP TRNG draws RndB from
# 2^64, where a single duplicate across any realistic batch is impossible.
NONCE_OBSERVED_POOL = 95                  # ~2^6.6, the paper's deployed-card figure
NONCE_GENUINE_BITS = 64
# No collision across this many draws effectively rules out the LFSR: P(no dup)
# for a ~2^6.5 pool at 39 draws is under 0.01%.
NONCE_CLEAR_THRESHOLD = 39


@dataclass
class NonceReport:
    total: int
    distinct: int
    duplicates: int
    first_collision_at: int | None        # 1-based draw index of first repeat
    est_pool: float | None                 # birthday-inverted effective pool
    p_genuine_would_dup: float             # P(a 2^64 TRNG collides in this batch)
    verdict: Verdict
    confidence: str
    notes: list[str] = field(default_factory=list)


def _normalize_nonce(s: str) -> str:
    """Reduce a captured RndB response to comparable hex: drop the CRC bracket,
    keep hex only, uppercase, strip a leading AF status byte so AF-prefixed and
    bare captures compare equal within a batch."""
    s = re.sub(r"\[[^\]]*\]", "", s)      # drop trailing CRC like [6355]
    s = re.sub(r"[^0-9A-Fa-f]", "", s)
    s = s.upper()
    if s.startswith("AF") and len(s) > 2:
        s = s[2:]
    return s


def _estimate_pool(distinct: int, n: int) -> float | None:
    """Invert E[distinct] = N(1-(1-1/N)^n) for N, given observed distinct in n
    draws. Monotonic in N, so bisect."""
    if distinct >= n or distinct < 1:
        return None
    lo, hi = float(distinct), 1e9
    for _ in range(200):
        mid = (lo + hi) / 2
        exp = mid * (1 - (1 - 1 / mid) ** n)
        if exp < distinct:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def analyze_nonces(samples: list[str]) -> NonceReport:
    """Collision analysis over a batch of captured RndB responses."""
    norm = [v for v in (_normalize_nonce(s) for s in samples) if v]
    n = len(norm)
    distinct = len(set(norm))
    dups = n - distinct

    seen: set[str] = set()
    first: int | None = None
    for i, v in enumerate(norm, 1):
        if v in seen and first is None:
            first = i
        seen.add(v)

    # P(a genuine 64-bit TRNG produces >=1 collision in n draws).
    p_trng = 1 - math.exp(-n * (n - 1) / (2 * 2 ** NONCE_GENUINE_BITS)) if n > 1 else 0.0
    pool = _estimate_pool(distinct, n) if dups > 0 else None
    notes: list[str] = []

    if n == 0:
        return NonceReport(0, 0, 0, None, None, 0.0, Verdict.INCONCLUSIVE, "low",
                           ["no parseable nonces in input"])

    if dups > 0:
        notes.append(f"{dups} duplicate RndB in {n} draws, first repeat at draw {first}")
        if pool is not None:
            notes.append(f"effective pool ~{pool:.0f} (~2^{math.log2(pool):.1f}); "
                         f"genuine TRNG is 2^{NONCE_GENUINE_BITS}")
        notes.append(f"a genuine TRNG would collide here with p={p_trng:.2e}, so a "
                     f"duplicate is proof of a weak PRNG (LFSR counterfeit)")
        return NonceReport(n, distinct, dups, first, pool, p_trng,
                           Verdict.SUSPECT, "high", notes)

    # no duplicates
    if n >= NONCE_CLEAR_THRESHOLD:
        notes.append(f"no collision in {n} draws; a ~2^6.5 LFSR pool would have "
                     f"collided with >99.99% probability by now")
        notes.append("consistent with a genuine NXP TRNG")
        return NonceReport(n, distinct, dups, first, pool, p_trng,
                           Verdict.GENUINE, "medium", notes)

    notes.append(f"no collision yet, but only {n} draws; capture at least "
                 f"{NONCE_CLEAR_THRESHOLD} to rule out the LFSR pool")
    return NonceReport(n, distinct, dups, first, pool, p_trng,
                       Verdict.INCONCLUSIVE, "low", notes)


def _extract_nonces(text: str) -> list[str]:
    """Pull RndB samples from either a nonce list (one per line) or a fingerprint
    capture (the `Cmd 1a00:` response lines)."""
    out: list[str] = []
    for line in text.splitlines():
        m = re.search(r"1a00:\s*([0-9A-Fa-f]+(?:\[[0-9A-Fa-f]+\])?)", line)
        if m:
            out.append(m.group(1))
            continue
        t = line.strip()
        if not t:
            continue
        hexonly = re.sub(r"[^0-9A-Fa-f]", "", re.sub(r"\[[^\]]*\]", "", t))
        if len(hexonly) >= 8 and re.fullmatch(r"[0-9A-Fa-f\[\] ]+", t):
            out.append(t)
    return out


def _expand_ranges(spec: str) -> set[int]:
    """Expand a Proxmark range spec like '00-19,1b-2f,51-a1,a3-ff' to a byte set."""
    out: set[int] = set()
    for part in spec.strip().split(","):
        part = part.strip().strip("`")   # fingerprint md form uses backquotes
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo_i, hi_i = int(lo, 16), int(hi, 16)
            except ValueError:
                continue
            out.update(range(lo_i, hi_i + 1))
        else:
            try:
                out.add(int(part, 16))
            except ValueError:
                continue
    return out


def _first_int(text: str) -> int | None:
    """Pull the first integer after a colon, tolerating 'N' and 'N/M' forms."""
    m = re.search(r":\s*(\d+)", text)
    return int(m.group(1)) if m else None


def parse_fingerprint(text: str) -> Fingerprint:
    """Parse a fingerprint capture. Tolerant of the two FDT line layouts and of
    partial captures (any field may be absent)."""
    fp = Fingerprint()
    for raw in text.splitlines():
        line = raw.rstrip()

        m = re.match(r"\s*UID:\s*([0-9A-Fa-f ]+)", line)
        if m and fp.uid is None:
            fp.uid = m.group(1).replace(" ", "").upper()
            continue
        m = re.match(r"\s*ATQA anticol:\s*([0-9A-Fa-f ]+)", line)
        if m:
            fp.atqa = m.group(1).strip().upper()
            continue
        m = re.match(r"\s*SAK anticol:\s*([0-9A-Fa-f ]+)", line)
        if m:
            fp.sak = m.group(1).strip().upper()
            continue
        m = re.match(r"\s*Answer to RATS:\s*(\S+)", line)
        if m:
            fp.rats = m.group(1).strip().upper()
            continue

        # FDT lines. Two layouts:
        #   "FDT to AF*  (bad key):  11412"
        #   "FDT to AF*  (bad key) min/max:  11428/11428 = ..."
        # and 1A00 may appear with no qualifier ("FDT to 1A00          :  14884").
        if "FDT to" in line:
            val = _first_int(line)
            if val is None:
                continue
            is_af = "AF" in line.split(":")[0]
            is_1a = "1A00" in line.split(":")[0] or "1A00" in line
            if "bad key" in line:
                if is_af:
                    fp.fdt_af_badkey = val
                elif is_1a and fp.fdt_1a00 is None:
                    fp.fdt_1a00 = val
            elif "def key" in line:
                if is_af:
                    fp.fdt_af_defkey = val
            else:
                # unqualified line: AF or 1A00 (USCUID single-run layout)
                if is_af and fp.fdt_af_badkey is None:
                    fp.fdt_af_badkey = val
                elif is_1a and fp.fdt_1a00 is None:
                    fp.fdt_1a00 = val
            continue

        # Command-response map: "Cmd **00=00:  00-19,1b-2f,31-4f,51-a1,a3-ff"
        m = re.match(r"\s*Cmd \*\*00=00:\s*(.+)", line)
        if m:
            got = _expand_ranges(m.group(1))
            # keep the broadest map seen (pre-auth map is the stable reference)
            if fp.cmd00_ack is None or len(got) > len(fp.cmd00_ack):
                fp.cmd00_ack = got
            continue

        # Weak-PRNG tells left by the probe.
        if "valid lfsr" in line.lower() or "wrong crc" in line.lower():
            fp.prng_weak = True
        m = re.search(r"Cmd 1a00:\s*([0-9A-Fa-f]+)", line)
        if m:
            fp.rnd_b_samples.append(m.group(1).upper())

    # repeated RndB across samples is itself a weak-PRNG signal; run the active
    # collision analysis rather than a bare set-length check so a single dup in
    # the capture is scored the same way as the --nonces mode.
    if len(fp.rnd_b_samples) >= 2:
        if analyze_nonces(fp.rnd_b_samples).duplicates > 0:
            fp.prng_weak = True

    log.debug("parsed uid=%s fdt_1a00=%s fdt_af_bad=%s cmd00_ack=%s prng_weak=%s",
              fp.uid, fp.fdt_1a00, fp.fdt_af_badkey,
              None if fp.cmd00_ack is None else len(fp.cmd00_ack), fp.prng_weak)
    return fp


def _near(value: int | None, centre: int, tol: int = FDT_TOL) -> bool:
    return value is not None and abs(value - centre) <= tol


def classify(fp: Fingerprint) -> Result:
    """Layered decision. Each layer appends evidence; we fall through to the next
    only when the current one leaves the family ambiguous."""
    ev: list[str] = []
    caveats: list[str] = []

    # --- Layer 1: FDT timing on the bad-key AF response -------------------
    af = fp.fdt_af_badkey
    if af is not None:
        us = af / TICKS_PER_US
        log.info("layer1 FDT AF(bad key)=%d ticks (%.0f us)", af, us)
        if _near(af, FDT_AF_BAD_ULCG):
            ev.append(f"FDT AF(bad key)={af} ticks (~{us:.0f} us): Giantec LFSR "
                      f"bails out ~10x faster than genuine (~842 us)")
            return Result(Verdict.ULCG, "high", ev, caveats)
        if _near(af, FDT_AF_BAD_USCUID):
            ev.append(f"FDT AF(bad key)={af} ticks (~{us:.0f} us): several times "
                      f"slower than genuine (~842 us), matches USCUID-UL v1")
            return Result(Verdict.USCUID, "high", ev, caveats)
        if _near(af, FDT_AF_BAD_NXP):
            ev.append(f"FDT AF(bad key)={af} ticks (~{us:.0f} us): genuine-looking, "
                      f"does not separate NXP from FJ8010 / USCUID-UL v2")
        else:
            ev.append(f"FDT AF(bad key)={af} ticks (~{us:.0f} us): no known bucket")
            caveats.append("FDT outside all reference buckets; capture or new variant")
    else:
        caveats.append("no FDT AF(bad key) value in capture; skipped timing layer")

    # --- Layer 2: command-response map ------------------------------------
    # Genuine NXP ACKs almost the whole command range; ULCG/FJ8010 ACK a tiny
    # set (often just 0xA0). This is what catches the timing-genuine fakes.
    cmd = fp.cmd00_ack
    if cmd is not None:
        n = len(cmd)
        log.info("layer2 cmd00 ACK set size=%d", n)
        if n <= 4:
            ev.append(f"command map: ACKs only {_fmt_bytes(cmd)} to XX00 "
                      f"({n} cmds) vs genuine NXP ACKing ~200 cmds")
            # ULCG vs FJ8010: timing already separates ULCG (handled in L1).
            # If we are here with a tiny map and genuine-looking timing, it is
            # the FJ8010 profile (ULCG would have been caught by FDT).
            if _near(af, FDT_AF_BAD_NXP):
                ev.append("tiny command map with genuine-looking FDT matches FJ8010")
                return Result(Verdict.FJ8010, "high", ev, caveats)
            ev.append("tiny command map indicates a Giantec/Feiju-class counterfeit")
            return Result(Verdict.SUSPECT, "medium", ev, caveats)
        # Broad map: genuine NXP or USCUID-UL. USCUID has a 0x50-0x5F gap
        # (responds 0x60-0xA1, not 0x51-0xA1).
        gap_50_5f = not any(b in cmd for b in range(0x51, 0x60))
        if gap_50_5f:
            ev.append("command map: broad but missing the 0x50-0x5F range "
                      "(0x60-0xA1), the USCUID-UL signature")
            if fp.prng_weak:
                ev.append("weak PRNG confirmed (repeated / wrong-CRC-but-valid RndB)")
            return Result(Verdict.USCUID, "high" if fp.prng_weak else "medium",
                          ev, caveats)
        ev.append(f"command map: broad ACK set ({n} cmds incl. 0x51-0xA1), "
                  f"consistent with genuine NXP")
    else:
        caveats.append("no command-response map in capture; skipped command layer")

    # --- Layer 3: PRNG quality -------------------------------------------
    if fp.prng_weak:
        ev.append("weak PRNG: repeated or wrong-CRC-but-valid RndB, genuine NXP "
                  "uses a TRNG and never shows this")
        return Result(Verdict.SUSPECT, "medium", ev, caveats)

    # --- Conclusion -------------------------------------------------------
    if _near(af, FDT_AF_BAD_NXP) and cmd is not None and len(cmd) > 4:
        ev.append("genuine-looking timing and command map, no counterfeit tell")
        conf = "medium" if not fp.prng_weak else "low"
        if not fp.rnd_b_samples:
            caveats.append("no RndB samples: PRNG quality not verified; capture "
                           "10k+ nonces to rule out a timing-genuine counterfeit")
        return Result(Verdict.GENUINE, conf, ev, caveats)

    if not ev:
        return Result(Verdict.INCONCLUSIVE, "low", ev,
                      caveats or ["capture lacked FDT, command map and nonce data"])
    return Result(Verdict.SUSPECT, "low", ev, caveats)


def _fmt_bytes(s: set[int]) -> str:
    return "{" + ",".join(f"0x{b:02X}" for b in sorted(s)) + "}"


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s [ulc-classify] %(levelname)s: %(message)s")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Classify a MIFARE Ultralight C fingerprint capture as "
                    "genuine NXP or a known counterfeit.")
    ap.add_argument("capture", nargs="?", default="-",
                    help="fingerprint capture file, or - for stdin")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="-v for INFO, -vv for DEBUG (to stderr)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--nonces", action="store_true",
                    help="treat the input as a batch of captured RndB responses "
                         "(one per line, or a capture's Cmd 1a00 lines) and run "
                         "only the PRNG collision analysis")
    args = ap.parse_args(argv)
    _setup_logging(args.verbose)

    text = sys.stdin.read() if args.capture == "-" else open(args.capture).read()

    if args.nonces:
        rep = analyze_nonces(_extract_nonces(text))
        if args.json:
            import json
            print(json.dumps({
                "mode": "nonces",
                "total": rep.total, "distinct": rep.distinct,
                "duplicates": rep.duplicates,
                "first_collision_at": rep.first_collision_at,
                "effective_pool": rep.est_pool,
                "p_genuine_would_dup": rep.p_genuine_would_dup,
                "verdict": rep.verdict.name,
                "verdict_text": rep.verdict.value,
                "confidence": rep.confidence,
                "notes": rep.notes,
            }, indent=2))
        else:
            print(f"Nonces:     {rep.total} captured, {rep.distinct} distinct, "
                  f"{rep.duplicates} duplicate")
            if rep.first_collision_at:
                print(f"First repeat at draw {rep.first_collision_at}")
            print(f"Verdict:    {rep.verdict.value}")
            print(f"Confidence: {rep.confidence}")
            for note in rep.notes:
                print(f"  - {note}")
        return 0

    fp = parse_fingerprint(text)
    res = classify(fp)

    if args.json:
        import json
        print(json.dumps({
            "uid": fp.uid,
            "verdict": res.verdict.name,
            "verdict_text": res.verdict.value,
            "confidence": res.confidence,
            "evidence": res.evidence,
            "caveats": res.caveats,
        }, indent=2))
    else:
        print(f"UID:        {fp.uid or 'unknown'}")
        print(f"Verdict:    {res.verdict.value}")
        print(f"Confidence: {res.confidence}")
        if res.evidence:
            print("Evidence:")
            for e in res.evidence:
                print(f"  - {e}")
        if res.caveats:
            print("Caveats:")
            for c in res.caveats:
                print(f"  - {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
