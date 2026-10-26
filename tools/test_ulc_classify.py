"""Regression tests for tools/ulc_classify.py.

These validate the classifier against the fingerprint captures already in this
repository (cards/*/analyses/fingerprint_ulc_*.txt), so the tool stays pinned to
the paper's own ground truth with no duplicated data.

Run from the repo root:  python3 -m pytest tools/test_ulc_classify.py -q
"""

import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from ulc_classify import (  # noqa: E402
    Verdict, analyze_nonces, classify, parse_fingerprint,
)

# In-repo reference captures -> expected verdict, expected minimum confidence.
CARD_FIXTURES = [
    ("cards/ulc/analyses/fingerprint_ulc_nxp.txt", Verdict.GENUINE, "medium"),
    ("cards/ulcg/analyses/fingerprint_ulc_ulcg.txt", Verdict.ULCG, "high"),
    ("cards/fj8010/analyses/fingerprint_ulc_fj8010.txt", Verdict.FJ8010, "high"),
    ("cards/uscuid-ul/analyses/fingerprint_ulc_uscuid-ul.txt", Verdict.USCUID, "high"),
]
CONF_RANK = {"low": 0, "medium": 1, "high": 2}


@pytest.mark.parametrize("rel,expected,min_conf", CARD_FIXTURES)
def test_reference_capture(rel, expected, min_conf):
    path = REPO / rel
    if not path.exists():
        pytest.skip(f"fixture not checked out: {rel}")
    res = classify(parse_fingerprint(path.read_text()))
    assert res.verdict == expected, f"{rel}: got {res.verdict} ({res.evidence})"
    assert CONF_RANK[res.confidence] >= CONF_RANK[min_conf]


def test_fdt_alone_misses_fj8010():
    """FJ8010 has genuine-looking timing; the command map is what flags it."""
    from ulc_classify import FDT_AF_BAD_NXP, FDT_TOL
    path = REPO / "cards/fj8010/analyses/fingerprint_ulc_fj8010.txt"
    if not path.exists():
        pytest.skip("fj8010 fixture not checked out")
    fp = parse_fingerprint(path.read_text())
    res = classify(fp)
    assert abs(fp.fdt_af_badkey - FDT_AF_BAD_NXP) <= FDT_TOL
    assert res.verdict == Verdict.FJ8010
    assert any("command map" in e for e in res.evidence)


def test_nonce_mode_flags_lfsr_batch():
    from ulc_classify import _extract_nonces
    path = HERE / "testdata" / "nonces_ulcg.txt"
    rep = analyze_nonces(_extract_nonces(path.read_text()))
    assert rep.duplicates > 0
    assert rep.verdict == Verdict.SUSPECT and rep.confidence == "high"
    assert rep.est_pool is not None and 16 < rep.est_pool < 512


def test_nonce_mode_clears_genuine_batch():
    from ulc_classify import _extract_nonces
    path = HERE / "testdata" / "nonces_genuine.txt"
    rep = analyze_nonces(_extract_nonces(path.read_text()))
    assert rep.duplicates == 0 and rep.verdict == Verdict.GENUINE


def test_single_duplicate_is_conclusive():
    rep = analyze_nonces(["AABBCCDDEEFF0011", "1122334455667788", "AABBCCDDEEFF0011"])
    assert rep.duplicates == 1 and rep.p_genuine_would_dup < 1e-30
    assert rep.verdict == Verdict.SUSPECT
