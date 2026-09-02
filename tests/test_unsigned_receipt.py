#!/usr/bin/env python3
"""Negative contract: an unsigned GovernedAction/v1 receipt must fail closed."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from receipt_lib import generate_keypair, verify_receipt  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "unsigned_receipt.json"


def test_unsigned_receipt_is_rejected_with_honest_reason() -> None:
    receipt = json.loads(FIXTURE.read_text(encoding="utf-8"))
    _, public_key = generate_keypair()

    result = verify_receipt(receipt, public_key)

    assert result.verdict == "FAIL"
    assert result.signature_valid is False
    assert result.evidence_completeness == "COMPLETE"
    assert "no signatures present" in result.reasons


def test_empty_signature_list_is_also_rejected() -> None:
    receipt = json.loads(FIXTURE.read_text(encoding="utf-8"))
    receipt["signatures"] = []
    _, public_key = generate_keypair()

    result = verify_receipt(receipt, public_key)

    assert result.verdict == "FAIL"
    assert result.signature_valid is False
    assert "no signatures present" in result.reasons
