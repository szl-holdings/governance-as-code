#!/usr/bin/env python3
"""Acceptance tests for the Credo → SZL governor map."""
from __future__ import annotations
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
from credo_governor import map_credo, compose


def test_allow_executes():
    r = map_credo("allow")
    assert r.szl == "ALLOW" and r.may_execute is True
    assert r.execution_status == "EXECUTED"
    assert r.lambda_label == "ADVISORY"


def test_block_is_deny_artifact():
    r = map_credo("block")
    assert r.szl == "DENY" and r.may_execute is False
    assert r.execution_status == "DENIED"


def test_escalate_holds_for_named_human():
    r = map_credo("escalate", human_principal="s.lutar")
    assert r.szl == "REVIEW" and r.may_execute is False
    assert r.execution_status == "HELD_FOR_REVIEW"


def test_escalate_without_human_is_deny():
    r = map_credo("escalate")
    assert r.szl == "DENY" and r.may_execute is False


def test_advise_never_authorizes():
    r = map_credo("advise")
    assert r.szl == "ADVISE" and r.may_execute is False
    assert r.execution_status == "ADVISED"
    assert any("cannot authorize" in x for x in r.reasons)


def test_hard_deny_survives_later_allow():
    denied = map_credo("block")
    later = compose(denied, "allow")
    assert later.szl == "DENY" and later.may_execute is False
    assert any("cannot lift a hard DENY" in x for x in later.reasons)


def test_hard_deny_survives_advise_and_escalate():
    denied = map_credo("block")
    assert compose(denied, "advise").szl == "DENY"
    assert compose(denied, "escalate", human_principal="s.lutar").szl == "DENY"


def test_missing_evidence_never_allows():
    r = map_credo("allow", evidence_complete=False)
    assert r.may_execute is False
    assert r.szl in ("DENY", "REVIEW")


def test_lambda_floor_miss_is_review_not_theorem():
    r = map_credo("allow", lambda_below_floor=True)
    assert r.szl == "REVIEW" and r.may_execute is False
    assert r.lambda_label == "ADVISORY"


def test_lambda_floor_plus_block_is_deny():
    r = map_credo("block", lambda_below_floor=True)
    assert r.szl == "DENY" and r.may_execute is False


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"ok  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    if failed:
        raise SystemExit(failed)
    print(f"{len(tests)} passed")
