"""Only a qualified boolean completeness claim can permit execution (C4)."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
from credo_governor import compose, map_credo  # noqa: E402


@pytest.mark.parametrize("evidence", [
    False, None, 0, "", [], {}, "false", "true", "INCOMPLETE", 1,
    ["missing"], {"present": False},
])
@pytest.mark.parametrize("composed", [False, True])
def test_unqualified_completeness_cannot_allow_execution(evidence, composed):
    if composed:
        result = compose(map_credo("advise"), "allow", evidence_complete=evidence)
    else:
        result = map_credo("allow", evidence_complete=evidence)
    assert result.may_execute is False
    assert result.szl == "REVIEW"
    assert result.execution_status == "HELD_FOR_REVIEW"
    assert any(reason.startswith("C4:") for reason in result.reasons)


@pytest.mark.parametrize("outcome", ["allow", "block", "escalate", "advise"])
def test_unqualified_completeness_cannot_lift_prior_deny(outcome):
    result = compose(map_credo("block"), outcome, evidence_complete="false")
    assert result.szl == "DENY"
    assert result.may_execute is False
    assert any(reason.startswith("C2:") for reason in result.reasons)


def test_explicit_block_with_unqualified_evidence_remains_denied():
    result = map_credo("block", evidence_complete="false")
    assert result.szl == "DENY"
    assert result.execution_status == "DENIED"
    assert result.may_execute is False


@pytest.mark.parametrize("composed", [False, True])
def test_qualified_boolean_completeness_still_allows(composed):
    if composed:
        result = compose(map_credo("advise"), "allow", evidence_complete=True)
    else:
        result = map_credo("allow", evidence_complete=True)
    assert result.szl == "ALLOW"
    assert result.execution_status == "EXECUTED"
    assert result.may_execute is True
