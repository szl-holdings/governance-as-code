"""Offline schema controls with honestly signed synthetic malformed receipts."""
from __future__ import annotations

import copy
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

from examples.verify_demo_bundle import verify_bundle  # noqa: E402
from receipt_lib import (  # noqa: E402
    PREDICATE_TYPE,
    build_receipt,
    canonical,
    chain_hash,
    export_pubkey_raw_b64,
    generate_keypair,
    keyid,
    sha256_hex,
    sign,
    verify_chain,
    verify_receipt,
)


@pytest.fixture
def signed_control():
    secret, public = generate_keypair()
    receipt = build_receipt(
        action_id="schema-control",
        subject_name="test:offline-schema",
        actor={"type": "human", "id": "fixture-owner", "is_service_account": False,
               "auth_method": "hardware_key", "human_principal": "Fixture Owner"},
        policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"policy"),
                         "evaluated_at": "2026-09-30T00:00:00+00:00"},
        execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
        evidence_items=[{"id": "fixture", "sha256": sha256_hex(b"fixture"), "present": True}],
        prev_chain_hash="GENESIS",
        signing_key=secret,
    )
    return receipt, secret, public


def resign(receipt, secret):
    # Rebind the predicate and sign exactly the malformed payload. Schema rejection
    # must be independent of digest or signature tampering.
    receipt["subject"]["digest"]["sha256"] = sha256_hex(canonical(receipt.get("predicate")))
    payload = {key: value for key, value in receipt.items() if key != "signatures"}
    receipt["signatures"] = [{"keyid": keyid(secret.public_key()),
                              "sig": sign(secret, PREDICATE_TYPE, canonical(payload))}]
    return receipt


def bundle_for(receipt, public):
    return {"public_key_raw_b64": export_pubkey_raw_b64(public), "keyid": keyid(public),
            "chain_tip": chain_hash(receipt), "receipts": [receipt]}


def test_valid_signed_control_remains_pass(signed_control):
    receipt, _, public = signed_control
    before = copy.deepcopy(receipt)
    verdict = verify_receipt(receipt, public)
    assert verdict.verdict == "PASS"
    assert verdict.signature_valid is True
    assert verdict.schema_valid is True
    assert verdict.evidence_completeness == "COMPLETE"
    assert verify_chain([receipt], public)["all_links_valid"] is True
    assert verify_bundle(bundle_for(receipt, public))[0] == 0
    assert receipt == before


@pytest.mark.parametrize("present", [False, "false", 1, {"present": True}, None, []])
def test_present_requires_a_boolean_and_exact_true(signed_control, present):
    receipt, secret, public = signed_control
    receipt["predicate"]["evidence"]["items"][0]["present"] = present
    receipt["predicate"]["evidence"]["completeness"] = "INCOMPLETE"
    resign(receipt, secret)
    verdict = verify_receipt(receipt, public)
    assert verdict.signature_valid is True
    assert verdict.evidence_completeness == "INCOMPLETE"
    if present is False:
        assert verdict.schema_valid is True
        assert verdict.verdict == "INCOMPLETE"
        assert verify_chain([receipt], public)["all_links_valid"] is True
        assert verify_bundle(bundle_for(receipt, public))[0] == 0
    else:
        assert verdict.verdict == "FAIL"
        assert verdict.schema_valid is False
        assert any("schema validation failed" in reason for reason in verdict.reasons)
        chain = verify_chain([receipt], public)
        assert chain["all_links_valid"] is False
        assert chain["verdicts"][0]["chain_link"] is True
        assert verify_bundle(bundle_for(receipt, public))[0] == 1


@pytest.mark.parametrize("path", [
    ("predicate", "action_id"), ("predicate", "actor"),
    ("predicate", "policy_decision"), ("predicate", "execution"),
    ("predicate", "evidence"), ("predicate", "timestamps"),
    ("predicate", "prev_chain_hash"),
    ("predicate", "actor", "id"), ("predicate", "actor", "auth_method"),
    ("predicate", "actor", "human_principal"),
    ("predicate", "policy_decision", "result"),
    ("predicate", "policy_decision", "policy_hash"),
    ("predicate", "policy_decision", "evaluated_at"),
    ("predicate", "execution", "side_effect_class"),
    ("predicate", "execution", "status"),
    ("predicate", "evidence", "items", 0, "id"),
    ("predicate", "evidence", "items", 0, "sha256"),
    ("predicate", "evidence", "items", 0, "present"),
    ("predicate", "timestamps", "created"),
    ("predicate", "timestamps", "ntp_synced"),
])
def test_signed_missing_required_fields_fail(signed_control, path):
    receipt, secret, public = signed_control
    node = receipt
    for part in path[:-1]:
        node = node[part]
    del node[path[-1]]
    resign(receipt, secret)
    verdict = verify_receipt(receipt, public)
    assert verdict.verdict == "FAIL"
    assert verdict.signature_valid is True
    assert verdict.schema_valid is False
    assert any("schema validation failed" in reason for reason in verdict.reasons)
    assert verify_chain([receipt], public)["all_links_valid"] is False
    assert verify_bundle(bundle_for(receipt, public))[0] == 1


@pytest.mark.parametrize(("path", "value"), [
    (("predicate",), None), (("predicate",), []), (("predicate",), "predicate"),
    (("predicate", "actor"), None),
    (("predicate", "actor", "type"), "robot"),
    (("predicate", "actor", "is_service_account"), 0),
    (("predicate", "policy_decision"), []),
    (("predicate", "policy_decision", "result"), "PASS"),
    (("predicate", "execution"), None),
    (("predicate", "execution", "status"), "SUCCESS"),
    (("predicate", "evidence"), None),
    (("predicate", "evidence", "items"), "items"),
    (("predicate", "evidence", "items", 0), []),
    (("predicate", "evidence", "items", 0, "id"), 1),
    (("predicate", "evidence", "items", 0, "sha256"), None),
    (("predicate", "timestamps"), None),
    (("predicate", "timestamps", "ntp_synced"), False),
    (("predicate", "prev_chain_hash"), "not-a-hash"),
])
def test_signed_schema_invalid_payload_fails_without_throwing(signed_control, path, value):
    receipt, secret, public = signed_control
    node = receipt
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    resign(receipt, secret)
    verdict = verify_receipt(receipt, public)
    assert verdict.verdict == "FAIL"
    assert verdict.signature_valid is True
    assert verdict.schema_valid is False
    assert verify_chain([receipt], public)["all_links_valid"] is False
    assert verify_bundle(bundle_for(receipt, public))[0] == 1


def test_signature_failure_is_distinct_from_schema_failure(signed_control):
    receipt, _, public = signed_control
    receipt["predicate"]["action_id"] = "altered-after-signing"
    verdict = verify_receipt(receipt, public)
    assert verdict.verdict == "FAIL"
    assert verdict.signature_valid is False
    assert verdict.schema_valid is True


@pytest.mark.parametrize("receipt", [None, [], "receipt", 1, True])
def test_non_object_receipt_is_a_structured_chain_failure(receipt):
    _, public = generate_keypair()
    result = verify_chain([receipt], public)
    assert result["all_links_valid"] is False
    assert result["verdicts"][0]["signature_valid"] is False
    assert result["verdicts"][0]["schema_valid"] is False


def test_empty_chain_contract_remains_unchanged():
    _, public = generate_keypair()
    result = verify_chain([], public)
    assert result == {"length": 0, "tip": "GENESIS", "all_links_valid": True, "verdicts": []}
