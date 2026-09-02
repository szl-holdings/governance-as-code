#!/usr/bin/env python3
"""Contract checks for the offline demo-bundle verifier."""
from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from receipt_lib import (  # noqa: E402
    build_receipt,
    canonical,
    export_pubkey_raw_b64,
    generate_keypair,
    keyid,
    sha256_hex,
    verify_chain,
)

SPEC = importlib.util.spec_from_file_location(
    "verify_demo_bundle", ROOT / "examples" / "verify_demo_bundle.py"
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

ACTOR = {
    "type": "human",
    "id": "fixture-owner",
    "is_service_account": False,
    "auth_method": "hardware_key",
    "human_principal": "Fixture Owner",
}
POLICY = {
    "result": "ALLOW",
    "policy_hash": sha256_hex(b"fixture-policy"),
    "evaluated_at": "2026-09-02T00:00:00+00:00",
}
EVIDENCE = [{"id": "fixture", "sha256": sha256_hex(b"fixture"), "present": True}]


def valid_bundle() -> dict:
    secret_key, public_key = generate_keypair()
    receipt = build_receipt(
        action_id="offline-verifier-fixture",
        subject_name="test:offline-verifier",
        actor=ACTOR,
        policy_decision=POLICY,
        execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
        evidence_items=EVIDENCE,
        prev_chain_hash="GENESIS",
        signing_key=secret_key,
    )
    chain = [receipt]
    result = verify_chain(chain, public_key)
    return {
        "public_key_raw_b64": export_pubkey_raw_b64(public_key),
        "keyid": keyid(public_key),
        "chain_tip": result["tip"],
        "receipts": chain,
    }


def test_valid_bundle_is_accepted() -> None:
    code, message = verifier.verify_bundle(valid_bundle())
    assert code == 0
    assert message.startswith("CHAIN OK length=1 tip=")


def test_unsigned_receipt_is_rejected() -> None:
    bundle = valid_bundle()
    bundle["receipts"][0].pop("signatures")
    code, message = verifier.verify_bundle(bundle)
    assert code == 1
    assert "has no signature" in message


def test_tip_tampering_is_rejected() -> None:
    bundle = valid_bundle()
    bundle["chain_tip"] = "0" * 64
    code, message = verifier.verify_bundle(bundle)
    assert code == 1
    assert "tip mismatch" in message


def test_signer_identifier_tampering_is_rejected() -> None:
    bundle = valid_bundle()
    tampered = copy.deepcopy(bundle)
    tampered["receipts"][0]["signatures"][0]["keyid"] = "0" * 16
    code, message = verifier.verify_bundle(tampered)
    assert code == 1
    assert "signer mismatch" in message


def test_payload_tampering_is_rejected() -> None:
    bundle = valid_bundle()
    tampered = copy.deepcopy(bundle)
    tampered["receipts"][0]["predicate"]["action_id"] = "altered-after-signing"
    code, message = verifier.verify_bundle(tampered)
    assert code == 1
    assert "verification failed" in message


def test_canonical_import_is_exercised_by_fixture() -> None:
    # Prevent the helper contract from silently dropping deterministic JSON
    # semantics while keeping the assertion independent of generated times.
    assert canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
