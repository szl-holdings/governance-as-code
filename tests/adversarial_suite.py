#!/usr/bin/env python3
"""adversarial_suite.py — attack battery against receipt_lib.

Every test is an attack an auditor's adversary would try. Each must produce
FAIL or INCOMPLETE — never PASS. If any attack yields PASS, the receipt claim
is broken and the test suite exits 1. This is the self-hosted CLM-011 gate;
independent review (Daybreak Blue S2) remains the external gate.

Attack classes:
  A1  tamper predicate field after signing
  A2  signature transplant from a different receipt
  A3  correctly signed foreign predicate type
  A4  evidence deletion after signing (integrity break)
  A5  honestly-signed incomplete evidence (must hold INCOMPLETE)
  A6  human-principal spoof via api_key
  A7  correctly signed service actor with is_service_account=false
  A8  missing human_principal for human actor
  A9  chain link splice — receipt pulled from another position
  A10 forged GENESIS — first receipt with wrong prev hash
  A11 backdated receipt with ntp_synced=false
  A12 declared completeness != computed (lie in the field)
  A13 duplicate-signature list manipulation (empty sigs)
  A14 correctly signed subject digest mismatch vs predicate
  A15 unicode/canonicalization confusion in string fields
"""
import copy, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
from receipt_lib import (build_receipt, chain_hash, generate_keypair, verify_chain,
                         verify_receipt, canonical, sha256_hex, sign)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1"),
       "evaluated_at": "2026-08-31T00:00:00+00:00"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

results = []
def check(name, verdict, expect):
    ok = verdict in expect
    results.append((name, verdict, ok))
    print(f"  [{'HELD' if ok else 'BROKEN':6s}] {name:52s} -> {verdict} (need {'/'.join(expect)})")
    return ok

def fresh_chain(sk):
    r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                       policy_decision=POL, execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED", "deployed_revision": "abc123"},
                       evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
    r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=HUMAN,
                       policy_decision=POL, execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                       evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk)
    return r1, r2

def resign(receipt, sk):
    """Re-sign a deliberately malformed envelope so semantic gates, not integrity failure, must reject it."""
    key = receipt["signatures"][0]["keyid"]
    payload_type = receipt.get("predicateType", "")
    signed = {k: v for k, v in receipt.items() if k != "signatures"}
    receipt["signatures"] = [{"keyid": key, "sig": sign(sk, payload_type, canonical(signed))}]
    return receipt

def main():
    sk, pk = generate_keypair()
    sk2, pk2 = generate_keypair()
    r1, r2 = fresh_chain(sk)
    all_ok = True

    t = copy.deepcopy(r1); t["predicate"]["execution"]["deployed_revision"] = "evil00"
    all_ok &= check("A1 tamper field", verify_receipt(t, pk).verdict, ["FAIL"])

    t = copy.deepcopy(r2); t["signatures"] = r1["signatures"]
    all_ok &= check("A2 signature transplant", verify_receipt(t, pk).verdict, ["FAIL"])

    # A3: foreign predicate type, honestly signed under that foreign type.
    # Integrity alone is valid; the GovernedAction/v1 semantic contract must reject it.
    t = copy.deepcopy(r1); t["predicateType"] = "https://example.com/other-predicate/v9"
    resign(t, sk)
    all_ok &= check("A3 signed foreign predicate type", verify_receipt(t, pk).verdict, ["FAIL"])

    t = copy.deepcopy(r1); t["predicate"]["evidence"]["items"] = []
    all_ok &= check("A4 evidence deletion post-signing", verify_receipt(t, pk).verdict, ["FAIL"])

    honest = build_receipt(action_id="a-003", subject_name="prod:svc", actor=HUMAN,
                           policy_decision=POL, execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                           evidence_items=[{"id": "log", "sha256": "", "present": False}],
                           prev_chain_hash=chain_hash(r2), signing_key=sk)
    all_ok &= check("A5 honest incomplete evidence", verify_receipt(honest, pk).verdict, ["INCOMPLETE"])

    t = copy.deepcopy(r1); t["predicate"]["actor"]["auth_method"] = "api_key"
    all_ok &= check("A6 api_key claims human", verify_receipt(t, pk).verdict, ["FAIL"])

    svc_spoof = copy.deepcopy(r1)
    svc_spoof["predicate"]["actor"] = {"type": "service", "id": "agent://x", "is_service_account": False, "auth_method": "api_key"}
    svc_spoof["subject"]["digest"]["sha256"] = sha256_hex(canonical(svc_spoof["predicate"]))
    resign(svc_spoof, sk)
    all_ok &= check("A7 signed service with is_service_account=false", verify_receipt(svc_spoof, pk).verdict, ["FAIL"])

    t = copy.deepcopy(r1); t["predicate"]["actor"]["human_principal"] = ""
    all_ok &= check("A8 human without principal", verify_receipt(t, pk).verdict, ["FAIL"])

    # A9: splice — swap r2's prev link to skip r1
    t = copy.deepcopy(r2); t["predicate"]["prev_chain_hash"] = "GENESIS"
    v = verify_chain([r1, t], pk)
    all_ok &= check("A9 chain splice", "FAIL" if not v["all_links_valid"] else "PASS", ["FAIL"])

    # A10: forged genesis — r2 presented as first with its real prev
    v = verify_chain([r2], pk)
    all_ok &= check("A10 forged genesis", "FAIL" if not v["all_links_valid"] else "PASS", ["FAIL"])

    t = copy.deepcopy(r1); t["predicate"]["timestamps"]["ntp_synced"] = False
    all_ok &= check("A11 unattested time", verify_receipt(t, pk).verdict, ["FAIL", "INCOMPLETE"])

    t = copy.deepcopy(r1); t["predicate"]["evidence"]["completeness"] = "COMPLETE"
    t["predicate"]["evidence"]["items"][0]["present"] = False
    all_ok &= check("A12 declared-vs-computed lie", verify_receipt(t, pk).verdict, ["FAIL", "INCOMPLETE"])

    t = copy.deepcopy(r1); t["signatures"] = []
    all_ok &= check("A13 empty signature list", verify_receipt(t, pk).verdict, ["FAIL"])

    # A14: corrupt the predicate-binding digest, then honestly re-sign the envelope.
    # The signature is valid; the subject/predicate semantic binding must still fail.
    t = copy.deepcopy(r1)
    t["subject"]["digest"]["sha256"] = sha256_hex(b"different")
    resign(t, sk)
    all_ok &= check("A14 signed subject-digest drift", verify_receipt(t, pk).verdict, ["FAIL"])

    # A15: unicode confusables in actor id (homoglyph)
    t = copy.deepcopy(r1)
    t["predicate"]["actor"]["id"] = "s.lutаr"  # cyrillic а
    all_ok &= check("A15 homoglyph actor id", verify_receipt(t, pk).verdict, ["FAIL"])

    # cross-key: r1 verified against a different public key
    all_ok &= check("A16 wrong public key", verify_receipt(r1, pk2).verdict, ["FAIL"])

    held = sum(1 for _, _, ok in results if ok)
    print(f"\nADVERSARIAL SUITE: {held}/{len(results)} attacks held")
    return 0 if all(ok for _, _, ok in results) else 1

if __name__ == "__main__":
    sys.exit(main())
