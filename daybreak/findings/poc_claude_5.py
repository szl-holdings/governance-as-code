#!/usr/bin/env python3
"""PoC 5 — S2.6/S2.8: MISSING actor (and other mandatory fields) still PASSes.

verify_receipt enforces presence of NOTHING except: a valid signature,
non-empty evidence items with present=true, and ntp_synced=true. The L3
check is guarded by `actor.get("type") == "human"`, so a receipt with NO
actor key at all skips every identity law and PASSes — a "governed action"
with zero accountable principal. Same for action_id/policy_decision/execution.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def sign_statement(sk, predicate, subject_name="prod:svc"):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": subject_name,
                        "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    payload = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
# A receipt for a "governed action" with NO actor, NO action_id,
# NO policy_decision, NO execution — nothing but evidence + timestamps.
predicate = {
    "evidence": {"items": EV, "completeness": "COMPLETE", "redaction_commitments": []},
    "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                   "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
}
receipt = sign_statement(sk, predicate)
v = verify_receipt(receipt, pk)
print("verdict:", v.verdict, "| signature_valid:", v.signature_valid)
print("reasons:", v.reasons)
print("predicate keys present:", sorted(receipt["predicate"].keys()))

# Unexpected PASS: receipt with no actor/action/policy/execution is
# "incomplete" by any reading of the schema, yet the verifier PASSes it.
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
