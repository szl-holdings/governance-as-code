#!/usr/bin/env python3
"""S2.6: verifier-output manipulation — GUTTED receipt verifies PASS.

verify_receipt() validates exactly four things: signature, the human-actor
half of L3 (only when actor.type == 'human'), ntp_synced, and evidence
completeness. It NEVER requires the presence of actor, action_id,
policy_decision, execution, or prev_chain_hash. A hand-crafted receipt that
omits the entire actor block — an action attributable to NOBODY — verifies
PASS when signed by the trusted key. build_receipt() enforces these fields
at construction, but verification is the auditor-side control and it has no
schema validation.

Also: a missing declared 'completeness' field only appends an advisory
reason; the verdict is still PASS.

Prints EXPLOIT-WORKS if a gutted receipt verifies PASS.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

sk, pk = generate_keypair()
NOW = "2026-08-30T12:00:00+00:00"
exploit = False

def hand_signed(pred):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "prod:svc",
                        "digest": {"sha256": sha256_hex(canonical(pred))}},
            "predicate": pred}
    payload = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

EV = {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
      "completeness": "COMPLETE", "redaction_commitments": []}
TS = {"created": NOW, "executed": NOW, "ntp_synced": True}

# V1: NO actor, NO action_id, NO policy_decision, NO execution, NO prev_chain_hash.
r = hand_signed({"evidence": EV, "timestamps": TS})
v = verify_receipt(r, pk)
print(f"[V1] receipt with no actor/action/policy/execution -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V2: gutted AND declared completeness field absent (mismatch is advisory only).
r = hand_signed({"evidence": {"items": EV["items"]}, "timestamps": TS})
v = verify_receipt(r, pk)
print(f"[V2] V1 + missing declared completeness          -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V3: no predicate.evidence key at all is INCOMPLETE (sanity), but
#     actor-less + policy-less + execution-less with evidence present is PASS.
r = hand_signed({"actor": {"type": "service", "id": "agent://deploy",
                           "is_service_account": True, "auth_method": "mtls"},
                 "evidence": EV, "timestamps": TS})
v = verify_receipt(r, pk)
print(f"[V3] no action_id/policy/execution (actor ok)    -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
