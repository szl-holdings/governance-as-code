#!/usr/bin/env python3
"""poc_alpha_10 — F4 strict-boolean gate (FIXED IN v2.3 DURING THIS REVIEW).

Against v2.2 this printed EXPLOIT-WORKS: `i.get("present") not in (True,
False)` uses ==, so present: 1 / present: 0 (the exact v1 attack values)
passed the "strict boolean" check with zero reasons, and build (truthiness)
vs verify (is-True) disagreed on the same receipt's completeness.

v2.3 uses `type(...) is not bool` on the verify side and asserts
`type(...) is bool` on the build side. This PoC attacks the VERIFY side with
hand-built, honestly signed receipts carrying present: 1 and present: 0 —
the values must now be hard-failed. Prints HELD when they are.
"""
import sys, copy
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def resign(stmt, sk):
    stmt["subject"]["digest"]["sha256"] = sha256_hex(canonical(stmt["predicate"]))
    payload = canonical({k: v for k, v in stmt.items() if k != "signatures"})
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
held = []
for bad in (1, 0, 1.0, "yes"):
    r = build_receipt(action_id="a-101", subject_name="prod:svc", actor=SVC,
                      policy_decision=POL,
                      execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                      evidence_items=copy.deepcopy(EV), prev_chain_hash="GENESIS", signing_key=sk)
    # signer-adversary: swap in the non-boolean present value and re-sign
    r["predicate"]["evidence"]["items"][0]["present"] = bad
    resign(r, sk)
    v = verify_receipt(r, pk)
    ok = v.verdict == "FAIL" and any("strict boolean" in x for x in v.reasons)
    held.append(ok)
    print(f"[*] present={bad!r:6} -> {v.verdict} (strict-boolean reason: {any('strict boolean' in x for x in v.reasons)})")

print("HELD" if all(held) else "EXPLOIT-WORKS")
