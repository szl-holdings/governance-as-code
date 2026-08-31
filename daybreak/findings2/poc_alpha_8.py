#!/usr/bin/env python3
"""poc_alpha_8 — governance self-contradiction DENY+EXECUTED (FIXED IN v2.3
DURING THIS REVIEW).

Against v2.2 this printed EXPLOIT-WORKS: the stock builder minted
policy DENY + status EXECUTED and verify_receipt PASSed it with empty
reasons. v2.3 adds the cross-check on BOTH sides:
  * build_receipt asserts DENY => status DENIED and EXECUTED => result ALLOW;
  * verify_receipt hard-fails "policy DENY with status EXECUTED".
This PoC now attacks the VERIFY side directly with a hand-built, honestly
signed receipt (signer-adversary model — build asserts are irrelevant to an
attacker with the key, and vanish under python -O anyway). Prints HELD when
the verify-side check rejects it.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def resign(stmt, sk):
    stmt["subject"]["digest"]["sha256"] = sha256_hex(canonical(stmt["predicate"]))
    payload = canonical({k: v for k, v in stmt.items() if k != "signatures"})
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
r = build_receipt(action_id="a-666", subject_name="prod:payments", actor=SVC,
                  policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")},
                  execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

# Signer-adversary: flip the policy result to DENY, keep EXECUTED, re-sign.
r["predicate"]["policy_decision"]["result"] = "DENY"
resign(r, sk)

v = verify_receipt(r, pk)
print(f"[*] hand-signed DENY+EXECUTED: verdict={v.verdict} reasons={v.reasons}")

held = v.verdict == "FAIL" and any("DENY" in x for x in v.reasons)
print("HELD" if held else "EXPLOIT-WORKS")
