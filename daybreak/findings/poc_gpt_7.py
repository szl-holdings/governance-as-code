#!/usr/bin/env python3
"""S2.3/S2.6: subject-digest declared-vs-computed lie (self-signed variant).

The DSSE statement binds subject.digest.sha256 = sha256(canonical(predicate))
at build time. verify_receipt() NEVER recomputes it. A14 in the suite only
catches POST-SIGNING drift (via the signature). But a signer who lies at
BUILD time — binding subject 'prod:svc' to a digest of completely different
content — passes cleanly. The auditor's core question ('does this receipt
attest THIS artifact?') is unanswerable from the verifier.

Prints EXPLOIT-WORKS if a receipt whose subject digest does not match its
predicate verifies PASS.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

sk, pk = generate_keypair()
NOW = "2026-08-30T12:00:00+00:00"
exploit = False

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
pred = {"action_id": "a-980", "actor": HUMAN,
        "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"p")},
        "execution": {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
        "evidence": {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                     "completeness": "COMPLETE"},
        "timestamps": {"created": NOW, "executed": NOW, "ntp_synced": True},
        "prev_chain_hash": "GENESIS"}

# V1: digest binds to attacker-chosen content, not the predicate.
lying_digest = sha256_hex(b"content the auditor thinks is being attested")
stmt = {"predicateType": PREDICATE_TYPE,
        "subject": {"name": "prod:svc", "digest": {"sha256": lying_digest}},
        "predicate": pred}
stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                       "sig": sign(sk, PREDICATE_TYPE, canonical(stmt))}]
assert stmt["subject"]["digest"]["sha256"] != sha256_hex(canonical(stmt["predicate"]))
v = verify_receipt(stmt, pk)
print(f"[V1] subject digest != hash(predicate) -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V2: subject.name claims a different artifact than the receipt is filed under.
stmt = {"predicateType": PREDICATE_TYPE,
        "subject": {"name": "prod:payments-db",          # receipt is about the DB...
                    "digest": {"sha256": sha256_hex(canonical(pred))}},
        "predicate": pred}                                # ...predicate touches svc
stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                       "sig": sign(sk, PREDICATE_TYPE, canonical(stmt))}]
v = verify_receipt(stmt, pk)
print(f"[V2] subject.name mismatch (never checked) -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
