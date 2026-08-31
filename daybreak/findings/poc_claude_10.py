#!/usr/bin/env python3
"""PoC 10 — S2.7: redaction_commitments are DEAD CODE at verify time.

build_receipt embeds `redaction_commitments` into the signed predicate, but
verify_receipt contains zero logic over them: no format check, no salt/hash
recomputation, no count vs evidence items, not even a presence note in
reasons. An auditor cannot detect that redaction also removed exculpatory
evidence; arbitrary garbage commitments PASS silently.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"redacted-body"), "present": True}]

sk, pk = generate_keypair()
receipt = build_receipt(
    action_id="a-314", subject_name="prod:svc", actor=HUMAN,
    policy_decision=POL,
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk,
    redaction_commitments=["GARBAGE", {"salt": "x", "sha256": "not-a-hash"}, 42])
v = verify_receipt(receipt, pk)
print("verdict:", v.verdict)
print("reasons:", v.reasons)
print("commitments embedded:", receipt["predicate"]["evidence"]["redaction_commitments"])

# Unexpected PASS: malformed/unverifiable redaction commitments are accepted
# without a single reason entry — the salted-commitment design is unenforced.
mentioned = any("redact" in r.lower() or "commit" in r.lower() for r in v.reasons)
if v.verdict == "PASS" and not mentioned:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
