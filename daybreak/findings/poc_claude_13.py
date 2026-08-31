#!/usr/bin/env python3
"""PoC 13 — S2.6: ALL-INCOMPLETE chain still reports all_links_valid=True.

verify_chain's ok-formula admits verdicts in ("PASS", "INCOMPLETE"). A chain
in which EVERY receipt is evidence-INCOMPLETE (missing evidence — the exact
data class the claim says must never pass) yields all_links_valid=True.
Any auditor automation keying on that field sees a green light on a bundle
with zero complete receipts.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
MISSING = [{"id": "log", "sha256": "", "present": False}]   # evidence absent

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=MISSING, prev_chain_hash="GENESIS", signing_key=sk)
r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=MISSING, prev_chain_hash=chain_hash(r1), signing_key=sk)

result = verify_chain([r1, r2], pk)
verdicts = [v["verdict"] for v in result["verdicts"]]
print("per-receipt verdicts:", verdicts)
print("all_links_valid:", result["all_links_valid"])

# Unexpected valid: a bundle whose every receipt is INCOMPLETE (evidence
# missing) still produces the verifier's truthy "valid" output field.
if result["all_links_valid"] is True and all(v == "INCOMPLETE" for v in verdicts):
    print("EXPLOIT-WORKS")
else:
    print("HELD")
