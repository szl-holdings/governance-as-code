#!/usr/bin/env python3
"""PoC 2 — S2.4/S2.6: TAIL TRUNCATION of the chain validates clean.

verify_chain anchors only the FRONT of the chain (prev == "GENESIS").
Nothing pins the expected length or tip hash. Truncating the most recent
receipts (the ones an attacker most wants gone) yields all_links_valid=True.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash="GENESIS", signing_key=sk)
r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash=chain_hash(r1), signing_key=sk)
r3 = build_receipt(action_id="a-003-incriminating", subject_name="prod:svc",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash=chain_hash(r2), signing_key=sk)

full = verify_chain([r1, r2, r3], pk)
truncated = verify_chain([r1], pk)   # suppress r2 and r3 entirely
print("full chain all_links_valid:", full["all_links_valid"], "len:", full["length"])
print("truncated  all_links_valid:", truncated["all_links_valid"], "len:", truncated["length"])

# Unexpected valid: the ledger with the latest actions erased validates True
if truncated["all_links_valid"] is True:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
