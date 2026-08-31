#!/usr/bin/env python3
"""PoC 2 — Cross-chain replay: no chain identity binding.

Receipts carry no chain ID and every chain starts from the literal string
"GENESIS". Two independent chains under the same key are indistinguishable to
the verifier: a receipt (or a whole chain) from chain B verifies as valid in
the context of chain A. The suite's A9/A10 only test splices and forged
genesis WITHIN one chain; replay ACROSS chains is untested. S2.3 / S2.4.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, verify_receipt, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "READ_ONLY", "status": "EXECUTED"}

sk, pk = generate_keypair()

# Chain A — the chain the auditor intends to verify
a1 = build_receipt(action_id="chainA-001", subject_name="prod:svc-a", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash="GENESIS", signing_key=sk)
a2 = build_receipt(action_id="chainA-002", subject_name="prod:svc-a", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash=chain_hash(a1), signing_key=sk)

# Chain B — a different chain (different action ids / subjects), same key,
# also rooted at the literal "GENESIS"
b1 = build_receipt(action_id="chainB-001", subject_name="prod:svc-b", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash="GENESIS", signing_key=sk)
b2 = build_receipt(action_id="chainB-002", subject_name="prod:svc-b", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash=chain_hash(b1), signing_key=sk)

# 1) A receipt that was never part of chain A verifies PASS standalone —
#    verify_receipt has no chain-context parameter at all.
standalone_replay_pass = verify_receipt(b1, pk).verdict == "PASS"

# 2) Wholesale substitution: the auditor is handed chain B while expecting
#    chain A. Nothing in the output reveals the swap — no chain identity
#    is committed anywhere.
sub = verify_chain([b1, b2], pk)
substitution_valid = sub["all_links_valid"] is True

print("EXPLOIT-WORKS" if (standalone_replay_pass and substitution_valid) else "HELD")
