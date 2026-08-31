#!/usr/bin/env python3
"""PoC 6 — S2.5: FABRICATED evidence hash PASSes (present-flag-only law).

L1 is implemented as `all(i.get("present") for i in items)`. The verifier
never checks — and offline cannot check — that an item's sha256 corresponds
to any real artifact. A receipt attesting evidence that never existed
(sha256 of nothing) with present:true is COMPLETE and PASSes.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}

sk, pk = generate_keypair()
# "Evidence" whose hash matches no artifact that exists anywhere.
fabricated = [{"id": "deployment-log",
               "sha256": sha256_hex(b"this log was never produced by any system"),
               "present": True}]
receipt = build_receipt(action_id="a-777", subject_name="prod:svc", actor=HUMAN,
                        policy_decision=POL,
                        execution={"side_effect_class": "WRITE_IRREVERSIBLE",
                                   "status": "EXECUTED"},
                        evidence_items=fabricated, prev_chain_hash="GENESIS",
                        signing_key=sk)
v = verify_receipt(receipt, pk)
print("verdict:", v.verdict, "| completeness:", v.evidence_completeness)
print("reasons:", v.reasons)

# Unexpected PASS per S2.5: fabricated evidence (hash of nothing real) is
# accepted as COMPLETE — the law checks the flag, not the evidence.
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
