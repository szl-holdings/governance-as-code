#!/usr/bin/env python3
"""S2.5: evidence-completeness gaming — FABRICATED evidence passes.

L1 claims: 'missing evidence => INCOMPLETE, never PASS'. verify_receipt()
computes completeness as `items and all(i.get('present') for i in items)` —
purely syntactic. An item with present:true and a sha256 that matches NOTHING
real (or no sha256 at all) is indistinguishable from real evidence.

Attacker model: the service holding the signing key (insider / compromised
workload) mints a receipt for an action whose 'audit log' was never produced.

Prints EXPLOIT-WORKS if any fabricated-evidence receipt verifies PASS.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import build_receipt, generate_keypair, verify_receipt, sha256_hex

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
exploit = False

# V1: present:true with a sha256 that corresponds to NO real artifact.
r1 = build_receipt(action_id="a-900", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC,
                   evidence_items=[{"id": "audit-log",
                                    "sha256": sha256_hex(b"this log was never written"),
                                    "present": True}],
                   prev_chain_hash="GENESIS", signing_key=sk)
v1 = verify_receipt(r1, pk)
print(f"[V1] fabricated sha256 (no real artifact) -> {v1.verdict}  reasons={v1.reasons}")
if v1.verdict == "PASS":
    exploit = True

# V2: present:true with NO sha256 field at all — a content-free 'evidence' item.
r2 = build_receipt(action_id="a-901", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC,
                   evidence_items=[{"id": "audit-log", "present": True}],
                   prev_chain_hash="GENESIS", signing_key=sk)
v2 = verify_receipt(r2, pk)
print(f"[V2] evidence item with no hash at all    -> {v2.verdict}  reasons={v2.reasons}")
if v2.verdict == "PASS":
    exploit = True

# V3: present is a truthy non-boolean ("yes", 1) — type confusion on the flag.
r3 = build_receipt(action_id="a-902", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC,
                   evidence_items=[{"id": "audit-log", "sha256": "", "present": "yes"}],
                   prev_chain_hash="GENESIS", signing_key=sk)
v3 = verify_receipt(r3, pk)
print(f"[V3] present='yes' (truthy string), empty sha256 -> {v3.verdict}")
if v3.verdict == "PASS":
    exploit = True

# V4: same artifact hash reused across N 'independent' evidence items.
r4 = build_receipt(action_id="a-903", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC,
                   evidence_items=[{"id": f"log-{i}", "sha256": sha256_hex(b"x"), "present": True}
                                   for i in range(5)],
                   prev_chain_hash="GENESIS", signing_key=sk)
v4 = verify_receipt(r4, pk)
print(f"[V4] one real artifact counted as 5 evidence items -> {v4.verdict}")
if v4.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
