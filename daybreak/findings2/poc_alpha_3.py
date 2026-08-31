#!/usr/bin/env python3
"""poc_alpha_3 — chain_id inheritance bug (FIXED IN v2.2 DURING THIS REVIEW).

Against the 01:31 v2 revision this printed EXPLOIT-WORKS: build_receipt
derived non-genesis chain_id as prev_chain_hash[:16], so every hop carried a
DIFFERENT id and verify_chain rejected the library's own honest 3-receipt
chain as "multiple chain_ids in one lineage — fork splice"
(all_links_valid=False with three individually-PASS receipts).

v2.2 (13:19) makes chain_id MANDATORY for non-genesis receipts and fails
loud at build time. This PoC now validates the fix: the insecure default is
gone, and an honest chain built with an inherited constant chain_id verifies.
Prints HELD when the fix is in place.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, verify_receipt, sha256_hex)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()

# 1) The insecure silent-derivation default must be gone:
fail_loud = False
try:
    r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                       policy_decision=POL,
                       execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                       evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
    build_receipt(action_id="a-002", subject_name="prod:svc", actor=SVC,
                  policy_decision=POL,
                  execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk)
    print("[!] non-genesis build without chain_id still silently derives (vulnerable)")
except ValueError as e:
    fail_loud = True
    print(f"[*] non-genesis build without chain_id fails loud: {e}")

# 2) An honest chain with a constant inherited chain_id must verify:
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
CID = r1["predicate"]["chain_id"]
r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk, chain_id=CID)
r3 = build_receipt(action_id="a-003", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash=chain_hash(r2), signing_key=sk, chain_id=CID)
out = verify_chain([r1, r2, r3], pk)
print(f"[*] honest 3-hop chain: all_links_valid={out['all_links_valid']}, "
      f"identity_bound={out['chain_identity_bound']}, ids={len({r['predicate']['chain_id'] for r in (r1,r2,r3)})}")

fixed = fail_loud and out["all_links_valid"] and out["chain_identity_bound"]
print("HELD" if fixed else "EXPLOIT-WORKS")
