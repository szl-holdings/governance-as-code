#!/usr/bin/env python3
"""poc_alpha_12 — the "genesis-derived" chain_id is deterministic over
predictable, attacker-known fields and contains NO randomness, key material,
environment label, or timestamp:

    seed = {action_id, actor, subject, policy_hash}   (genesis only)

Two INDEPENDENT chains whose genesis receipts record the same action — the
same scheduled deploy fired in staging and prod, a chain restarted after
wipe, a deliberately cloned genesis — emit the IDENTICAL chain_id under
DIFFERENT keys at DIFFERENT times. The F6 "lineage identifier" cannot
identify a lineage: an auditor comparing two presented chains by chain_id
cannot tell they are distinct histories, and a verifier collecting chain_ids
sees one identity where two exist.
"""
import sys, time
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, sha256_hex)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def genesis(sk, note):
    return build_receipt(action_id="deploy-001", subject_name="prod:svc", actor=SVC,
                         policy_decision=POL,
                         execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED",
                                    "note": note},
                         evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

skA, pkA = generate_keypair()
skB, pkB = generate_keypair()
gA = genesis(skA, "staging run")
time.sleep(0.01)
gB = genesis(skB, "prod run")  # different key, different time, SAME seed fields

idA, idB = gA["predicate"]["chain_id"], gB["predicate"]["chain_id"]
hA, hB = chain_hash(gA), chain_hash(gB)
print(f"[*] chain A (staging, key A): chain_id={idA}  hash={hA[:16]}…")
print(f"[*] chain B (prod,    key B): chain_id={idB}  hash={hB[:16]}…")
print(f"[*] chain_ids collide: {idA == idB}; receipts are distinct: {hA != hB}")

outA = verify_chain([gA], pkA)
outB = verify_chain([gB], pkB)
print(f"[*] verify_chain A: identity_bound={outA['chain_identity_bound']}; "
      f"B: identity_bound={outB['chain_identity_bound']} — same 'identity' for two lineages")

# Even a mixed presentation [gA] + [receipt from B's chain] cannot be flagged
# by chain_id when the ids collide; only prev_chain_hash linkage catches it,
# and B's genuine continuation links to gB, so the splice FAILs only because
# of hashes — the chain_id layer adds ZERO discrimination here.
works = (idA == idB) and (hA != hB) and outA["chain_identity_bound"] and outB["chain_identity_bound"]
print("EXPLOIT-WORKS" if works else "HELD")
