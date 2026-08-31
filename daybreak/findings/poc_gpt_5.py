#!/usr/bin/env python3
"""S2.8: human-principal spoofing — the WELL-FORMED spoof passes.

The suite (A6-A8) only tests MALFORMED spoofs, which fail because (a) the
signature breaks or (b) the syntactic L3 check fires. But L3 as implemented
in verify_receipt() is purely syntactic:

    if actor.get('type') == 'human' and (is_service_account is not False
        or auth_method == 'api_key' or not human_principal): ...

Nothing binds the signing key to any identity. A SERVICE workload signs a
receipt claiming a human principal (an exec), with all L3 fields
syntactically satisfied -> PASS. Additionally, the check fires ONLY on the
exact string 'human': an actor with no 'type', or type 'Human'/'HUMAN', or a
non-string type, bypasses L3 entirely while authenticating with api_key.
And the service-side law (is_service_account must be True) is not verified
at all at verify time (A7 only held via signature break).

Attacker model: the signing key belongs to the service (self-issued receipts);
build-time asserts are irrelevant to a hand-crafting insider.

Prints EXPLOIT-WORKS if any spoof verifies PASS.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

sk_service, pk_service = generate_keypair()   # the service's own signing key
NOW = "2026-08-30T12:00:00+00:00"
exploit = False

def hand_signed(pred):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "prod:svc",
                        "digest": {"sha256": sha256_hex(canonical(pred))}},
            "predicate": pred}
    stmt["signatures"] = [{"keyid": keyid(sk_service.public_key()),
                           "sig": sign(sk_service, PREDICATE_TYPE, canonical(stmt))}]
    return stmt

def base(actor):
    return {"action_id": "a-950", "actor": actor,
            "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"p")},
            "execution": {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
            "evidence": {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                         "completeness": "COMPLETE"},
            "timestamps": {"created": NOW, "executed": NOW, "ntp_synced": True},
            "prev_chain_hash": "GENESIS"}

# V1: service key signs receipt naming a HUMAN executive (well-formed L3).
r = hand_signed(base({"type": "human", "id": "s.lutar", "is_service_account": False,
                      "auth_method": "hardware_key",
                      "human_principal": "Stephen P. Lutar (fabricated attribution)"}))
v = verify_receipt(r, pk_service)
print(f"[V1] service key claims human exec (well-formed) -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V2: actor with NO 'type' key, api_key auth — L3 never fires.
r = hand_signed(base({"id": "agent://ci", "is_service_account": False,
                      "auth_method": "api_key"}))
v = verify_receipt(r, pk_service)
print(f"[V2] untyped actor + api_key auth                -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V3: case-variant type 'Human' with api_key and no principal — exact-match bypass.
r = hand_signed(base({"type": "Human", "id": "agent://ci", "is_service_account": True,
                      "auth_method": "api_key"}))
v = verify_receipt(r, pk_service)
print(f"[V3] type='Human' + api_key (case bypass)        -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

# V4: service actor with is_service_account=False (service half of L3 unchecked).
r = hand_signed(base({"type": "service", "id": "agent://ci",
                      "is_service_account": False, "auth_method": "api_key"}))
v = verify_receipt(r, pk_service)
print(f"[V4] service actor, is_service_account=false     -> {v.verdict}  reasons={v.reasons}")
if v.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
