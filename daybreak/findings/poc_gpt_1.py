#!/usr/bin/env python3
"""S2.1 probe: canonicalization confusion against canonical().

Attempts to find two semantically different receipt objects that serialize to
the same canonical bytes (which would let a tampered receipt keep a valid
signature). Also documents non-injectivity / non-JSON emissions of
canonical() (int-vs-str keys, tuple-vs-list, NaN/Infinity, surrogate crash,
mixed-key sort crash).

Prints EXPLOIT-WORKS if any collision yields an unexpected PASS on tampered
data, else HELD.
"""
import sys, json
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
import receipt_lib
from receipt_lib import (build_receipt, chain_hash, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

exploit = False

# --- Probe 1: int-key vs str-key collision (non-injective on Python types)
c_int = canonical({1: "x"})
c_str = canonical({"1": "x"})
print(f"[probe] canonical({{1:'x'}})={c_int}  canonical({{'1':'x'}})={c_str}  equal={c_int == c_str}")
# Same JSON semantics after round-trip -> not a usable semantic collision.

# --- Probe 2: tuple vs list
c_tup = canonical({"items": (1, 2)})
c_lst = canonical({"items": [1, 2]})
print(f"[probe] tuple-vs-list equal={c_tup == c_lst} ({c_tup!r})")

# --- Probe 3: NaN / Infinity emission (invalid strict JSON)
c_nan = canonical({"v": float("nan")})
c_inf = canonical({"v": float("inf")})
print(f"[probe] canonical NaN -> {c_nan} ; Infinity -> {c_inf}")
try:
    json.loads(c_nan, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("strict reject")))
    print("[probe] strict reparse of NaN: accepted")
except ValueError as e:
    print(f"[probe] strict reparse of NaN: REJECTED ({e}) -> cross-implementation divergence")

# --- Probe 4: mixed-type keys crash sort_keys
try:
    canonical({1: "a", "b": 2})
    print("[probe] mixed int/str keys: no crash")
except TypeError as e:
    print(f"[probe] mixed int/str keys: canonical() CRASHES ({e})")

# --- Probe 5: lone surrogate crashes utf-8 encode
try:
    canonical({"id": "\ud800"})
    print("[probe] lone surrogate: no crash")
except UnicodeEncodeError as e:
    print(f"[probe] lone surrogate: canonical() CRASHES ({type(e).__name__})")

# --- Probe 6: 0.0 vs -0.0 (equal-comparing values, different bytes)
print(f"[probe] canonical(0.0)={canonical(0.0)} canonical(-0.0)={canonical(-0.0)}")

# --- Exploit attempts: turn collisions into a PASS on tampered content.

# Attempt A: swap a string key for an int key post-signing (canonical-identical).
t = json.loads(json.dumps(r1))          # clean round-trip copy
# rebuild predicate evidence dict with an int key standing in for "present"
evil_items = [{0: True}]                 # not the same JSON; just confirm it can't pass
t2 = json.loads(json.dumps(r1))
t2["predicate"]["evidence"]["items"] = evil_items
v = verify_receipt(t2, pk)
print(f"[attempt] int-keyed evidence item tamper -> {v.verdict}")
if v.verdict == "PASS":
    exploit = True

# Attempt B: NaN smuggling — replace a numeric field with NaN post-signing.
t3 = json.loads(json.dumps(r1))
t3["predicate"]["execution"]["risk_score"] = float("nan")
v = verify_receipt(t3, pk)
print(f"[attempt] post-signing NaN insertion -> {v.verdict}")
if v.verdict == "PASS":
    exploit = True

# Attempt C: unicode normalization pair (NFC vs NFD) post-signing.
t4 = json.loads(json.dumps(r1))
t4["predicate"]["actor"]["id"] = "s.luta\u0301r"  # 'a' + combining acute (NFD), visually 's.lutár'
assert t4["predicate"]["actor"]["id"] != "s.lutar", "tamper must actually differ"
assert "s.luta\u0301r".encode() != "s.lutar".encode(), "canonical bytes must differ"
v = verify_receipt(t4, pk)
print(f"[attempt] NFD homoglyph post-signing -> {v.verdict}")
if v.verdict == "PASS":
    exploit = True

# Attempt D: float/int confusion: signed 1 vs presented 1.0 in a numeric field.
pred = dict(r1["predicate"]); pred["execution"] = dict(pred["execution"], retry=1)
stmt = {"predicateType": PREDICATE_TYPE,
        "subject": {"name": "prod:svc", "digest": {"sha256": sha256_hex(canonical(pred))}},
        "predicate": pred}
payload = canonical(stmt)
stmt["signatures"] = [{"keyid": keyid(sk.public_key()), "sig": sign(sk, PREDICATE_TYPE, payload)}]
t5 = json.loads(json.dumps(stmt))
t5["predicate"]["execution"]["retry"] = 1.0   # 1 -> 1.0 changes canonical bytes ("1" vs "1.0")
v = verify_receipt(t5, pk)
print(f"[attempt] int->float post-signing -> {v.verdict}")
if v.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
