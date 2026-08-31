#!/usr/bin/env python3
"""S2.10: FlightRecorder crash-recovery and denial-of-receipt.

Format: 24-byte MAGIC, then [4-byte big-endian length][canonical JSON]...
No per-record integrity, no graceful torn-write handling.

Findings demonstrated:
  V1 TORN TAIL: a crash between the length prefix and the blob (or a
     truncated blob) makes read_all() raise — EVERY prior valid record
     becomes unreadable. One partial write bricks the whole log.
  V2 ZERO-LENGTH RECORD: a 4-byte zero prefix makes json.loads(b'') raise —
     same total loss.
  V3 SILENT TAIL TRUNCATION: an attacker (or disk issue) that removes whole
     trailing records leaves a perfectly readable prefix whose chain still
     verifies all_links_valid=True — deletion of recent receipts is
     undetectable (no tip attestation).

Prints EXPLOIT-WORKS if any of these behaviors is observed.
"""
import sys, os, tempfile
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (FlightRecorder, build_receipt, generate_keypair,
                         verify_chain, sha256_hex, chain_hash)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
exploit = False

def make_chain():
    r1 = build_receipt(action_id="f-001", subject_name="prod:svc", actor=HUMAN,
                       policy_decision=POL, execution=EXEC, evidence_items=EV,
                       prev_chain_hash="GENESIS", signing_key=sk)
    r2 = build_receipt(action_id="f-002", subject_name="prod:svc", actor=HUMAN,
                       policy_decision=POL, execution=EXEC, evidence_items=EV,
                       prev_chain_hash=chain_hash(r1), signing_key=sk)
    return r1, r2

with tempfile.TemporaryDirectory() as d:
    # V1: torn tail
    p = os.path.join(d, "fr1.bin")
    fr = FlightRecorder(p)
    r1, r2 = make_chain()
    fr.append(r1); fr.append(r2)
    with open(p, "ab") as f:                      # simulate crash mid-append:
        f.write((100).to_bytes(4, "big"))         # length prefix says 100...
        f.write(b'{"partial":')                   # ...but only 11 bytes land
    try:
        recs = fr.read_all()
        print(f"[V1] torn tail -> read_all returned {len(recs)} records (survived)")
    except Exception as e:
        print(f"[V1] torn tail -> read_all RAISED {type(e).__name__}: {e} "
              f"-- all valid records unreadable")
        exploit = True

    # V2: zero-length record
    p = os.path.join(d, "fr2.bin")
    fr = FlightRecorder(p)
    fr.append(r1)
    with open(p, "ab") as f:
        f.write((0).to_bytes(4, "big"))
    try:
        recs = fr.read_all()
        print(f"[V2] zero-length record -> read_all returned {len(recs)} (survived)")
    except Exception as e:
        print(f"[V2] zero-length record -> read_all RAISED {type(e).__name__}: {e}")
        exploit = True

    # V3: silent tail truncation
    p = os.path.join(d, "fr3.bin")
    fr = FlightRecorder(p)
    fr.append(r1)
    size_after_r1 = os.path.getsize(p)
    fr.append(r2)
    os.truncate(p, size_after_r1)                 # delete the last receipt
    try:
        recs = fr.read_all()
        res = verify_chain(recs, pk)
        print(f"[V3] tail truncation -> read_all OK ({len(recs)} records), "
              f"all_links_valid={res['all_links_valid']} -- deletion undetectable")
        if res["all_links_valid"] and len(recs) == 1:
            exploit = True
    except Exception as e:
        print(f"[V3] tail truncation -> read_all raised {e} (detectable at least)")

print("EXPLOIT-WORKS" if exploit else "HELD")
