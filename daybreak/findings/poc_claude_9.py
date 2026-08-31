#!/usr/bin/env python3
"""PoC 9 — S2.10: TORN WRITE makes the ENTIRE FlightRecorder ledger unreadable.

FlightRecorder.append is crash-safe only for itself; read_all has NO
crash-recovery: it does `json.loads(f.read(n))` with no short-read check.
A crash (or attacker) that leaves a partial trailing record — e.g. the
4-byte length written, blob truncated — makes read_all() raise, denying
verification of EVERY receipt, including the intact ones before the tear.
"""
import os, sys, tempfile
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (FlightRecorder, build_receipt, generate_keypair,
                         verify_receipt, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
path = os.path.join(tempfile.mkdtemp(), "ledger.fr")
fr = FlightRecorder(path)

r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
fr.append(r1)

# sanity: intact ledger reads back and r1 verifies
assert verify_receipt(fr.read_all()[0], pk).verdict == "PASS"

# simulate crash mid-append: length prefix says 512 bytes, only 8 ever landed
with open(path, "ab") as f:
    f.write((512).to_bytes(4, "big"))
    f.write(b'{"predic')          # torn blob — power lost here
    f.flush(); os.fsync(f.fileno())

denied = False
try:
    fr.read_all()                  # must recover r1; instead it dies
except Exception as e:
    denied = True
    print("read_all() raised:", type(e).__name__, "-", str(e)[:80])

# Unexpected denial: one torn tail record makes even the intact, verifiable
# receipt r1 unreadable — no partial recovery, no truncation handling.
if denied:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
