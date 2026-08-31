#!/usr/bin/env python3
"""PoC 4 — Torn write makes the WHOLE recorder unreadable (denial-of-receipt).

FlightRecorder.read_all has no per-record checksum and no truncation
tolerance: if a crash (or an attacker) leaves a length prefix promising bytes
that never landed, json.loads raises and recovery of EVERY record — including
fully durable, fsynced ones — fails. L5 promises PENDING_SYNC is "never
hidden"; a torn append hides everything. S2.10.
"""
import os, sys, tempfile
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (FlightRecorder, build_receipt, generate_keypair,
                         sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "READ_ONLY", "status": "EXECUTED"}

sk, pk = generate_keypair()
path = os.path.join(tempfile.mkdtemp(), "fr.bin")
fr = FlightRecorder(path)
r = build_receipt(action_id="a-001", subject_name="prod:svc", actor=HUMAN,
                  policy_decision=POL, execution=EXEC, evidence_items=EV,
                  prev_chain_hash="GENESIS", signing_key=sk)
fr.append(r)

# Simulate a crash mid-append: 4-byte length prefix for 64 bytes, then only
# 9 bytes of payload hit the platter.
with open(path, "ab") as f:
    f.write((64).to_bytes(4, "big"))
    f.write(b'{"partial"')

torn_crash = False
try:
    fr.read_all()  # should recover the durable record; instead it raises
except Exception:
    torn_crash = True

# Bonus variant: corrupt the magic -> AssertionError, same total loss.
path2 = os.path.join(tempfile.mkdtemp(), "fr2.bin")
fr2 = FlightRecorder(path2)
fr2.append(r)
with open(path2, "r+b") as f:
    f.write(b"X")
magic_crash = False
try:
    fr2.read_all()
except Exception:
    magic_crash = True

print("EXPLOIT-WORKS" if (torn_crash and magic_crash) else "HELD")
