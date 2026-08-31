#!/usr/bin/env python3
"""poc_alpha_14 — F7 contract breach: verify_integrity() promises to "report
records/corruption/truncation INSTEAD OF RAISING". But _frames() still does
`raise ValueError("flight recorder magic mismatch")` when the header is
corrupted — and header corruption is the single most common real corruption
(start of file takes the write hits). One flipped byte in the first 24 bytes
and the 'integrity report' is an exception; every record, torn or not, is
unverifiable. Same for a zeroed/truncated-to-empty file.
"""
import sys, tempfile, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import FlightRecorder, build_receipt, generate_keypair, sha256_hex

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
sk, pk = generate_keypair()
r = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                  policy_decision=POL,
                  execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

raised_magic = raised_empty = False

path = tempfile.mktemp(suffix=".a11yfr")
fr = FlightRecorder(path)
fr.append(r)
data = bytearray(open(path, "rb").read())
data[0] ^= 0xFF                      # one-bit header corruption
open(path, "wb").write(bytes(data))
try:
    print("[*] corrupted-magic verify_integrity:", fr.verify_integrity())
except Exception as e:
    raised_magic = True
    print(f"[!] verify_integrity RAISED on magic corruption: {type(e).__name__}: {e}")

path2 = tempfile.mktemp(suffix=".a11yfr")
fr2 = FlightRecorder(path2)
fr2.append(r)
open(path2, "wb").close()            # truncate to zero bytes
try:
    print("[*] emptied-file verify_integrity:", fr2.verify_integrity())
except Exception as e:
    raised_empty = True
    print(f"[!] verify_integrity RAISED on emptied file: {type(e).__name__}: {e}")

os.unlink(path); os.unlink(path2)
print("EXPLOIT-WORKS" if (raised_magic and raised_empty) else "HELD")
