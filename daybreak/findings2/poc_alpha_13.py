#!/usr/bin/env python3
"""poc_alpha_13 — F7 residual: the corruption guard catches ONLY
json.JSONDecodeError. A complete, well-framed record whose bytes are INVALID
UTF-8 (or otherwise undecodable) makes json.loads raise UnicodeDecodeError,
which propagates uncaught through BOTH read paths:

  * verify_integrity() CRASHES instead of reporting records/corruption —
    the exact F7 contract ("reports ... instead of raising") is still broken
    for this frame class;
  * read_all(tolerate_torn=True) — the sanctioned crash-recovery path —
    crashes too, so intact frames before the corrupt one are unreachable
    through the public API.

(v2.3 fixed the SILENT-shadowing half of this finding: read_all() now refuses
torn views loudly via MidFileCorruption, and verify_integrity reports offsets
for JSONDecodeError-class tears. This PoC targets the remaining exception-
type hole, deterministically: 0xFF is never valid UTF-8.)
"""
import sys, tempfile, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import FlightRecorder, build_receipt, generate_keypair, sha256_hex

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

path = tempfile.mktemp(suffix=".fr")
fr = FlightRecorder(path)
fr.append(r1)

# Complete frame, valid length prefix, deterministic invalid-UTF-8 payload.
bad = b"\xff\xff\xff\xff"
with open(path, "ab") as f:
    f.write(len(bad).to_bytes(4, "big")); f.write(bad)

vi_crash = ra_crash = None
try:
    print("[*] verify_integrity:", fr.verify_integrity())
except Exception as e:
    vi_crash = f"{type(e).__name__}: {e}"
    print(f"[!] verify_integrity RAISED instead of reporting: {vi_crash}")
try:
    fr.read_all(tolerate_torn=True)
    print("[*] read_all(tolerate_torn=True) returned frames")
except Exception as e:
    ra_crash = f"{type(e).__name__}: {e}"
    print(f"[!] read_all(tolerate_torn=True) RAISED: {ra_crash}")

os.unlink(path)
works = vi_crash is not None and "UnicodeDecodeError" in vi_crash and ra_crash is not None
print("EXPLOIT-WORKS" if works else "HELD")
