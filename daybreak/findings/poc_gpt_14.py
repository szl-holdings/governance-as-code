#!/usr/bin/env python3
"""S2.7: redaction vs integrity — the salted-hash-commitment design gives the
auditor ZERO assurance. verify_receipt() never reads redaction_commitments:
not their presence, not their format, not their correspondence to evidence
items. So a redactor can (a) drop exculpatory evidence items entirely, (b)
attach garbage commitments that commit to nothing, and the receipt verifies
PASS with no signal that redaction even occurred. The commitments are also
self-asserted by the same signer being audited — there is no third-party
binding, no salt disclosure protocol, no way to distinguish 'redacted 1 of 3'
from 'never had 3'.

Prints EXPLOIT-WORKS if a receipt with exculpatory evidence silently removed
and garbage commitments verifies PASS.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}

sk, pk = generate_keypair()
exploit = False

# Original (truthful) evidence set: 3 items, one of them exculpatory for the
# affected user / incriminating context for the operator.
full_items = [
    {"id": "policy-input",   "sha256": sha256_hex(b"policy-input-bytes"),   "present": True},
    {"id": "exculpatory-log","sha256": sha256_hex(b"user-consent-record"),  "present": True},
    {"id": "approval",       "sha256": sha256_hex(b"approval-bytes"),       "present": True},
]
# V1: redactor drops the exculpatory item, keeps 2, attaches garbage
# commitments that commit to nothing (not even salted hashes of real bytes).
redacted = build_receipt(action_id="a-600", subject_name="prod:svc", actor=HUMAN,
                         policy_decision=POL, execution=EXEC,
                         evidence_items=[full_items[0], full_items[2]],
                         prev_chain_hash="GENESIS", signing_key=sk,
                         redaction_commitments=["sha256:deadbeefcafe",
                                                "sha256:000000000000"])
v = verify_receipt(redacted, pk)
commitments_checked = any("redact" in r.lower() for r in v.reasons)
print(f"[V1] exculpatory item dropped + garbage commitments -> {v.verdict}")
print(f"     verifier emitted redaction-related reason: {commitments_checked}  reasons={v.reasons}")
if v.verdict == "PASS" and not commitments_checked:
    exploit = True

# V2: commitments present but evidence claims items were NEVER redacted —
# commitments are pure decoration; nothing cross-checks them.
r2 = build_receipt(action_id="a-601", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=full_items,
                   prev_chain_hash="GENESIS", signing_key=sk,
                   redaction_commitments=["not-even-a-hash"])
v2 = verify_receipt(r2, pk)
print(f"[V2] malformed commitment string accepted -> {v2.verdict}  reasons={v2.reasons}")
if v2.verdict == "PASS":
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
