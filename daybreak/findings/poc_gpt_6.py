#!/usr/bin/env python3
"""S2.9: time manipulation — backdated / future / garbage timestamps PASS.

verify_receipt() checks ONLY `timestamps.ntp_synced is True`. The created /
executed values are never parsed, never range-checked, never compared to the
chain, and rfc3161_token is never cryptographically validated. ntp_synced is
self-asserted by the signer (build_receipt hardcodes True), so the entire
time story is 'the signer pinky-swears'. A receipt executed in 1970, or in
2999, or 'not-a-date', with a fake TSA token, verifies PASS. And
verify_chain enforces NO temporal ordering: a receipt predating its parent
is fine.

Prints EXPLOIT-WORKS if any such receipt/chain verifies PASS/valid.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (generate_keypair, verify_receipt, verify_chain,
                         chain_hash, canonical, sha256_hex, sign, keyid,
                         PREDICATE_TYPE)

sk, pk = generate_keypair()
exploit = False

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}

def hand_signed(pred):
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "prod:svc",
                        "digest": {"sha256": sha256_hex(canonical(pred))}},
            "predicate": pred}
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, canonical(stmt))}]
    return stmt

def base(created, executed, extra_ts=None):
    ts = {"created": created, "executed": executed, "ntp_synced": True}
    ts.update(extra_ts or {})
    return {"action_id": "a-970", "actor": HUMAN,
            "policy_decision": {"result": "ALLOW", "policy_hash": sha256_hex(b"p")},
            "execution": {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
            "evidence": {"items": [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}],
                         "completeness": "COMPLETE"},
            "timestamps": ts, "prev_chain_hash": "GENESIS"}

cases = [
    ("V1 backdated to 1970",        base("1970-01-01T00:00:00+00:00", "1970-01-01T00:00:00+00:00")),
    ("V2 future year 2999",         base("2999-01-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00")),
    ("V3 non-ISO garbage strings",  base("not-a-date", "whenever")),
    ("V4 executed BEFORE created",  base("2026-08-30T12:00:00+00:00", "2020-01-01T00:00:00+00:00")),
    ("V5 fabricated rfc3161 token", base("2026-08-30T12:00:00+00:00", "2026-08-30T12:00:00+00:00",
                                         {"rfc3161_token": "AAAA-FAKE-TSA-TOKEN"})),
]
for name, pred in cases:
    v = verify_receipt(hand_signed(pred), pk)
    print(f"[{name}] -> {v.verdict}  reasons={v.reasons}")
    if v.verdict == "PASS":
        exploit = True

# V6: chain temporal inversion — child predates parent; links are fine.
r1 = hand_signed({**base("2026-08-30T12:00:00+00:00", "2026-08-30T12:00:00+00:00"),
                  "action_id": "t-1"})
r2pred = base("2019-01-01T00:00:00+00:00", "2019-01-01T00:00:00+00:00")  # 7 years earlier
r2pred["action_id"] = "t-2"
r2pred["prev_chain_hash"] = chain_hash(r1)
r2 = hand_signed(r2pred)
res = verify_chain([r1, r2], pk)
print(f"[V6 chain temporal inversion] all_links_valid={res['all_links_valid']} "
      f"verdicts={[x['verdict'] for x in res['verdicts']]}")
if res["all_links_valid"]:
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
