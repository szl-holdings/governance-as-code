#!/usr/bin/env python3
"""credo_loop.py — one harness loop: Credo outcomes → SZL receipts.

Simulates the four Credo checkpoints Credo documents
(session start, prompt, before tool, after tool) plus a later allow
that must not lift a prior block.

Does not call Claude Code. Does not claim a live Credo integration.
MEASURED: this process. REPORTED: Credo's four outcomes.
"""
from __future__ import annotations
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from credo_governor import map_credo, compose
from receipt_lib import (
    build_receipt, chain_hash, generate_keypair, keyid, verify_receipt, sha256_hex,
)

HUMAN = {
    "type": "human",
    "id": "s.lutar",
    "is_service_account": False,
    "auth_method": "hardware_key",
    "human_principal": "Stephen P. Lutar",
}
AGENT = {
    "type": "service",
    "id": "agent://claude-code",
    "is_service_account": True,
    "auth_method": "api_key",
}


def emit(sk, prev, action_id, actor, result, status, side):
    ev = [{"id": "governor-trace", "sha256": sha256_hex(action_id.encode()), "present": True}]
    rec = build_receipt(
        action_id=action_id,
        subject_name="harness:claude-code-sim",
        actor=actor,
        policy_decision={
            "result": "ALLOW" if result == "ALLOW" else "DENY",
            "policy_hash": sha256_hex(b"szl-credo-map:v1"),
            "evaluated_at": "2026-09-04T16:00:00+00:00",
        },
        execution={"side_effect_class": side, "status": "EXECUTED" if status == "EXECUTED" else "DENIED"},
        evidence_items=ev,
        prev_chain_hash=prev,
        signing_key=sk,
    )
    return rec


def main() -> int:
    sk, pk = generate_keypair()
    print(f"governor boot — key {keyid(pk)}  Λ=ADVISORY")

    events = [
        ("session_start", "allow", HUMAN, "READ_ONLY"),
        ("prompt", "advise", AGENT, "READ_ONLY"),
        ("before_tool_destructive", "block", AGENT, "WRITE_IRREVERSIBLE"),
        ("after_block_allow_attempt", "allow", AGENT, "WRITE_IRREVERSIBLE"),
        ("escalate_secret_read", "escalate", AGENT, "READ_ONLY"),
    ]

    prior = None
    prev = "GENESIS"
    chain = []
    for name, credo, actor, side in events:
        if prior is None:
            gov = map_credo(
                credo,
                human_principal="s.lutar" if credo == "escalate" else None,
            )
        else:
            gov = compose(
                prior,
                credo,
                human_principal="s.lutar" if credo == "escalate" else None,
            )
        rec = emit(sk, prev, name, actor, gov.szl, gov.execution_status, side)
        v = verify_receipt(rec, pk)
        print(
            f"{name:28s} credo={credo:8s} szl={gov.szl:6s} "
            f"exec={gov.may_execute!s:5s} receipt={v.verdict}"
        )
        assert v.verdict == "PASS", v
        if name == "after_block_allow_attempt":
            assert gov.szl == "DENY" and gov.may_execute is False
        if name == "prompt":
            assert gov.szl == "ADVISE" and gov.may_execute is False
        prior = gov
        prev = chain_hash(rec)
        chain.append({"event": name, "governor": gov.__dict__, "receipt_verdict": v.verdict})

    out = ROOT / "receipts"
    out.mkdir(exist_ok=True)
    (out / "credo_loop.json").write_text(json.dumps(chain, indent=2, default=str))
    print(f"wrote {out / 'credo_loop.json'} — deny survived the later allow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
