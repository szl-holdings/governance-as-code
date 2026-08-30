#!/usr/bin/env python3
"""hf_estate_apply.py — execute the HF estate remediation over REST (JSON commits).

Per Space: unprivate (if private) -> commit GOVERNANCE.md (rebuild trigger)
-> POST /restart. Every action is receipted into receipts/hf_ops_applied.jsonl.
Results land in data/hf_ops_results.json for the org card.

Auth: injected via HTTPS proxy (custom-cred:huggingface.co). No token in this file.
"""
import json, pathlib, subprocess, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import build_receipt, chain_hash, generate_keypair, sha256_hex, canonical

ROOT = pathlib.Path(__file__).resolve().parent.parent
INV = json.load(open(ROOT / "data" / "hf_space_inventory.json"))
OUT = ROOT / "receipts"; OUT.mkdir(exist_ok=True)
API = "https://huggingface.co/api"
DELAY = 0.4

CORE_MODELS = ["SZLHOLDINGS/SZL-Khipu-1.5B", "SZLHOLDINGS/SZL-Forge-1.5B-ReceiptAgent",
               "SZLHOLDINGS/A11OY-MINI", "SZLHOLDINGS/chaski",
               "SZLHOLDINGS/szl-receiptagent-qwen35-0.8b-v3"]

def stamp(space):
    return (f"# Governance stamp — {space['id']}\n\n"
            f"tier: {space['tier']}\n"
            f"truth_state: ATTESTED — estate remediation 2026-08-30\n"
            f"governance: https://github.com/szl-holdings/governance-as-code\n"
            f"verifier: https://huggingface.co/spaces/SZLHOLDINGS/governed-receipt-verifier\n\n"
            "## Estate model references (literal IDs for Hub backlinking)\n" +
            "".join(f"- {m}\n" for m in CORE_MODELS) +
            "\nVerification proves integrity & origin, never accuracy or performance.\n")

def call(method, url, payload=None):
    args = ["curl", "-sS", "-m", "40", "-w", "\n__HTTP:%{http_code}", "-X", method, url]
    if payload is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(payload)]
    r = subprocess.run(args, capture_output=True, text=True)
    body, _, tail = r.stdout.rpartition("\n__HTTP:")
    code = int(tail.strip() or 0)
    try:
        parsed = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        parsed = {"raw": body[:200]}
    return code, parsed

def main():
    spaces = INV["spaces"]
    sk, pk = generate_keypair()
    prev = "GENESIS"
    results = []
    log = open(OUT / "hf_ops_applied.jsonl", "w")
    for s in spaces:
        rid = s["id"]
        op = {"id": rid, "tier": s["tier"], "was_private": s["private"]}

        if s["private"]:
            code, body = call("POST", f"{API}/spaces/{rid}/settings", {"private": False})
            op["unprivate"] = "OK" if code in (200, 201, 204) else f"HTTP {code}: {str(body)[:100]}"
            time.sleep(DELAY)
        else:
            op["unprivate"] = "already public"

        code, body = call("POST", f"{API}/spaces/{rid}/commit/main?hot_reload=true",
                          {"summary": "governance stamp + estate model backlinks (rebuild)",
                           "files": [{"path": "GOVERNANCE.md", "content": stamp(s), "encoding": "utf-8"}]})
        op["governance_commit"] = "OK " + body.get("commitOid", "")[:8] if code == 200 else f"HTTP {code}: {str(body)[:100]}"
        time.sleep(DELAY)

        code, body = call("POST", f"{API}/spaces/{rid}/restart")
        op["restart"] = "OK" if code in (200, 201, 204) else f"HTTP {code}: {str(body)[:100]}"
        time.sleep(DELAY)

        all_ok = all(str(op[k]).startswith(("OK", "already")) for k in ("unprivate", "governance_commit", "restart"))
        op["result"] = "EXECUTED" if all_ok else "PARTIAL"
        r = build_receipt(
            action_id=f"hf-estate-apply:{rid}",
            subject_name=f"hf://spaces/{rid}",
            actor={"type": "human", "id": "stephenlutar2", "is_service_account": False,
                   "auth_method": "oidc", "human_principal": "Stephen P. Lutar"},
            policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"estate-ops-v1"),
                             "evaluated_at": "2026-08-30T23:15:00+00:00",
                             "human_approval": {"approver": "s.lutar", "at": "2026-08-30T23:15:00+00:00"}},
            execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED" if all_ok else "DENIED"},
            evidence_items=[{"id": "op-result", "sha256": sha256_hex(canonical(op)), "present": True}],
            prev_chain_hash=prev, signing_key=sk)
        prev = chain_hash(r)
        log.write(json.dumps(r) + "\n")
        results.append(op)
        print(f"  {rid:46s} {op['result']:8s} pub={op['unprivate'][:14]:14s} commit={op['governance_commit'][:20]:20s} restart={op['restart'][:20]}", flush=True)
    log.close()
    json.dump({"ran_at": "2026-08-30", "chain_tip": prev, "results": results},
              open(ROOT / "data" / "hf_ops_results.json", "w"), indent=1)
    n_pub = sum(1 for o in results if o["unprivate"].startswith(("OK", "already")))
    n_commit = sum(1 for o in results if o["governance_commit"].startswith("OK"))
    n_restart = sum(1 for o in results if o["restart"] == "OK")
    print(f"\ndone — public {n_pub}/45 · stamped {n_commit}/45 · restarted {n_restart}/45 · chain tip {prev[:16]}…")
    return 0

if __name__ == "__main__":
    sys.exit(main())
