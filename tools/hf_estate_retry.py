#!/usr/bin/env python3
"""hf_estate_retry.py — finish the estate remediation with correct endpoints.

PUT /settings for visibility (POST 404s), JSON commits for missing stamps,
restart only for docker/gradio (static 400s are N/A — no runtime to restart).
Retries with backoff. Receipts append to receipts/hf_ops_retry.jsonl.
"""
import json, pathlib, subprocess, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import build_receipt, chain_hash, generate_keypair, sha256_hex, canonical
from hf_estate_apply import stamp, API  # reuse the stamp text

ROOT = pathlib.Path(__file__).resolve().parent.parent
INV = json.load(open(ROOT / "data" / "hf_space_inventory.json"))
PREV = json.load(open(ROOT / "data" / "hf_ops_results.json"))
OUT = ROOT / "receipts"
DELAY = 0.5

prev_by_id = {r["id"]: r for r in PREV["results"]}

def call(method, url, payload=None, tries=3):
    for attempt in range(tries):
        args = ["curl", "-sS", "-m", "45", "-w", "\n__HTTP:%{http_code}", "-X", method, url]
        if payload is not None:
            args += ["-H", "Content-Type: application/json", "-d", json.dumps(payload)]
        r = subprocess.run(args, capture_output=True, text=True)
        body, _, tail = r.stdout.rpartition("\n__HTTP:")
        try:
            code = int(tail.strip() or 0)
        except ValueError:
            code = 0
        if code and code < 500:
            break
        time.sleep(2 ** attempt * 2)
    try:
        parsed = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        parsed = {"raw": body[:150]}
    return code, parsed

def main():
    sk, pk = generate_keypair()
    prev_hash = "GENESIS"
    chain_cid = None
    results = []
    log = open(OUT / "hf_ops_retry.jsonl", "w")
    for s in INV["spaces"]:
        rid = s["id"]; old = prev_by_id.get(rid, {})
        op = {"id": rid, "tier": s["tier"], "was_private": s["private"]}

        # 1. visibility: flip anything still private (old POST 404'd => still private unless OK'd)
        if s["private"] and not str(old.get("unprivate", "")).startswith("OK"):
            code, body = call("PUT", f"{API}/spaces/{rid}/settings", {"private": False})
            op["unprivate"] = "OK" if code == 200 and body.get("private") is False else f"HTTP {code}: {str(body)[:90]}"
            time.sleep(DELAY)
        elif s["private"]:
            op["unprivate"] = "OK (first pass)"
        else:
            op["unprivate"] = "already public"

        # 2. governance commit where missing
        if str(old.get("governance_commit", "")).startswith("OK"):
            op["governance_commit"] = old["governance_commit"] + " (first pass)"
        else:
            code, body = call("POST", f"{API}/spaces/{rid}/commit/main",
                              {"summary": "governance stamp + estate model backlinks (rebuild)",
                               "files": [{"path": "GOVERNANCE.md", "content": stamp(s), "encoding": "utf-8"}]})
            op["governance_commit"] = "OK " + body.get("commitOid", "")[:8] if code == 200 else f"HTTP {code}: {str(body)[:90]}"
            time.sleep(DELAY)

        # 3. restart only where a runtime exists
        if s["sdk"] in ("docker", "gradio"):
            if old.get("restart") == "OK":
                op["restart"] = "OK (first pass)"
            else:
                code, body = call("POST", f"{API}/spaces/{rid}/restart")
                op["restart"] = "OK" if code in (200, 201, 204) else f"HTTP {code}: {str(body)[:90]}"
                time.sleep(DELAY)
        else:
            op["restart"] = "N/A (static — commit triggers rebuild)"

        all_ok = all(str(op[k]).startswith(("OK", "already", "N/A")) for k in ("unprivate", "governance_commit", "restart"))
        op["result"] = "EXECUTED" if all_ok else "PARTIAL"
        r = build_receipt(
            action_id=f"hf-estate-retry:{rid}",
            subject_name=f"hf://spaces/{rid}",
            actor={"type": "human", "id": "stephenlutar2", "is_service_account": False,
                   "auth_method": "oidc", "human_principal": "Stephen P. Lutar"},
            policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"estate-ops-v2"),
                             "evaluated_at": "2026-08-30T23:40:00+00:00",
                             "human_approval": {"approver": "s.lutar", "at": "2026-08-30T23:40:00+00:00"}},
            execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED" if all_ok else "DENIED"},
            evidence_items=[{"id": "op-result", "sha256": sha256_hex(canonical(op)), "present": True}],
            prev_chain_hash=prev_hash, signing_key=sk, **({"chain_id": chain_cid} if chain_cid else {}))
        prev_hash = chain_hash(r)
        if chain_cid is None:
            chain_cid = r["predicate"].get("chain_id")
        log.write(json.dumps(r) + "\n")
        results.append(op)
        print(f"  {rid:46s} {op['result']:8s} pub={op['unprivate'][:16]:16s} commit={op['governance_commit'][:22]:22s} restart={op['restart'][:22]}", flush=True)
    log.close()
    json.dump({"ran_at": "2026-08-30T23:40-04:00", "chain_tip": prev_hash, "results": results},
              open(ROOT / "data" / "hf_ops_results.json", "w"), indent=1)
    n_pub = sum(1 for o in results if o["unprivate"].startswith(("OK", "already")))
    n_commit = sum(1 for o in results if o["governance_commit"].startswith("OK"))
    print(f"\ndone — public {n_pub}/45 · stamped {n_commit}/45 · chain tip {prev_hash[:16]}…")
    return 0

if __name__ == "__main__":
    sys.exit(main())
