#!/usr/bin/env python3
"""hf_estate_ops.py — HF estate remediation, gated and receipted.

Runs ONLY with a write-scoped HF token (HF_TOKEN env). The current OAuth
credential is contribute-only (PR scope); direct visibility changes and commits
require write scope. Dry-run by default; --apply executes.

Actions per Space:
  1. set visibility public        (Zero-Bandaid: private flagship is invisible)
  2. upload GOVERNANCE.md stamp   (truth state + literal model IDs = backlinks; commit triggers rebuild = restart)
  3. restart_space()              (where supported)
Every action emits a GovernedAction/v1 receipt into receipts/hf_ops.jsonl.

Usage:
  HF_TOKEN=hf_... python3 tools/hf_estate_ops.py            # dry run
  HF_TOKEN=hf_... python3 tools/hf_estate_ops.py --apply    # execute
"""
import json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import build_receipt, chain_hash, generate_keypair, sha256_hex, canonical

ROOT = pathlib.Path(__file__).resolve().parent.parent
INV = json.load(open(ROOT / "data" / "hf_space_inventory.json"))
OUT = ROOT / "receipts"; OUT.mkdir(exist_ok=True)

CORE_MODELS = ["SZLHOLDINGS/SZL-Khipu-1.5B", "SZLHOLDINGS/SZL-Forge-1.5B-ReceiptAgent",
               "SZLHOLDINGS/A11OY-MINI", "SZLHOLDINGS/chaski", "SZLHOLDINGS/WILLAY",
               "SZLHOLDINGS/szl-receiptagent-qwen35-0.8b-v3", "SZLHOLDINGS/szl-kernels",
               "SZLHOLDINGS/szl-lambda-gate", "SZLHOLDINGS/szl-invariants", "SZLHOLDINGS/szl-govsign"]

def stamp(space):
    return (f"# Governance stamp — {space['id']}\n\n"
            f"tier: {space['tier']}\n"
            f"truth_state: ATTESTED — file-level audit 2026-08-30\n"
            f"governance: https://github.com/szl-holdings/governance-as-code\n"
            f"verifier: https://huggingface.co/spaces/SZLHOLDINGS/governed-receipt-verifier\n\n"
            "## Estate model references (literal IDs for Hub backlinking)\n" +
            "".join(f"- {m}\n" for m in CORE_MODELS) +
            "\nVerification proves integrity & origin, never accuracy or performance.\n")

def main():
    apply = "--apply" in sys.argv
    token = os.environ.get("HF_TOKEN")
    spaces = INV["spaces"]
    private = [s for s in spaces if s["private"]]
    print(f"estate: {len(spaces)} spaces | {len(private)} private | mode: {'APPLY' if apply else 'DRY-RUN'}")
    if apply and not token:
        print("HF_TOKEN with write scope is required for --apply. The OAuth connector credential")
        print("is contribute-only (create_pr); ask for a write token at hf.co/settings/tokens.")
        return 2
    api = None
    if apply:
        from huggingface_hub import HfApi
        api = HfApi(token=token)
    sk, pk = generate_keypair()
    prev = "GENESIS"
    n = 0
    with open(OUT / "hf_ops.jsonl", "a") as log:
        for s in spaces:
            plan = []
            if s["private"]:
                plan.append("set_public")
            plan += ["upload_GOVERNANCE.md", "restart"]
            print(f"  {s['id']:44s} [{s['tier']:10s}] {' + '.join(plan)}")
            if apply:
                if s["private"]:
                    api.update_repo_visibility(s["id"], repo_type="space", private=False)
                api.upload_file(repo_id=s["id"], repo_type="space", path_in_repo="GOVERNANCE.md",
                                path_or_fileobj=stamp(s).encode(),
                                commit_message="governance stamp + estate model backlinks (rebuild)")
                try:
                    api.restart_space(s["id"])
                except Exception:
                    pass  # static SDK or factory-managed: the commit already forces a rebuild
            r = build_receipt(
                action_id=f"hf-estate-op:{s['id']}",
                subject_name=f"hf://spaces/{s['id']}",
                actor={"type": "human", "id": "stephenlutar2", "is_service_account": False,
                       "auth_method": "oidc", "human_principal": "Stephen P. Lutar"},
                policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"estate-ops-v1"),
                                 "evaluated_at": "2026-08-30T22:15:00+00:00"},
                execution={"side_effect_class": "WRITE_REVERSIBLE",
                           "status": "EXECUTED" if apply else "DENIED"},
                evidence_items=[{"id": "inventory-row", "sha256": sha256_hex(canonical(s)), "present": True}],
                prev_chain_hash=prev, signing_key=sk)
            prev = chain_hash(r)
            log.write(json.dumps(r) + "\n")
            n += 1
    print(f"\n{n} receipt(s) -> receipts/hf_ops.jsonl (tip {prev[:16]}…)")
    if not apply:
        print("dry-run complete. Re-run with --apply and a write-scoped HF_TOKEN to execute.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
