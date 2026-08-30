#!/usr/bin/env python3
"""spaces_audit.py — READ_ONLY audit of the HF Spaces estate. Emits a signed
GovernedAction/v1 receipt for its own run: if a11oy's own audit can't run
READ_ONLY, the side-effect classification is theater.

Invariant enforced in code: stage=RUNNING is never treated as evidence of a
deployed revision. Runtime state and revision attestation are separate lanes.
"""
import json, sys, pathlib, datetime
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import (build_receipt, chain_hash, generate_keypair, keyid,
                         export_pubkey_raw_b64, sha256_hex, canonical)

ROOT = pathlib.Path(__file__).resolve().parent.parent
INV = ROOT / "data" / "hf_space_inventory.json"
OUT = ROOT / "receipts"
FLAGSHIP_CAP = 5
SUPPORTING_CAP = 12

def audit(inv):
    spaces = inv["spaces"]
    findings = []
    tiers = {}
    for s in spaces:
        tiers.setdefault(s["tier"], []).append(s)
    # Rule 1: flagship cap
    if len(tiers.get("FLAGSHIP", [])) > FLAGSHIP_CAP:
        findings.append({"sev": "BLOCKER", "rule": "FLAGSHIP_CAP",
                         "msg": f"{len(tiers['FLAGSHIP'])} flagships > cap {FLAGSHIP_CAP}"})
    if len(tiers.get("SUPPORTING", [])) > SUPPORTING_CAP:
        findings.append({"sev": "HIGH", "rule": "SUPPORTING_CAP",
                         "msg": f"{len(tiers['SUPPORTING'])} supporting > cap {SUPPORTING_CAP}"})
    # Rule 2: untiered surface blocks release
    for s in spaces:
        if s.get("tier") not in ("FLAGSHIP", "SUPPORTING", "LAB", "ORG_CARD"):
            findings.append({"sev": "BLOCKER", "rule": "UNTIERED", "msg": f"{s['id']} has no tier"})
    # Rule 3: private flagship = invisible flagship
    for s in tiers.get("FLAGSHIP", []):
        if s["private"]:
            findings.append({"sev": "BLOCKER", "rule": "PRIVATE_FLAGSHIP",
                             "msg": f"{s['id']} is FLAGSHIP but private — invisible to buyers/diligence"})
    # Rule 4: docker/gradio on free cpu-basic requires PRO (account is PRO — recorded as ATTESTED context)
    docker_like = [s for s in spaces if s["sdk"] in ("docker", "gradio")]
    findings.append({"sev": "INFO", "rule": "DOCKER_TIER",
                     "msg": f"{len(docker_like)} docker/gradio Spaces; account is PRO, org plan={inv['inventory_meta']['org_plan']} — recreatable. Docker on free tier would be at billing risk."})
    # Rule 5: estate counts
    pub = sum(1 for s in spaces if not s["private"])
    findings.append({"sev": "INFO", "rule": "VISIBILITY",
                     "msg": f"{pub} public / {len(spaces)-pub} private of {len(spaces)} Spaces"})
    # Rule 6: staleness — supporting+flagship untouched > 30 days
    today = datetime.date(2026, 8, 30)
    for s in spaces:
        if s["tier"] in ("FLAGSHIP", "SUPPORTING"):
            age = (today - datetime.date.fromisoformat(s["lastModified"])).days
            if age > 30:
                findings.append({"sev": "HIGH", "rule": "STALE_SURFACE",
                                 "msg": f"{s['id']} ({s['tier']}) untouched {age}d — DEGRADED until re-attested"})
    return tiers, findings

def main():
    inv = json.load(open(INV))
    tiers, findings = audit(inv)
    spaces = inv["spaces"]
    blockers = [f for f in findings if f["sev"] == "BLOCKER"]
    print("SPACES AUDIT (READ_ONLY) — hf.co/SZLHOLDINGS")
    print(f"  estate: {len(spaces)} Spaces | " +
          " | ".join(f"{t}:{len(v)}" for t, v in sorted(tiers.items())))
    print(f"  visibility: {sum(1 for s in spaces if not s['private'])} public / "
          f"{sum(1 for s in spaces if s['private'])} private")
    for f in findings:
        print(f"  [{f['sev']:8s}] {f['rule']:16s} {f['msg']}")
    # Sign the audit itself — dogfooding: the audit is a governed action.
    OUT.mkdir(exist_ok=True)
    sk, pk = generate_keypair()
    evidence = [{"id": "data/hf_space_inventory.json",
                 "sha256": sha256_hex(canonical(inv)), "present": True}]
    r = build_receipt(
        action_id="spaces-audit-2026-08-30",
        subject_name="hf://spaces/SZLHOLDINGS/*",
        actor={"type": "human", "id": "stephenlutar2", "is_service_account": False,
               "auth_method": "oidc", "human_principal": "Stephen P. Lutar"},
        policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"spaces-audit-readonly-v1"),
                         "evaluated_at": "2026-08-30T22:15:00+00:00"},
        execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
        evidence_items=evidence, prev_chain_hash="GENESIS", signing_key=sk)
    receipt = {"audit_receipt": r, "chain_hash": chain_hash(r),
               "auditor_key": export_pubkey_raw_b64(pk),
               "completeness": "COMPLETE" if all(i["present"] for i in evidence) else "INCOMPLETE",
               "limitations": ["stage=RUNNING is not evidence of a deployed revision",
                               "runtime stage not probed per-Space in this run",
                               "visibility change requires org settings scope, not available to this audit"],
               "findings": findings}
    (OUT / "spaces_audit_receipt.json").write_text(json.dumps(receipt, indent=1))
    print(f"\n  receipt signed (key {keyid(pk)}) → receipts/spaces_audit_receipt.json")
    print(f"  verdict: {'FAIL — ' + str(len(blockers)) + ' blockers' if blockers else 'PASS'}")
    return 1 if blockers else 0

if __name__ == "__main__":
    sys.exit(main())
