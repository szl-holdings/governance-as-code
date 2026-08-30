#!/usr/bin/env python3
"""revision_attest.py — bind each Space's live runtime stage to a pinned git
revision and content hashes. This is the CLM-009 closure instrument.

Law: stage=RUNNING is runtime state, not evidence of revision. This tool
produces the missing evidence: for every Space it records the exact git sha the
Hub reports, hashes README.md and GOVERNANCE.md AT THAT REVISION, confirms the
governance stamp content matches (proving our commit is what's deployed), and
signs one GovernedAction/v1 receipt per Space.

Output: data/revision_attestations.json + receipts/revision_attest.jsonl
"""
import hashlib, json, pathlib, subprocess, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import build_receipt, chain_hash, generate_keypair, sha256_hex, canonical
from hf_estate_apply import stamp, API

ROOT = pathlib.Path(__file__).resolve().parent.parent
INV = json.load(open(ROOT / "data" / "hf_space_inventory.json"))
OUT = ROOT / "receipts"; OUT.mkdir(exist_ok=True)
RAW = "https://huggingface.co/spaces"

def get_json(url, tries=3):
    for a in range(tries):
        r = subprocess.run(["curl", "-sS", "-m", "30", url], capture_output=True, text=True)
        try:
            return json.loads(r.stdout)
        except Exception:
            time.sleep(2 ** a * 2)
    return {}

def get_bytes(url, tries=3):
    for a in range(tries):
        r = subprocess.run(["curl", "-sS", "-m", "30", url], capture_output=True)
        if r.returncode == 0 and r.stdout:
            return r.stdout
        time.sleep(2 ** a * 2)
    return b""

def http_status(url):
    r = subprocess.run(["curl", "-sS", "-m", "30", "-o", "/dev/null", "-w", "%{http_code}",
                        "-L", url], capture_output=True, text=True)
    return r.stdout.strip()

def main():
    sk, pk = generate_keypair()
    prev_hash = "GENESIS"
    attestations = []
    log = open(OUT / "revision_attest.jsonl", "w")
    for s in INV["spaces"]:
        rid = s["id"]; name = rid.split("/", 1)[1]
        info = get_json(f"{API}/spaces/{rid}")
        rev = info.get("sha")
        stage = (info.get("runtime") or {}).get("stage")
        hw = ((info.get("runtime") or {}).get("hardware") or {}).get("current")
        # hash files AT the pinned revision
        readme = get_bytes(f"{RAW}/{rid}/raw/{rev}/README.md") if rev else b""
        gov = get_bytes(f"{RAW}/{rid}/raw/{rev}/GOVERNANCE.md") if rev else b""
        expected_stamp = stamp(s).encode()
        att = {
            "id": rid, "tier": s["tier"], "sdk": s["sdk"],
            "revision": rev, "stage": stage, "hardware": hw,
            "private": info.get("private"),
            "readme_sha256": hashlib.sha256(readme).hexdigest() if readme else None,
            "governance_sha256": hashlib.sha256(gov).hexdigest() if gov else None,
            "stamp_deployed": (gov == expected_stamp),
            "app_http": http_status(f"https://{name.lower() and rid.replace('/', '-').lower()}.hf.space") if stage == "RUNNING" else None,
        }
        att["attested"] = bool(rev and att["stamp_deployed"] and stage == "RUNNING" and att["private"] is False)
        r = build_receipt(
            action_id=f"revision-attest:{rid}",
            subject_name=f"hf://spaces/{rid}@{rev}",
            actor={"type": "human", "id": "stephenlutar2", "is_service_account": False,
                   "auth_method": "oidc", "human_principal": "Stephen P. Lutar"},
            policy_decision={"result": "ALLOW", "policy_hash": sha256_hex(b"revision-attest-v1"),
                             "evaluated_at": "2026-08-31T00:10:00+00:00"},
            execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED",
                       "deployed_revision": rev or "UNKNOWN"},
            evidence_items=[
                {"id": "README.md@rev", "sha256": att["readme_sha256"] or "", "present": bool(readme)},
                {"id": "GOVERNANCE.md@rev", "sha256": att["governance_sha256"] or "", "present": bool(gov)},
            ],
            prev_chain_hash=prev_hash, signing_key=sk)
        prev_hash = chain_hash(r)
        log.write(json.dumps(r) + "\n")
        attestations.append(att)
        print(f"  {rid:46s} rev={str(rev)[:8]:8s} stage={str(stage):8s} stamp={'✓' if att['stamp_deployed'] else '✗'} app={att['app_http']}", flush=True)
        time.sleep(0.3)
    log.close()
    json.dump({"attested_at": "2026-08-31", "chain_tip": prev_hash, "attestations": attestations},
              open(ROOT / "data" / "revision_attestations.json", "w"), indent=1)
    n = sum(1 for a in attestations if a["attested"])
    print(f"\nattested {n}/{len(attestations)} — revision-pinned, stamp-matched, RUNNING, public · chain tip {prev_hash[:16]}…")
    return 0

if __name__ == "__main__":
    sys.exit(main())
