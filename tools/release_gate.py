#!/usr/bin/env python3
"""release_gate.py — gates on CLAIMS_LEDGER (release) and COMMERCIAL_LEDGER (raise).
Exit 0: gate passed. Exit 1: release blocked. Exit 2: raise blocked.
UNKNOWN renders literally — an empty field reads as an oversight; UNKNOWN reads as an audited state."""
import sys, pathlib, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

def check_claims():
    ledger = yaml.safe_load(open(ROOT / "governance" / "CLAIMS_LEDGER.yaml"))
    blockers, ok = [], []
    for c in ledger["claims"]:
        state, blocks = c["truth_state"], c.get("blocks_release", False)
        if state in ("VERIFIED", "ATTESTED"):
            ok.append(c)
        elif blocks:
            blockers.append(c)
    return ok, blockers

ATTESTED_ARTIFACT_STATES = {"HYPOTHESIS_PUBLISHED", "DEFINED_UNVALIDATED", "REGISTER_COMPLETE", "INSTRUMENTED", "SCAFFOLDED"}

def check_commercial():
    ledger = yaml.safe_load(open(ROOT / "governance" / "COMMERCIAL_LEDGER.yaml"))
    rows = ledger["rows"]
    unknown = [r for r in rows if r["value"] == "UNKNOWN" and r.get("blocks_raise")]
    attested = [r for r in rows if r["value"] in ATTESTED_ARTIFACT_STATES]
    return unknown, attested, ledger["series_a_targets"]

def main():
    raise_mode = "--raise" in sys.argv
    ok, blockers = check_claims()
    print(f"RELEASE GATE — claims verified/attested: {len(ok)}, blocking: {len(blockers)}")
    for c in blockers:
        print(f"  [BLOCKER] {c['id']}: {c['claim']}")
        if c.get("note"):
            print(f"            {c['note']}")
    if raise_mode:
        unknown, attested, targets = check_commercial()
        if attested:
            print(f"\nArtifacts built (attested but not founder-truth): {len(attested)}")
            for r in attested:
                print(f"  [BUILT] {r['id']}: {r['fact']} — {r['value']}")
        print(f"\nRAISE GATE — commercial facts still UNKNOWN: {len(unknown)} (any UNKNOWN blocks a raise)")
        for r in unknown:
            print(f"  [UNKNOWN] {r['id']}: {r['fact']}")
        print(f"\nSeries A targets: ARR ${targets['arr_to_qualify_usd']:,} · GM ≥{targets['gross_margin_floor']:.0%} · "
              f"NRR ≥{targets['nrr_floor']:.0%} · CAC payback ≤{targets['cac_payback_months_max']}mo · "
              f"burn multiple ≤{targets['burn_multiple_max']}x")
        print(f"Second door: {targets['second_door']}")
        if unknown:
            print("\nRAISE GATE: BLOCKED — no model may invent these values; only the founder can supply them.")
            return 2
    if blockers:
        print("\nRELEASE GATE: FAIL — evidence required, not edits to this gate.")
        return 1
    print("\nRELEASE GATE: PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
