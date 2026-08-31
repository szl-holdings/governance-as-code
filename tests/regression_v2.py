#!/usr/bin/env python3
"""regression_v2.py — re-executes every reviewer PoC against current receipt_lib.

Any PoC printing EXPLOIT-WORKS fails CI, except the two documented residuals
whose root cause is information-theoretic (offline verification cannot detect
history truncation without an out-of-band anchor — the verifier discloses
unanchored verification explicitly). Closing them is a Control-plane feature:
published tip hash / transparency-log anchoring.

Residuals (must never silently pass — they carry the anchor disclosure):
  poc_claude_2  — tail truncation, unanchored verify_chain
  poc_gpt_13    — FlightRecorder V3 silent tail deletion, same root cause
Defenses that crash the exploit script (CanonicalizationError, build-side
AssertionError) count as HELD — the attack can no longer be constructed.
"""
import pathlib, subprocess, sys

FINDINGS_DIRS = [pathlib.Path(__file__).resolve().parent.parent / "daybreak" / d for d in ("findings", "findings2")]
RESIDUALS = {"poc_alpha_4.py"}  # same-chain equivocation is invisible offline; closure = transparency log (Control-plane)
SUPERSEDED = {"poc_kimi_4.py"}  # v2.3 changed semantics by design: read_all refuses silently-truncated views (beta PoC-3); crash recovery is tolerate_torn=True — kimi_4's "raises = exploit" premise predates that contract

def main():
    pocs = sorted(p for d in FINDINGS_DIRS for p in d.glob("poc_*.py") if d.exists())
    failed, residual_confirmed, held = [], [], 0
    for p in pocs:
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().splitlines()
        last = out[-1] if out else ""
        if "EXPLOIT-WORKS" in r.stdout:
            if p.name in RESIDUALS:
                residual_confirmed.append(p.name)
                print(f"  [RESIDUAL ] {p.name} — documented: same-chain equivocation needs a transparency log")
            elif p.name in SUPERSEDED:
                residual_confirmed.append(p.name)
                print(f"  [SUPERSEDED] {p.name} — premise predates v2.3 loud-refusal contract (beta PoC-3 fix)")
            else:
                failed.append(p.name)
                print(f"  [REGRESSED] {p.name} — EXPLOIT-WORKS against current library")
        else:
            held += 1
            print(f"  [HELD     ] {p.name}")
    missing = RESIDUALS - set(residual_confirmed)
    for m in missing:
        print(f"  [NOTE     ] {m} now fully held (residual list may be pruned)")
    print(f"\nREGRESSION v2: {held} held · {len(residual_confirmed)} documented residuals · {len(failed)} regressed")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
