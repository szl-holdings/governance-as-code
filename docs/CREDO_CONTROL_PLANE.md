# Credo Agent Governor → a11oy control plane

**Status:** MEASURED mapping in this repository. Credo product facts are REPORTED from public pages dated July–August 2026. Λ remains Conjecture 1.

## What Credo ships

Credo Agent Governor (research preview) installs approved policy onto an agent harness and resolves each loop event to **allow / block / escalate / advise**. First harness: Claude Code. Record kept: policy version, actor, tool, arguments, decision. This is a real control plane. It is not unique to SZL as a *category*.

Sources (public):
- https://www.credo.ai/blog/introducing-credo-ai-agent-governor
- https://www.credo.ai/agent-governor

## What SZL sells that Credo does not

| Question | Credo Governor | a11oy / GovernedAction/v1 |
|---|---|---|
| Does the action happen? | allow / block / escalate / advise at the harness | ALLOW / DENY / REVIEW before side effects |
| Can a warning authorize work? | advise is a first-class outcome | ADVISE is never authority (C1) |
| Can approval lift a hard block? | not stated as a law | No. C2 is executable. |
| Does the deny survive the vendor? | structured record in Credo's backend | DSSE + hash chain + offline verifier; vendor can be out of the loop |
| What if evidence is missing? | observability lever | INCOMPLETE / DENY — never PASS |
| Is trust a theorem? | not claimed | Λ uniqueness is Conjecture 1. Floor miss is REVIEW or DENY, not "proven unique" |
| Product vs proof | one product surface | a-11-oy.com product · a11oy.net proof |

The sentence to use with a buyer who already has Credo:

> Keep Credo as the program-of-record and policy pack. Use a11oy as the admission + receipt plane: every harness decision becomes a GovernedAction/v1 object a third party can verify after Credo, SZL, or the model vendor is gone.

That is coexistence, not a clone.

## Executable contract

```
python3 tests/test_credo_governor.py
python3 demo/credo_loop.py
```

Laws C1–C5 live in `tools/credo_governor.py`. They are not slogans.

## What this file does not claim

- No Credo partnership.
- No statement that Credo receipts are unsigned or weak beyond what they publish.
- No ATO, no SLSA L3, no unconditional Λ uniqueness.
- No "we beat Credo." We give away the format and sell admission.

Doctrine v11 LOCKED · locked-proven formulas = exactly 8 · Λ = Conjecture 1
