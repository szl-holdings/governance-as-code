# governance-as-code

**Control before action. Evidence after.** The SZL Holdings governance estate as
executable code: receipt schema, gates, ledgers, and the 12-step demo that is the
acceptance test for the whole doctrine.

Give away the format. Sell the control plane. This repo is the format.

## What enforces what

| Layer | File | Law |
|---|---|---|
| Receipt schema | `schemas/governed_action_v1.schema.json` | `is_service_account=false` is structural for human principals (Art.12(3)(d)); `ntp_synced` is `const: true` |
| Crypto | `tools/receipt_lib.py` | Ed25519 over DSSE PAE; hash chain; missing evidence => INCOMPLETE, never PASS |
| Credo map | `tools/credo_governor.py` | C1 advise never authorizes; C2 hard DENY is unliftable; C3 escalate needs a human; C4 missing evidence never ALLOW; C5 Λ floor miss is advisory |
| Vocabulary | `tools/lexicon_gate.py` | Banned phrases fail CI with the correction attached |
| Release | `tools/release_gate.py` | Claims without evidence block release; commercial UNKNOWNs block a raise |
| Estate | `tools/spaces_audit.py` | READ_ONLY audit of all 45 Spaces; signs a receipt for its own run |
| Demo | `demo/demo_harness.py` | 12 steps: sign, deny, tamper, evidence-cut, outage, replay, spoof, Article 12 report |
| Credo loop | `demo/credo_loop.py` | allow → advise → block → later allow stays DENY; receipts signed |
| Offline verification | `examples/verify_demo_bundle.py` | Replays DSSE signatures and the receipt hash chain without network access |

## Start here

The [five-minute quickstart](QUICKSTART.md) goes from a fresh clone to a verified
offline receipt chain, including Windows, macOS, and Linux commands and the exact
shape of a passing result.

Credo coexistence (not a clone): [docs/CREDO_CONTROL_PLANE.md](docs/CREDO_CONTROL_PLANE.md).
Lean discrete witness (Conjecture 1 untouched): [lutar-lean CredoVerdictWitness](https://github.com/szl-holdings/lutar-lean/blob/main/Showcase/Frontier/CredoVerdictWitness.lean).

## Run it

```bash
pip install pyyaml cryptography   # only runtime dependencies
python3 demo/demo_harness.py      # the 12-step demo, as a test
python3 tests/test_credo_governor.py
python3 demo/credo_loop.py        # Credo outcomes → SZL receipts; deny survives later allow
python3 examples/verify_demo_bundle.py receipts/demo_bundle.json
python3 tools/lexicon_gate.py     # vocabulary gate
python3 tools/spaces_audit.py     # estate audit + self-receipt
python3 tools/release_gate.py     # release gate
python3 tools/release_gate.py --raise   # raise gate (will report UNKNOWNs)
```

Gates failing on first run is correct. The exit codes are the checklist.

## The positioning sentence

IAM says what an identity may access. a11oy proves what an AI agent was
authorized to do, what it actually did, and whether the required evidence exists.

Keep Credo as the program-of-record if you already have it. Use a11oy as the
admission + receipt plane: a third party can verify the envelope after Credo,
SZL, or the model vendor is gone.

Codex auto-review decides. a11oy proves. The decision does not survive the
vendor, the outage, or the auditor; the receipt does.

## Scope exclusions (v1)

No MCP servers. No agent framework. No UI beyond the demo. No multi-tenant SaaS.
No billing. No AQL. No live Claude Code / Credo harness install in this repo.
The Zero-Bandaid Law applies to generated code too: no
`pass`, no `NotImplementedError`, no mock-for-now.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

This is the deliberate expression of "give away the format": the GovernedAction/v1
schema, gates, and demo in this repository are Apache-2.0 so anyone can implement
and verify the format. The SZL control plane and any repository carrying
`LicenseRef-SZL-Proprietary` are **not** covered by this grant.

**Verification boundary.** A receipt in this format proves integrity, origin, and
that a declared policy executed. It does not prove model accuracy, safety,
fairness, effectiveness, or uptime. Λ = Conjecture 1 (advisory) — never
"proven trust."
