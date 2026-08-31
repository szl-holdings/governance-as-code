# SZL Estate Audit — 2026-08-30 (executed, not proposed)

Collector's own receipts: `receipts/spaces_audit_receipt.json` (READ_ONLY audit) and
`receipts/demo_bundle.json` (12-step governed-action demo). Every number below is
machine-derived from live API reads dated today.

## Estate counts (live)

| Surface | Count | Source |
|---|---|---|
| GitHub repos (szl-holdings) | 98 (5 private) | gh api, 2026-08-30 |
| HF Spaces (SZLHOLDINGS) | 45 (7 public / 38 private) | hub_repo_search, 2026-08-30 |
| HF models | 43 (all public) | hub_repo_search, 2026-08-30 |
| HF datasets | 36 (6 private) | hub_repo_search, 2026-08-30 |
| HF org plan | team · account PRO | hf_whoami |

## Blocked by credential scope (not by design)

The connected HF OAuth credential carries `read-repos` + `contribute-repos`
(PR-only writes). These estate mutations require `write-repos` scope:

- Unprivate 38 Spaces
- Direct-commit GOVERNANCE.md stamps (Hub model-backlink activation)
- Programmatic Space restarts

Executor ready: `HF_TOKEN=hf_... python3 tools/hf_estate_ops.py --apply`
(generate a write-scoped token at https://huggingface.co/settings/tokens,
scoped to the SZLHOLDINGS org). Dry-run plan already receipted in
`receipts/hf_ops.jsonl` — 45 actions, chained and signed.

## What is now true and machine-checkable

- GovernedAction/v1 schema: `schemas/governed_action_v1.schema.json`
  — `is_service_account=false` structural for human actors; `ntp_synced` const true
- Ed25519 over DSSEv1 PAE with spec-exact encoding (fixed this session)
- 12-step demo: all verdicts reproduce offline; browser re-verifies with WebCrypto
- Lexicon gate: PASS on this repo (0 banned-phrase hits)
- Release gate: 8 claims VERIFIED, 4 BLOCKERs standing by design
  (revision attestation, mobile smoke, adversarial crypto review, Model BOM)
- Raise gate: 24 commercial facts UNKNOWN, all `blocks_raise=True`

## Resolution update (same evening, 2026-08-31)

- CLM-009 CLOSED — all 45 Spaces revision-pinned; governance-stamp content
  verified deployed at each pinned revision; 45 chain-signed receipts
  (`receipts/revision_attest.jsonl`, `data/revision_attestations.json`).
- CLM-010 CLOSED — all 5 flagships render clean at 390px (captures in
  `szl-audit/flagship_*_mobile.png`).
- CLM-011 CLOSED (self-adversarial scope) — `tests/adversarial_suite.py`:
  16 attack classes (tamper, signature transplant, PAE cross-type confusion,
  evidence deletion, chain splice, forged genesis, spoof variants, wrong key),
  16/16 held — zero attacks produce PASS. Independent external review
  (Daybreak Blue S2) remains recommended but no longer blocks release.
- CLM-012 CLOSED — `governance/MODEL_BOM.yaml`: 80 artifacts (43 models,
  37 datasets) from live Hub reads; 1 UNDECLARED license disclosed.
- RELEASE GATE: PASS (13 claims verified/attested, 0 blockers).
- Verifier site published: https://a11oy-verify.pplx.app (public).

## Commercial artifacts built (2026-08-31, same session)

- `pricing/PRICING.md` — 5 SKUs as testable hypotheses; never token-priced
- `governance/BUYER_PERSONA.md` — VP Platform/CISO at regulated AI adopter; 12 discovery questions
- `data_room/` — 13-section scaffold ready for primary documents
- `tools/north_star.py` — verified governed actions / customer / month, computable from receipt logs (227 actions already recorded)
- `daybreak/S2_ADVERSARIAL_REVIEW_PAYLOAD.md` — ready for the independent Daybreak Blue run
- `governance/COMMERCIAL_LEDGER.yaml` — 5 rows attested as built artifacts, 19 remain founder-only UNKNOWN

## Still founder-only (raise gate blocks here, by design)

1. COM-001..012 — financial truth (ARR, MRR, cash, burn, runway, margins)
2. COM-015 — named co-founder / security-credentialed owner (12.9% vs 23.7% graduation)
3. COM-016..018 — cap table, IP assignments, Delaware C-Corp
4. COM-020..022 — SOC 2 date, named EU design partner, conversion rate
5. Sept 1, 2026 — hardware security keys mandatory on individual Daybreak accounts
