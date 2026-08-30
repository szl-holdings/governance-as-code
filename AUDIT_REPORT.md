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

## Blockers that need a human, not a model

1. CLM-011 — receipt claim has never been adversarially attacked:
   run the Daybreak Blue S2 payload against `tools/receipt_lib.py`
2. CLM-012 — Model BOM/license register across 43 models + 36 datasets
3. COM-015 — solo-founder gate (12.9% vs 23.7% Series A graduation)
4. COM-013 — no published price; GM/NRR/CAC/burn-multiple are uncomputable
5. Sept 1, 2026 — hardware security keys mandatory on individual Daybreak accounts
