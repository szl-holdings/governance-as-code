# GovernedAction/v1 — Portable Evidence for Consequential AI-Agent Actions

**Status:** v1.1, published 2026-08-31 · **Canonical:** `https://szl.dev/predicates/governed-action/v1`
**Reference implementation:** https://github.com/szl-holdings/governance-as-code (Python + browser JS, byte-parity)
**Live verifier:** https://a11oy-verify.pplx.app · https://huggingface.co/spaces/SZLHOLDINGS/governed-receipt-verifier

## 1. Abstract

GovernedAction/v1 is a receipt format for AI-agent actions that have real-world
side effects. A receipt records what an agent was authorized to do, what it
actually did, and whether the required evidence exists. Receipts are signed
Ed25519 over DSSE pre-authentication encoding, hash-chained, and verifiable
offline by any auditor without entering the issuing platform.

**The format is open. Implement it, emit it, and let anyone verify it.**

## 2. Envelope

Receipts are in-toto ITE-6-style statements:

```
{
  "predicateType": "https://szl.dev/predicates/governed-action/v1",
  "subject": { "name": "...", "digest": { "sha256": "<sha256(canonical(predicate))>" } },
  "predicate": { ... },
  "signatures": [ { "keyid": "<16-hex>", "sig": "<base64 Ed25519>" } ]
}
```

`subject.digest.sha256` MUST equal the SHA-256 of the canonical predicate
(Section 5). Verifiers recompute it; a mismatch is a binding failure.

## 3. Predicate fields

| Field | Rule |
|---|---|
| `action_id` | non-empty string |
| `actor` | §4 — identity laws |
| `policy_decision` | `result` ∈ {ALLOW, DENY}; `policy_hash`; `evaluated_at` |
| `execution` | `side_effect_class` ∈ {READ_ONLY, WRITE_REVERSIBLE, WRITE_IRREVERSIBLE, EXTERNAL_OBSERVABLE}; `status` ∈ {EXECUTED, DENIED, ROLLED_BACK, PENDING_SYNC}; `deployed_revision` optional |
| `evidence` | `items[]` with strict-boolean `present`; present items carry 64-hex `sha256`; `completeness` is computed by verifiers, never trusted as declared |
| `timestamps` | RFC3339 `created`/`executed`; `executed >= created`; `ntp_synced` const true; optional `rfc3161_token` (base64) |
| `prev_chain_hash` | 64-hex of prior receipt or `GENESIS` |
| `chain_id` | genesis-derived lineage marker |

## 4. Identity laws (Art. 12(3)(d) alignment)

- `actor.type` is exactly `"human"` or `"service"` — case-sensitive.
- Human actors: `is_service_account=false`, `auth_method` ≠ `api_key`,
  non-blank `human_principal` (the natural person accountable).
- Service actors: `is_service_account=true`.
- Verifiers bind the signing `keyid` to an identity via an authorized-actors
  registry obtained out-of-band. Human-actor receipts verified without a
  registry cap at INCOMPLETE — an unanchored key cannot prove a person acted.

## 5. Signing and canonicalization

- Canonical JSON: UTF-8, sorted keys, no whitespace, `allow_nan=false`,
  string keys only.
- Signature: Ed25519 over `DSSEv1 SP len(type) SP type SP len(payload) SP payload`.
- `signatures` contains exactly one `{keyid, sig}` entry; `keyid` MUST equal
  `sha256(raw public key)[:16]`.

## 6. Verification verdicts

| Verdict | Meaning |
|---|---|
| PASS | signature valid, structure complete, evidence complete, time attested, identity registry-bound |
| INCOMPLETE | honestly signed but evidence missing, time unattested, or identity unanchored — **never PASS with missing evidence** |
| FAIL | signature invalid, structure violated, chain link broken, identity spoof |

## 7. Chain verification

`verify_chain` checks linkage, per-receipt verdicts, lineage identity, and
temporal ordering. **Empty chains are invalid.** Unanchored verification
proves internal consistency only; detection of truncation or cross-context
replay requires an out-of-band anchor (`expected_tip`, `min_length`) — e.g. a
tip hash published to a transparency log.

## 8. Conformance profile

The EU AI Act Article 12 logging conformance profile maps each predicate field
to statutory record-keeping requirements: `article12/conformance_profile.yaml`.
This is a logging conformance profile, not a claim of EU AI Act compliance;
applicability, classification, and deployer obligations remain deployer-specific.
Retention floor: 180 days.

## 9. Security record

Independent multi-model adversarial review (2026-08-31): 39 executable PoCs;
37 confirmed exploits against v1's semantic layer; crypto core held in all
reviews. v1.1 hardened; all PoCs regression-locked in CI (`tests/regression_v2.py`).
Two documented residuals share one information-theoretic root cause
(unanchored truncation) and are disclosed in the verifier output.
