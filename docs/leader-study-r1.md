# governance-as-code domain leader study r1 (propose-only)

Date: 2026-11-24. Method: web-verified leader landscape + governing-seat ratification (Kimi nonce T10-RULING-20261124-K1). Study pinned to governance-as-code HEAD f91c3cc37105543553fde232c343e1bd94779e03, fetched 2026-11-24. This card is documentation only; it changes no code, CI, config, or existing PR status. All absorb actions are FUTURE PROPOSALS (non-authorizing); implementation and merges remain separately reviewed and gated. L Conjecture 1: OPEN (advisory, never a closed theorem). No speedup, energy, or proven-trust claims; upstream performance claims are labeled as upstream claims only.

## Domain: GovernedAction/v1 receipt format, executable CI gates, and the 12-step governed-action demo, with the receipt format as the public surface and the control plane as the commercial layer.

## Leaders studied (web-verified 2026-11-24)
1. in-toto (https://github.com/in-toto/in-toto) - moat: a mature supply-chain integrity framework with signed link metadata and layout verification that records and checks who performed each step.
2. Cosign (https://github.com/sigstore/cosign) - moat: widely adopted artifact signing and verification integrated with the Sigstore ecosystem, including keyless signing and transparency-log support.
3. Actions Runner (https://github.com/actions/runner) - moat: the production execution engine for GitHub Actions workflows, with broad operational adoption and tight integration into GitHub-hosted and self-hosted CI.

## Absorb actions (FUTURE PROPOSALS, non-authorizing)
1. (in-toto) Propose a documentation-only design note comparing GovernedAction/v1 receipts with in-toto link and layout concepts, identifying terminology overlaps and differences without asserting compatibility or proven trust. Cost: doc-only, approximately 0.5-1 maintainer day including review; limit: note only, no code, no infra changes.
2. (Cosign) Propose a documentation-only review of where Cosign-style signing and verification concepts could be discussed as optional future receipt-verification context, while keeping the public receipt format stable and making no integration commitment. Cost: doc-only, approximately 0.5-1 maintainer day including review; limit: note only, no code, no infra changes.
3. (Actions Runner) Propose a documentation-only review mapping the 12-step governed-action demo's CI execution assumptions to Actions Runner concepts, with explicit separation between observed runner behavior and this repo's gate requirements. Cost: doc-only, approximately 0.5-1 maintainer day including review; limit: note only, no code, no infra changes.
4. Baseline preserve honestly: preserve the doctrine that the GovernedAction/v1 receipt format is the public surface, CI gates must remain executable and testable rather than prose commitments, and the "Give away the format; sell the control plane" boundary must not be blurred by leader-study language. Cost: doc-only, approximately 0.25 maintainer day for review; limit: note only, no code, no infra changes.

## Do not do (per governing seat)

Do not merge, bypass the signature wall, or claim implementation beyond this card.
