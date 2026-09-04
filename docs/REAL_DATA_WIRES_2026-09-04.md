# Real data wires — 2026-09-04

**Class:** MEASURED this recapture. Not a roadmap. Not a qualification pack.
**Product:** https://a-11-oy.com
**Proof:** https://a11oy.net
**Never:** a11oy.com. Never a new Space.

## Live wires observed

| Wire | URL | Class | Observation |
|---|---|---|---|
| Honest API | https://a-11-oy.com/honest | MEASURED | 200. organ=a11oy. git_sha=6acc6c752262. Doctrine v11 LOCKED. Λ=Conjecture 1. locked-8 {F1,F4,F7,F11,F12,F18,F19,F22}. Persistence label: sqlite durable=True. |
| Receipt lake | https://a-11-oy.com/api/lake/v1/receipts | MEASURED | 200. Header x-szl-wire-d=LIVE. JSON count=100 of chain_index 1..206. Organs include a11oy, bets, state_plane, token_plane, kernel_plane, pr_sweep. Energy label UNAVAILABLE. Payload label MODELED on sampled pcai/run. Ingest span 2026-08-28T19:26Z → 2026-09-04T23:14Z. |
| Cosign pubkey | https://a-11-oy.com/cosign.pub | MEASURED | 200. ECDSA P-256 PEM. |
| Verify | https://a-11-oy.com/verify | MEASURED | 200. In-browser independent check. Signer may be ABSENT/UNAVAILABLE after restart — not faked. |
| Command / govern / khipu / decision | a-11-oy.com paths | MEASURED reachability | 200. CUDA UNAVAILABLE. Energy UNAVAILABLE. |
| Proof notes | https://a11oy.net/notes/#2026-09-04 | MEASURED | 200. Section live on Pages. |
| Proof contracts | https://a11oy.net/evidence.json https://a11oy.net/record.json | MEASURED | 200. Static registry. No receipt store on this origin. |
| Hub Space | https://huggingface.co/spaces/SZLHOLDINGS/a11oy | MEASURED | Running. Same honest SHA 6acc6c75. |
| Hub receipts dataset | https://huggingface.co/datasets/SZLHOLDINGS/uds-governance-receipts | REPORTED | Append-only DSSE receipts. Not the live lake. |
| Hub lake mirror | https://huggingface.co/datasets/SZLHOLDINGS/szl-lake | REPORTED | Mirror, not the product query API. |
| Killinchu OSINT | https://huggingface.co/datasets/SZLHOLDINGS/killinchu-osint-corpus | REPORTED | Public-data corpus. Effectors stay SIMULATED. |

## Not wired from this session

- GPU train / Forge weights — BLOCKED_NO_METAL
- www.a-11-oy.com TLS — access denied
- Persistent DSSE signer — ABSENT on healthz this recapture
- Product publisher SHA — live 6acc6c75, Menu lock 7f51d72 source-only. #1359 OPEN
- Hub card count rewrite — no Hub write token. Org README still drifts vs public API (Spaces 16 API / 17 org card / 15 profile text)

## Buyer sentence

The product origin is wired to a live SHA3-256 receipt lake. Proof stays a separate static registry. Models and energy stay labeled. Deny-by-default survives a missing signer.
