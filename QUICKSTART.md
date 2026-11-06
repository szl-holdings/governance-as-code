# Five-minute governed-action quickstart

This walkthrough starts from a fresh clone, executes the complete 12-step governed-action demo, and verifies the resulting receipt chain without network access.

## 1. Clone and enter the repository

```bash
git clone https://github.com/szl-holdings/governance-as-code.git
cd governance-as-code
```

## 2. Create an isolated Python environment

Linux or macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Step 4 needs Linux or macOS: the demo's flight recorder locks with POSIX
`fcntl.flock`, which native Windows Python does not provide, so run the demo
under WSL there. The offline verifier in step 5 does not use `fcntl`.

## 3. Install the runtime dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` pins the three libraries the demo and verifier import
(`cryptography`, `jsonschema`, `pyyaml`) plus `huggingface-hub`, which only
`tools/hf_estate_ops.py --apply` uses.

## 4. Run the 12-step acceptance demo

```bash
python demo/demo_harness.py
```

A passing run exercises all of these outcomes:

- an allowed action is signed and verifies as `PASS`;
- a denied action is preserved as signed evidence;
- post-signing tampering is rejected as `FAIL`;
- missing evidence remains `INCOMPLETE`, never `PASS`;
- a sink outage remains visible as `PENDING_SYNC`;
- chain replay is non-mutating;
- backdated or unattested time cannot pass;
- a service account cannot impersonate a human principal;
- an Article 12 conformance report is emitted.

A passing run ends with these two lines:

```text
DEMO COMPLETE — receipts/chain.jsonl, demo_bundle.json, article12_report.json
Every verdict above is reproducible offline: python3 demo/demo_harness.py
```

The demo creates a new ephemeral Ed25519 key on each run, so receipt hashes and the signer fingerprint intentionally change.
It overwrites the committed snapshots `receipts/chain.jsonl`, `receipts/demo_bundle.json` and
`receipts/flight_recorder.bin`; `receipts/article12_report.json` is rewritten with identical bytes.

## 5. Verify the bundle offline

Disconnect the machine from the network if desired, then run:

```bash
python examples/verify_demo_bundle.py receipts/demo_bundle.json
```

Expected output has this shape:

```text
CHAIN OK length=2 tip=<64 hexadecimal characters> signer=<16 hexadecimal characters>
```

The verifier independently:

1. loads the public key embedded in the demo bundle;
2. verifies each DSSE/Ed25519 signature;
3. recomputes every hash-chain link;
4. compares the recomputed tip with the bundle's declared tip;
5. rejects any receipt whose signature key identifier differs from the bundle signer.

A nonzero exit code means the bundle is malformed, its chain is broken, a signature is invalid, or its declared tip does not match the verified chain.

## Optional adversarial gate

```bash
python tests/adversarial_suite.py
```

The adversarial suite must report that every attack class held. It includes tampering, signature transplantation, cross-predicate confusion, evidence deletion, identity spoofing, chain splicing, forged genesis, time manipulation, subject-digest drift, Unicode confusion, an empty signature list, and verification with the wrong public key.

## Restore the committed receipt snapshots

`receipts/` is tracked: besides the demo outputs it holds the signed estate-operation logs
(`hf_ops*.jsonl`, `revision_attest.jsonl`) and other committed receipts, so do not delete the
directory. Put the files the demo rewrote back to their committed versions and remove the ignored
per-run outputs (such as `receipts/credo_loop.json`):

```bash
git restore receipts/
git clean -fX receipts/
```

The same two commands work in PowerShell.
