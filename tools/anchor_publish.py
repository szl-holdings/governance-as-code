#!/usr/bin/env python3
"""anchor_publish.py — publish a signed chain-tip anchor.

Closes the unanchored-truncation residual class with infrastructure that
already exists: each anchor line binds (timestamp, log file, chain tip,
length) and is itself Ed25519-signed. Anchors append to anchors/CHAIN_TIPS.jsonl
and are committed to this repo — the repo is the out-of-band channel. An
auditor fetches the anchor from GitHub (independent of whoever hands them the
log) and calls verify_chain(..., expected_tip=tip, min_length=length).

Usage: python3 tools/anchor_publish.py receipts/hf_ops_retry.jsonl receipts/revision_attest.jsonl ...
"""
import base64, json, pathlib, sys
from datetime import datetime, timezone
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from receipt_lib import (canonical, chain_hash, export_pubkey_raw_b64, generate_keypair,
                         keyid, load_pubkey_raw_b64, sha256_hex, sign)

ROOT = pathlib.Path(__file__).resolve().parent.parent
ANCHORS = ROOT / "anchors"
KEYFILE = ANCHORS / "anchor_key.json"   # demo-grade: file-held key. Production: HSM/KMS.

def load_or_create_anchor_key():
    ANCHORS.mkdir(exist_ok=True)
    if KEYFILE.exists():
        d = json.loads(KEYFILE.read_text())
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        sk = load_der_private_key(base64.b64decode(d["sk_der_b64"]), password=None)
        return sk, sk.public_key()
    sk, pk = generate_keypair()
    from cryptography.hazmat.primitives import serialization
    KEYFILE.write_text(json.dumps({
        "warning": "demo-grade file-held key; production anchors must use HSM/KMS",
        "sk_der_b64": base64.b64encode(sk.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())).decode(),
        "keyid": keyid(pk)}))
    return sk, pk

def tip_of(jsonl_path):
    receipts = [json.loads(l) for l in open(jsonl_path) if l.strip()]
    return (chain_hash(receipts[-1]), len(receipts)) if receipts else (None, 0)

def main():
    files = sys.argv[1:]
    if not files:
        files = sorted(str(p) for p in (ROOT / "receipts").glob("*.jsonl"))
    sk, pk = load_or_create_anchor_key()
    kid = keyid(pk)
    now = datetime.now(timezone.utc).isoformat()
    lines = []
    for f in files:
        tip, length = tip_of(f)
        if tip is None:
            continue
        anchor = {"at": now, "log": str(pathlib.Path(f).relative_to(ROOT)),
                  "chain_tip": tip, "length": length, "anchor_keyid": kid}
        payload = canonical(anchor)
        anchor["sig"] = sign(sk, "szl.dev/chain-tip-anchor/v1", payload)
        lines.append(anchor)
        print(f"  anchored {anchor['log']:40s} tip={tip[:16]}… len={length}")
    out = ANCHORS / "CHAIN_TIPS.jsonl"
    with open(out, "a") as fh:
        for a in lines:
            fh.write(json.dumps(a) + "\n")
    (ANCHORS / "ANCHOR_PUBKEY.txt").write_text(
        f"anchor key keyid: {kid}\nraw ed25519 pubkey (b64): {export_pubkey_raw_b64(pk)}\n"
        f"out-of-band check: fetch this file from github.com/szl-holdings/governance-as-code\n")
    print(f"\n{len(lines)} anchor(s) appended -> anchors/CHAIN_TIPS.jsonl (key {kid})")
    return 0

if __name__ == "__main__":
    sys.exit(main())
