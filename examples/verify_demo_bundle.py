#!/usr/bin/env python3
"""Verify a governance-as-code demo bundle without network access."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from receipt_lib import keyid, load_pubkey_raw_b64, verify_chain  # noqa: E402

HEX_16 = re.compile(r"^[0-9a-f]{16}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def load_bundle(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"bundle not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("bundle root must be a JSON object")
    return value


def verify_bundle(bundle: dict[str, Any]) -> tuple[int, str]:
    required = ("public_key_raw_b64", "keyid", "chain_tip", "receipts")
    missing = [name for name in required if name not in bundle]
    if missing:
        return 1, "CHAIN FAIL missing fields: " + ", ".join(missing)

    declared_keyid = bundle["keyid"]
    declared_tip = bundle["chain_tip"]
    receipts = bundle["receipts"]
    if not isinstance(declared_keyid, str) or not HEX_16.fullmatch(declared_keyid):
        return 1, "CHAIN FAIL keyid must be 16 lowercase hexadecimal characters"
    if not isinstance(declared_tip, str) or not HEX_64.fullmatch(declared_tip):
        return 1, "CHAIN FAIL chain_tip must be 64 lowercase hexadecimal characters"
    if not isinstance(receipts, list) or not receipts:
        return 1, "CHAIN FAIL receipts must be a non-empty array"

    try:
        public_key = load_pubkey_raw_b64(str(bundle["public_key_raw_b64"]))
    except Exception as exc:  # malformed public-key bytes
        return 1, f"CHAIN FAIL public key is malformed: {exc}"

    observed_keyid = keyid(public_key)
    if observed_keyid != declared_keyid:
        return 1, f"CHAIN FAIL signer mismatch: declared={declared_keyid} observed={observed_keyid}"

    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            return 1, f"CHAIN FAIL receipt {index} is not an object"
        signatures = receipt.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            return 1, f"CHAIN FAIL receipt {index} has no signature"
        receipt_keyid = signatures[0].get("keyid") if isinstance(signatures[0], dict) else None
        if receipt_keyid != declared_keyid:
            return 1, (
                f"CHAIN FAIL receipt {index} signer mismatch: "
                f"declared={declared_keyid} receipt={receipt_keyid!r}"
            )

    result = verify_chain(receipts, public_key)
    if not result["all_links_valid"]:
        failed = [
            f"{row['index']}:{row['verdict']}"
            for row in result.get("verdicts", [])
            if row.get("verdict") == "FAIL" or not row.get("chain_link")
        ]
        return 1, "CHAIN FAIL verification failed at " + (", ".join(failed) or "unknown index")
    if result["tip"] != declared_tip:
        return 1, f"CHAIN FAIL tip mismatch: declared={declared_tip} observed={result['tip']}"

    return 0, f"CHAIN OK length={result['length']} tip={result['tip']} signer={declared_keyid}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle",
        nargs="?",
        type=pathlib.Path,
        default=ROOT / "receipts" / "demo_bundle.json",
        help="path to demo_bundle.json (default: receipts/demo_bundle.json)",
    )
    args = parser.parse_args(argv)
    try:
        bundle = load_bundle(args.bundle)
    except ValueError as exc:
        print(f"CHAIN FAIL {exc}", file=sys.stderr)
        return 1
    code, message = verify_bundle(bundle)
    print(message, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
