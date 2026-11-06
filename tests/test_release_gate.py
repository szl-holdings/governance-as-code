"""The release gate reports every claim that is not current; only blockers fail it."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_gate  # noqa: E402

LEDGER = ROOT / "governance" / "CLAIMS_LEDGER.yaml"


def test_claims_are_partitioned_without_dropping_any(tmp_path):
    path = tmp_path / "ledger.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "claims": [
        {"id": "A", "claim": "a", "truth_state": "VERIFIED", "evidence": "e", "blocks_release": False},
        {"id": "B", "claim": "b", "truth_state": "ATTESTED", "evidence": "e"},
        {"id": "C", "claim": "c", "truth_state": "DEGRADED", "evidence": "e", "degraded": "stale",
         "blocks_release": False},
        {"id": "D", "claim": "d", "truth_state": "UNKNOWN", "blocks_release": True},
        {"id": "E", "claim": "e", "truth_state": "UNKNOWN"},
    ]}), encoding="utf-8")
    ok, blockers, not_current = release_gate.check_claims(path)
    assert [c["id"] for c in ok] == ["A", "B"]
    assert [c["id"] for c in blockers] == ["D"]
    assert [c["id"] for c in not_current] == ["C", "E"]


def test_gate_lists_every_non_current_claim():
    claims = yaml.safe_load(LEDGER.read_text(encoding="utf-8"))["claims"]
    not_current = [c for c in claims if c["truth_state"] not in release_gate.CURRENT_STATES]
    blocking = [c for c in not_current if c.get("blocks_release")]
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "release_gate.py")],
                            capture_output=True, text=True, check=False)
    assert result.returncode == (1 if blocking else 0), result.stdout
    assert f"not current (non-blocking): {len(not_current) - len(blocking)}" in result.stdout
    for c in not_current:
        label = "BLOCKER" if c.get("blocks_release") else c["truth_state"]
        assert f"[{label}] {c['id']}:" in result.stdout


def test_every_degraded_claim_records_why_it_is_stale():
    claims = yaml.safe_load(LEDGER.read_text(encoding="utf-8"))["claims"]
    for c in claims:
        if c["truth_state"] == "DEGRADED":
            assert c.get("degraded"), c["id"]
            assert c.get("evidence"), c["id"]
