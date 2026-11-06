"""North Star counts: completeness, denials and unauthorized executions."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import north_star  # noqa: E402


def receipt(result, status, present=True, subject="acme:payments", created="2026-11-06T10:00:00+00:00"):
    return {"subject": {"name": subject},
            "predicate": {"policy_decision": {"result": result}, "execution": {"status": status},
                          "evidence": {"items": [{"present": present}]},
                          "timestamps": {"created": created}, "actor": {"id": "agent://x"}}}


def write_log(tmp_path, rows):
    path = tmp_path / "log.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_unauthorized_means_executed_without_allow(tmp_path):
    log = write_log(tmp_path, [
        receipt("ALLOW", "EXECUTED"),
        receipt("DENY", "EXECUTED"),     # executed despite DENY: unauthorized
        receipt("ALLOW", "DENIED"),      # approved but blocked or dry-run: not unauthorized
        receipt("DENY", "DENIED"),
    ])
    bucket = north_star.summarize([log])[("acme", "2026-11")]
    assert bucket == {"actions": 4, "complete": 4, "denied": 2, "unauthorized": 1}


def test_only_boolean_true_counts_as_present(tmp_path):
    log = write_log(tmp_path, [receipt("ALLOW", "EXECUTED", present=p) for p in (True, "true", 1, False, None)])
    bucket = north_star.summarize([log])[("acme", "2026-11")]
    assert bucket["actions"] == 5 and bucket["complete"] == 1


def test_unparseable_timestamps_are_bucketed_as_unknown(tmp_path):
    log = write_log(tmp_path, [receipt("ALLOW", "EXECUTED", created=c) for c in ("not a date", 20261106)])
    assert north_star.summarize([log])[("acme", "unknown")]["actions"] == 2


def test_committed_logs_report_counts_and_the_verification_boundary():
    logs = sorted(str(p) for p in (ROOT / "receipts").glob("*.jsonl"))
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "north_star.py"), *logs],
                            capture_output=True, text=True, check=True)
    total = sum(b["actions"] for b in north_star.summarize(logs).values())
    assert f"Total governed-action receipts across logs: {total} (signatures not verified" in result.stdout
    assert "Unauthorized executions (EXECUTED without ALLOW): 0" in result.stdout
