#!/usr/bin/env python3
"""north_star.py — compute the North Star metric from receipt logs.

North Star: verified governed actions per customer per month, with complete
evidence coverage and zero unauthorized executions.

Reads one or more receipt JSONL logs (receipts/*.jsonl) and emits the metric.
In production, each customer's receipts land in their own log; the metric is
per-customer-per-month. This tool makes the metric computable from day one
so the number exists before there is a dashboard.

Definitions (receipt fields, GovernedAction/v1):
  complete      every evidence item has present == true (boolean; L1)
  denied        execution.status == DENIED
  unauthorized  execution.status == EXECUTED while policy_decision.result != ALLOW

Boundary: this tool counts receipts. It does not verify signatures or chain
links (the logs do not carry their signing keys), so its totals are receipt
counts, not verified actions. Verify a chain with receipt_lib.verify_chain
(or examples/verify_demo_bundle.py for a demo bundle) before calling a count
verified.
"""
import json
import pathlib
import sys
from collections import defaultdict
from datetime import datetime


def _obj(value):
    return value if isinstance(value, dict) else {}


def parse_ts(r):
    ts = _obj(_obj(r.get("predicate")).get("timestamps")).get("created")
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def customer_of(r):
    # design: subject.name carries "customer:system" or falls back to actor id
    subj = _obj(r.get("subject")).get("name")
    if isinstance(subj, str) and ":" in subj:
        return subj.split(":")[0]
    actor_id = _obj(_obj(r.get("predicate")).get("actor")).get("id")
    return actor_id if isinstance(actor_id, str) else "unknown"


def summarize(paths):
    buckets = defaultdict(lambda: {"actions": 0, "complete": 0, "denied": 0, "unauthorized": 0})
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                pred = _obj(r.get("predicate"))
                ts = parse_ts(r)
                b = buckets[(customer_of(r), ts.strftime("%Y-%m") if ts else "unknown")]
                b["actions"] += 1
                items = _obj(pred.get("evidence")).get("items")
                if isinstance(items, list) and items and all(_obj(i).get("present") is True for i in items):
                    b["complete"] += 1
                status = _obj(pred.get("execution")).get("status")
                if status == "DENIED":
                    b["denied"] += 1
                if status == "EXECUTED" and _obj(pred.get("policy_decision")).get("result") != "ALLOW":
                    b["unauthorized"] += 1  # executed without an ALLOW decision
    return dict(buckets)


def main(paths):
    buckets = summarize(paths)
    print(f"{'customer':24s} {'month':8s} {'actions':>8s} {'complete':>9s} {'coverage':>9s} {'denied':>7s} "
          f"{'unauthorized':>13s}")
    for (cust, month), b in sorted(buckets.items()):
        cov = b["complete"] / b["actions"] if b["actions"] else 0
        print(f"{cust:24s} {month:8s} {b['actions']:8d} {b['complete']:9d} {cov:8.0%} {b['denied']:7d} "
              f"{b['unauthorized']:13d}")
    total = sum(b["actions"] for b in buckets.values())
    unauthorized = sum(b["unauthorized"] for b in buckets.values())
    print(f"\nTotal governed-action receipts across logs: {total} (signatures not verified by this tool)")
    print(f"Unauthorized executions (EXECUTED without ALLOW): {unauthorized}")
    print("North Star: verified governed actions / customer / month, with complete evidence coverage and zero unauthorized execution.")
    return 0


if __name__ == "__main__":
    paths = sys.argv[1:] or sorted(str(p) for p in pathlib.Path("receipts").glob("*.jsonl"))
    sys.exit(main(paths))
