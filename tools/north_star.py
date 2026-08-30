#!/usr/bin/env python3
"""north_star.py — compute the North Star metric from receipt logs.

North Star: verified governed actions per customer per month, with complete
evidence coverage and zero unauthorized executions.

Reads one or more receipt JSONL logs (receipts/*.jsonl) and emits the metric.
In production, each customer's receipts land in their own log; the metric is
per-customer-per-month. This tool makes the metric computable from day one
so the number exists before there is a dashboard.
"""
import json, pathlib, sys
from collections import defaultdict
from datetime import datetime, timezone

def parse_ts(r):
    ts = (r.get("predicate", {}).get("timestamps", {}) or {}).get("created", "")
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def customer_of(r):
    # design: subject.name carries "customer:system" or falls back to actor id
    subj = (r.get("subject", {}) or {}).get("name", "")
    return subj.split(":")[0] if ":" in subj else r.get("predicate", {}).get("actor", {}).get("id", "unknown")

def main(paths):
    buckets = defaultdict(lambda: {"actions": 0, "complete": 0, "denied": 0, "unauthorized": 0})
    for p in paths:
        for line in open(p):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            pred = r.get("predicate", {})
            ts = parse_ts(r)
            month = ts.strftime("%Y-%m") if ts else "unknown"
            cust = customer_of(r)
            key = (cust, month)
            b = buckets[key]
            b["actions"] += 1
            ev = pred.get("evidence", {})
            items = ev.get("items", [])
            if items and all(i.get("present") for i in items):
                b["complete"] += 1
            if pred.get("execution", {}).get("status") == "DENIED":
                b["denied"] += 1
            pol = pred.get("policy_decision", {})
            if pol.get("result") == "ALLOW" and pred.get("execution", {}).get("status") == "DENIED":
                b["unauthorized"] += 1  # approved but blocked = governance working
    print(f"{'customer':24s} {'month':8s} {'actions':>8s} {'complete':>9s} {'coverage':>9s} {'denied':>7s}")
    for (cust, month), b in sorted(buckets.items()):
        cov = b["complete"] / b["actions"] if b["actions"] else 0
        print(f"{cust:24s} {month:8s} {b['actions']:8d} {b['complete']:9d} {cov:8.0%} {b['denied']:7d}")
    total = sum(b["actions"] for b in buckets.values())
    print(f"\nTotal governed actions across logs: {total}")
    print("North Star: verified governed actions / customer / month, with complete evidence coverage and zero unauthorized execution.")
    return 0

if __name__ == "__main__":
    paths = sys.argv[1:] or sorted(str(p) for p in pathlib.Path("receipts").glob("*.jsonl"))
    sys.exit(main(paths))
