"""Replay a deterministic, fictional three-day analyst workflow and duplicate rerun."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from triage.core import Store
from triage.reporting import write_reports
from triage.sources import read_file, read_owners


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="reports/demo-v2", help="New directory for the demo database and reports")
    args = parser.parse_args()
    output = Path(args.out)
    if output.exists():
        parser.error("output already exists; choose a new directory with --out")
    root = Path(__file__).resolve().parent
    day1 = datetime(2026, 10, 9, 9, tzinfo=timezone.utc)
    day2 = datetime(2026, 10, 10, 9, tzinfo=timezone.utc)
    day3 = datetime(2026, 10, 11, 9, tzinfo=timezone.utc)
    owners = read_owners(root / "examples/owners.json")
    store = Store(output / "demo.db")
    try:
        stats = store.ingest(read_file(root / "examples/day1.json"), owners, "synthetic:day1", day1)
        print("Day 1: " + json.dumps(stats))
        write_reports(store, output / "day1-before-triage", day1)
        store.decide(1, "remediate", "Lab policy permits public reads; ask data-platform to remove it.", "demo-analyst", now=day1)
        store.decide(3, "accepted-risk", "Lab migration planned by October 16; revisit if source finding changes.",
                     "demo-analyst", "2026-10-16T17:00:00Z", day1)
        write_reports(store, output / "day1-after-triage", day1)
        stats = store.ingest(read_file(root / "examples/day2.json"), owners, "synthetic:day2", day2)
        print("Day 2: " + json.dumps(stats))
        write_reports(store, output / "day2", day2)
        print("Day 2 changes: " + ", ".join(sorted({c["kind"] for c in store.changes()["changes"]})))
        records = read_file(root / "examples/day3.json")
        stats = store.ingest(records, owners, "synthetic:day3", day3)
        print("Day 3: " + json.dumps(stats))
        write_reports(store, output / "day3", day3)
        print("Day 3 changes: " + ", ".join(sorted({c["kind"] for c in store.changes()["changes"]})))
        stats = store.ingest(records, owners, "synthetic:day3-repeat", day3)
        write_reports(store, output / "day3-repeat", day3)
        print("Repeated import: " + json.dumps(stats) + "; change events: " + str(len(store.changes()["changes"])))
        print("Open " + str(output / "day3/report.md"))
        print("Expected: 6 findings; 5 actionable; 3 P1. Production/public HIGH is P1; development/public HIGH is P2.")
        print("Repeat report: " + str(output / "day3-repeat/report.md") + " (no new change events)")
    finally:
        store.close()


if __name__ == "__main__":
    main()
