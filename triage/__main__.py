import argparse
import json
import sqlite3
import sys

from .core import DECISIONS, Store, effective_state
from .insights import priority_for
from .reporting import write_reports
from .sources import aws_findings, read_file, read_owners


def parser():
    root = argparse.ArgumentParser(description="Collect, deduplicate, and triage Security Hub CSPM findings.")
    root.add_argument("--db", default="data/triage.db", help="SQLite database path")
    commands = root.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest", help="Import an ASFF JSON export")
    ingest.add_argument("path")
    ingest.add_argument("--owners", help="JSON mapping of AWS account IDs to teams")
    sync = commands.add_parser("sync", help="Read findings from one AWS region")
    sync.add_argument("--region", required=True)
    sync.add_argument("--profile")
    sync.add_argument("--owners")
    commands.add_parser("list", help="List findings and local IDs")
    changes = commands.add_parser("changes", help="Show before/after changes for a successful import")
    changes.add_argument("--run", type=int, help="Run ID; defaults to the most recent import")
    trend = commands.add_parser("trend", help="Show inventory and priority counts across imports")
    trend.add_argument("--limit", type=int, default=7)
    decide = commands.add_parser("triage", help="Record a local analyst decision")
    decide.add_argument("id", type=int)
    decide.add_argument("decision", choices=DECISIONS)
    decide.add_argument("--reason", required=True)
    decide.add_argument("--actor", required=True)
    decide.add_argument("--expires", help="Timezone-aware timestamp; required for exceptions")
    history = commands.add_parser("history", help="Show the decision audit trail")
    history.add_argument("id", type=int)
    report = commands.add_parser("report", help="Write Markdown and CSV reports")
    report.add_argument("--out", default="reports/latest")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    store = None
    try:
        store = Store(args.db)
        if args.command in ("ingest", "sync"):
            owners = read_owners(args.owners)
            if args.command == "ingest":
                records, source = read_file(args.path), "file:" + args.path
            else:
                records = aws_findings(args.region, args.profile)
                source = "aws:" + args.region + ":" + (args.profile or "default-credentials")
            print(json.dumps(store.ingest(records, owners, source), indent=2))
        elif args.command == "list":
            for row in store.findings():
                # JSON avoids rendering untrusted terminal control characters.
                print(json.dumps({k: row[k] for k in ("id", "severity", "title", "owner")}
                                 | {"state": effective_state(row)}
                                 | priority_for(row, effective_state(row))))
        elif args.command == "changes":
            print(json.dumps(store.changes(args.run), indent=2))
        elif args.command == "trend":
            print(json.dumps(store.trend(args.limit), indent=2))
        elif args.command == "triage":
            store.decide(args.id, args.decision, args.reason, args.actor, args.expires)
            print("Recorded local decision for finding " + str(args.id))
        elif args.command == "history":
            print(json.dumps(store.history(args.id), indent=2))
        else:
            for path in write_reports(store, args.out):
                print(path)
        return 0
    except (ValueError, OSError, sqlite3.Error, TypeError, AttributeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        # AWS errors are optional dependencies; preserve unexpected programming errors.
        if type(exc).__module__.startswith("botocore"):
            print("AWS error: " + str(exc), file=sys.stderr)
            return 1
        raise
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
