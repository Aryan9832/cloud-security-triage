"""Normalization, persistence, and local analyst decisions (standard library only)."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .insights import diff_snapshots, snapshot_for


SEVERITIES = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
DECISIONS = ("open", "remediate", "accepted-risk", "false-positive")
EXCEPTIONS = ("accepted-risk", "false-positive")


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    """Require timezone-aware timestamps; normalize offsets before comparisons."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp: " + value) from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone: " + value)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def required_text(item, key):
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing or invalid " + key)
    return value


def normalize(finding, owners):
    if not isinstance(finding, dict):
        raise ValueError("each finding must be an object")
    product = required_text(finding, "ProductArn")
    finding_id = required_text(finding, "Id")
    account = required_text(finding, "AwsAccountId")
    title = required_text(finding, "Title")
    updated = timestamp(required_text(finding, "UpdatedAt"))
    severity = (finding.get("Severity") or {}).get("Label", "UNKNOWN")
    if severity not in SEVERITIES and severity != "UNKNOWN":
        raise ValueError("unrecognized Severity.Label: " + str(severity))
    resources = finding.get("Resources", [])
    if not isinstance(resources, list) or not resources:
        raise ValueError("Resources must be a nonempty list")
    resource_ids, tag_owners = [], set()
    for resource in resources:
        resource_ids.append(required_text(resource, "Id"))
        tags = resource.get("Tags") or {}
        if not isinstance(tags, dict):
            raise ValueError("resource Tags must be an object")
        normalized_tags = {str(k).lower(): str(v).strip() for k, v in tags.items()}
        owner = normalized_tags.get("owner") or normalized_tags.get("team")
        if owner:
            tag_owners.add(owner)
    if tag_owners:
        owner = "; ".join(sorted(tag_owners))
        owner_source = "resource tags"
    elif account in owners:
        owner = owners[account]
        owner_source = "account fallback"
    else:
        owner, owner_source = "UNASSIGNED", "missing"
    record_state = finding.get("RecordState", "ACTIVE")
    workflow = (finding.get("Workflow") or {}).get("Status", "NEW")
    if record_state not in ("ACTIVE", "ARCHIVED"):
        raise ValueError("invalid RecordState")
    if workflow not in ("NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"):
        raise ValueError("invalid Workflow.Status")
    return {
        "product_arn": product, "finding_id": finding_id, "account": account,
        "title": title, "severity": severity, "owner": owner,
        "owner_source": owner_source, "resources": json.dumps(resource_ids),
        "record_state": record_state, "workflow": workflow,
        "source_updated": updated, "raw": json.dumps(finding, sort_keys=True),
    }


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                product_arn TEXT NOT NULL, finding_id TEXT NOT NULL,
                account TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                owner TEXT NOT NULL, owner_source TEXT NOT NULL, resources TEXT NOT NULL,
                record_state TEXT NOT NULL, workflow TEXT NOT NULL,
                source_updated TEXT NOT NULL, raw TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                decision TEXT NOT NULL DEFAULT 'open',
                reason TEXT, actor TEXT, expires TEXT, decision_source_updated TEXT,
                UNIQUE(product_arn, finding_id)
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY, finding INTEGER NOT NULL REFERENCES findings(id),
                previous TEXT NOT NULL, decision TEXT NOT NULL,
                reason TEXT NOT NULL, actor TEXT NOT NULL, expires TEXT,
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY, source TEXT NOT NULL, completed_at TEXT NOT NULL,
                received INTEGER NOT NULL, inserted INTEGER NOT NULL,
                updated INTEGER NOT NULL, unchanged INTEGER NOT NULL, stale INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS run_analytics (
                run_id INTEGER PRIMARY KEY REFERENCES runs(id),
                baseline_run_id INTEGER REFERENCES runs(id),
                baseline_kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS run_snapshots (
                run_id INTEGER NOT NULL REFERENCES runs(id),
                finding INTEGER NOT NULL REFERENCES findings(id),
                summary TEXT NOT NULL,
                PRIMARY KEY(run_id, finding)
            );
            CREATE TABLE IF NOT EXISTS finding_changes (
                id INTEGER PRIMARY KEY,
                run_id INTEGER NOT NULL REFERENCES runs(id),
                finding INTEGER NOT NULL REFERENCES findings(id),
                title TEXT NOT NULL, kind TEXT NOT NULL,
                before_value TEXT NOT NULL, after_value TEXT NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def ingest(self, findings, owners=None, source="file", now=None):
        # Validate/fetch the entire small batch before committing anything.
        records = [normalize(f, owners or {}) for f in findings]
        now = now or utcnow()
        observed = timestamp(now.isoformat())
        stats = dict(received=len(records), inserted=0, updated=0, unchanged=0, stale=0)
        with self.db:
            # Take the write lock before selecting the baseline and changing evidence.
            self.db.execute("BEGIN IMMEDIATE")
            prior = self.latest_run()
            tracked = prior and self.db.execute(
                "SELECT 1 FROM run_analytics WHERE run_id=?", (prior["id"],)).fetchone()
            if tracked:
                before = self.snapshots(prior["id"])
                baseline_kind, baseline_id = "previous-run", prior["id"]
            else:
                # Existing v1 databases have no historical snapshots. Start from their
                # current inventory; never invent a history or call every finding new.
                before = self.current_snapshot(now)
                baseline_kind = "existing-inventory" if prior or before else "first-import"
                baseline_id = None
            for record in records:
                old = self.db.execute(
                    "SELECT * FROM findings WHERE product_arn=? AND finding_id=?",
                    (record["product_arn"], record["finding_id"]),
                ).fetchone()
                if old is None:
                    fields = list(record) + ["first_seen", "last_seen"]
                    values = list(record.values()) + [observed, observed]
                    self.db.execute(
                        "INSERT INTO findings (" + ",".join(fields) + ") VALUES ("
                        + ",".join("?" for _ in fields) + ")", values,
                    )
                    stats["inserted"] += 1
                else:
                    if record["source_updated"] < old["source_updated"]:
                        stats["stale"] += 1
                    elif any(record[k] != old[k] for k in record):
                        self.db.execute(
                            "UPDATE findings SET " + ",".join(k + "=?" for k in record)
                            + " WHERE id=?", list(record.values()) + [old["id"]],
                        )
                        stats["updated"] += 1
                    else:
                        stats["unchanged"] += 1
                    self.db.execute("UPDATE findings SET last_seen=? WHERE id=?", (observed, old["id"]))
            cursor = self.db.execute(
                "INSERT INTO runs (source,completed_at,received,inserted,updated,unchanged,stale) "
                "VALUES (?,?,?,?,?,?,?)", (source, observed, *stats.values()),
            )
            run_id = cursor.lastrowid
            after = self.current_snapshot(now)
            self.db.execute("INSERT INTO run_analytics VALUES (?,?,?)", (run_id, baseline_id, baseline_kind))
            self.db.executemany("INSERT INTO run_snapshots VALUES (?,?,?)",
                                [(run_id, row_id, json.dumps(summary, sort_keys=True))
                                 for row_id, summary in after.items()])
            self.db.executemany(
                "INSERT INTO finding_changes (run_id,finding,title,kind,before_value,after_value) VALUES (?,?,?,?,?,?)",
                [(run_id, change["finding"], change["title"], change["kind"],
                  json.dumps(change["before"], sort_keys=True), json.dumps(change["after"], sort_keys=True))
                 for change in diff_snapshots(before, after)],
            )
        return stats

    def decide(self, finding_id, decision, reason, actor, expires=None, now=None):
        now = now or utcnow()
        if decision not in DECISIONS:
            raise ValueError("invalid decision")
        if not reason.strip() or not actor.strip():
            raise ValueError("reason and actor must not be blank")
        if decision in EXCEPTIONS:
            if not expires:
                raise ValueError("accepted risks and false positives require --expires")
            expires = timestamp(expires)
            if expires <= timestamp(now.isoformat()):
                raise ValueError("expiry must be in the future")
        elif expires:
            raise ValueError("--expires applies only to accepted-risk and false-positive")
        with self.db:
            old = self.db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if old is None:
                raise ValueError("finding ID does not exist: " + str(finding_id))
            self.db.execute(
                "UPDATE findings SET decision=?,reason=?,actor=?,expires=?,decision_source_updated=? WHERE id=?",
                (decision, reason, actor, expires, old["source_updated"], finding_id),
            )
            self.db.execute(
                "INSERT INTO decisions (finding,previous,decision,reason,actor,expires,recorded_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (finding_id, old["decision"], decision, reason, actor, expires, timestamp(now.isoformat())),
            )

    def findings(self):
        rows = [dict(row) for row in self.db.execute("SELECT * FROM findings")]
        return sorted(rows, key=lambda r: (-SEVERITIES.get(r["severity"], 6), r["id"]))

    def history(self, finding_id):
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM decisions WHERE finding=? ORDER BY id", (finding_id,))]

    def latest_run(self):
        row = self.db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def current_snapshot(self, now=None):
        now = now or utcnow()
        return {row["id"]: snapshot_for(row, effective_state(row, now)) for row in self.findings()}

    def snapshots(self, run_id):
        return {row["finding"]: json.loads(row["summary"]) for row in self.db.execute(
            "SELECT finding,summary FROM run_snapshots WHERE run_id=?", (run_id,))}

    def changes(self, run_id=None):
        latest = self.latest_run()
        if run_id is None:
            if latest is None:
                return {"run_id": None, "baseline_kind": "no-import", "changes": []}
            run_id = latest["id"]
        if not self.db.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
            raise ValueError("import run does not exist: " + str(run_id))
        metadata = self.db.execute("SELECT * FROM run_analytics WHERE run_id=?", (run_id,)).fetchone()
        result = dict(metadata) if metadata else {"run_id": run_id, "baseline_kind": "untracked", "baseline_run_id": None}
        result["changes"] = [
            {"finding": row["finding"], "title": row["title"], "kind": row["kind"],
             "before": json.loads(row["before_value"]), "after": json.loads(row["after_value"])}
            for row in self.db.execute("SELECT * FROM finding_changes WHERE run_id=? ORDER BY id", (run_id,))
        ]
        return result

    def trend(self, limit=7):
        if limit < 1 or limit > 100:
            raise ValueError("trend limit must be between 1 and 100")
        result = []
        for run in self.db.execute(
            "SELECT runs.* FROM runs JOIN run_analytics ON runs.id=run_analytics.run_id ORDER BY runs.id DESC LIMIT ?",
            (limit,),
        ):
            snapshots = list(self.snapshots(run["id"]).values())
            queue = [row for row in snapshots if row["actionable"]]
            result.append({"run_id": run["id"], "completed_at": run["completed_at"], "source": run["source"],
                           "total": len(snapshots), "actionable": len(queue),
                           "p1": sum(row["priority"] == "P1" for row in queue),
                           "unassigned": sum(row["owner"] == "UNASSIGNED" for row in queue)})
        return list(reversed(result))


def effective_state(finding, now=None):
    if finding["record_state"] == "ARCHIVED":
        return "provider-archived"
    if finding["workflow"] in ("RESOLVED", "SUPPRESSED"):
        return "provider-" + finding["workflow"].lower()
    if finding["decision"] in EXCEPTIONS:
        if not finding["expires"] or finding["expires"] <= timestamp((now or utcnow()).isoformat()):
            return "exception-expired"
        if finding["source_updated"] != finding["decision_source_updated"]:
            return "review-needed"
    return finding["decision"]


def actionable(finding, now=None):
    return effective_state(finding, now) in ("open", "remediate", "exception-expired", "review-needed")
