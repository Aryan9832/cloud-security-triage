"""Portable analyst reports; render external text as data."""

import csv
import html
import json
from collections import Counter
from pathlib import Path

from .core import actionable, effective_state, utcnow
from .insights import priority_for, PRIORITY_POLICY


def md(value):
    value = html.escape(str(value), quote=False)
    for character in ("\\", "`", "*", "_", "[", "]", "|"):
        value = value.replace(character, "\\" + character)
    return value.replace("\r", " ").replace("\n", " ")


def csv_cell(value):
    value = str(value)
    # Also protect values with leading whitespace before a formula marker.
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def write_reports(store, output, now=None):
    now = now or utcnow()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = store.findings()
    priorities = {r["id"]: priority_for(r, effective_state(r, now)) for r in rows}
    queue = sorted([r for r in rows if actionable(r, now)], key=lambda r: priorities[r["id"]]["priority"])
    counts = Counter(effective_state(r, now) for r in rows)
    run = store.latest_run()
    lines = ["# Cloud findings triage report", "", "Generated (UTC): " + now.isoformat(), "",
             "Findings: **%d** · Needs action: **%d** · Unassigned actionable: **%d**" % (
                 len(rows), len(queue), sum(r["owner"] == "UNASSIGNED" for r in queue)), ""]
    if run:
        lines.extend([
            "Last successful import: " + run["completed_at"],
            "Source: " + md(run["source"]),
            "Import records: {received}; new: {inserted}; updated: {updated}; unchanged: {unchanged}; stale ignored: {stale}.".format(**run), "",
        ])
    else:
        lines.extend(["No successful import has been recorded.", ""])
    delta = store.changes()
    changes = delta["changes"]
    lines.extend(["This is the accumulated local inventory. Missing findings are not assumed resolved.", "",
                  "## What changed at the latest import", "",
                  "Run: " + str(delta["run_id"]) + "; baseline: " + delta["baseline_kind"]
                  + (" (run " + str(delta["baseline_run_id"]) + ")" if delta.get("baseline_run_id") else "") + ".", ""])
    if delta["baseline_kind"] == "untracked":
        lines.extend(["This older import predates change tracking; historical changes are unavailable.", ""])
    elif changes:
        changed_findings = len({change["finding"] for change in changes})
        lines.append("**%d findings changed; %d change events.** A finding can have multiple events." % (changed_findings, len(changes)))
        lines.append("")
        for kind, count in sorted(Counter(change["kind"] for change in changes).items()):
            lines.append("- " + kind + ": " + str(count))
        lines.extend(["", "| Finding ID | Change | Before | After |", "| --- | --- | --- | --- |"])
        for change in changes:
            def display(value):
                return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            lines.append("| " + " | ".join(md(value) for value in (
                change["finding"], change["kind"], display(change["before"]), display(change["after"]))) + " |")
        lines.append("")
    else:
        lines.extend(["No tracked changes at this import.", ""])
    lines.extend(["Import changes are frozen at collection time. The queue below reflects decisions and expiries at report time.", "",
                  "## Work queue", "", "Sorted by local priority, then source severity. Policy: " + PRIORITY_POLICY + ".", "",
                  "Priority is an explainable project policy, not CVSS. Exposure/environment tags are declared context, not verified reachability.", "",
                  "| ID | Priority | Severity | Finding | Owner | State |",
                  "| --- | --- | --- | --- | --- | --- |"])
    for row in queue:
        lines.append("| " + " | ".join(md(v) for v in (
            row["id"], priorities[row["id"]]["priority"], row["severity"], row["title"], row["owner"], effective_state(row, now))) + " |")
    if not queue:
        lines.append("| N/A | N/A | N/A | No actionable findings in the local inventory | N/A | N/A |")
    lines.extend(["", "## Owner workload", "", "| Owner | Actionable | P1 |", "| --- | --- | --- |"])
    for owner, count in sorted(Counter(row["owner"] for row in queue).items()):
        p1 = sum(row["owner"] == owner and priorities[row["id"]]["priority"] == "P1" for row in queue)
        lines.append("| " + md(owner) + " | " + str(count) + " | " + str(p1) + " |")
    lines.extend(["", "## Recent import trend", "",
                  "Historical counts reflect the inventory at each successful import, including findings not seen in that import.", "",
                  "| Run | Completed (UTC) | Total | Actionable | P1 | Unassigned |",
                  "| --- | --- | --- | --- | --- | --- |"])
    for point in store.trend():
        lines.append("| " + " | ".join(md(point[key]) for key in (
            "run_id", "completed_at", "total", "actionable", "p1", "unassigned")) + " |")
    lines.extend(["", "## State totals", ""])
    lines.extend("- " + state + ": " + str(count) for state, count in sorted(counts.items()))
    lines.extend(["", "## Evidence and triage details", ""])
    for row in rows:
        lines.extend([
            "### Finding " + str(row["id"]) + ": " + md(row["title"]), "",
            "- Source finding ID: " + md(row["finding_id"]),
            "- Product ARN: " + md(row["product_arn"]),
            "- Account: " + md(row["account"]),
            "- Resources: " + md("; ".join(json.loads(row["resources"]))),
            "- Owner: " + md(row["owner"]) + " (" + row["owner_source"] + ")",
            "- Severity: " + row["severity"],
            "- Local priority: " + priorities[row["id"]]["priority"] + " (" + PRIORITY_POLICY + ")",
            "- Why this priority: " + md(" ".join(priorities[row["id"]]["priority_reasons"])),
            "- Declared resource context: " + md(json.dumps(priorities[row["id"]]["context"], sort_keys=True)),
            "- Source updated: " + row["source_updated"],
            "- Last observed locally: " + row["last_seen"],
            "- Provider state: " + row["record_state"] + " / " + row["workflow"],
            "- Effective state: " + effective_state(row, now),
            "- Local decision: " + row["decision"],
            "- Reason: " + md(row["reason"] or "Not yet triaged"),
            "- Analyst: " + md(row["actor"] or "N/A"),
            "- Exception expiry: " + (row["expires"] or "N/A"), "",
        ])
    markdown_path = output / "report.md"
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    csv_path = output / "findings.csv"
    fields = ["id", "severity", "priority", "priority_policy", "priority_reasons", "title", "account", "owner", "owner_source", "effective_state",
              "decision", "reason", "actor", "expires", "source_updated", "last_seen", "finding_id", "product_arn", "resources"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            exported = dict(row, effective_state=effective_state(row, now), **priorities[row["id"]])
            exported["priority_reasons"] = " ".join(exported["priority_reasons"])
            writer.writerow({key: csv_cell(exported[key] if exported[key] is not None else "") for key in fields})
    return markdown_path, csv_path
