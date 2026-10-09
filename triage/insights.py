"""Explainable local priority policy and successful-import change detection.

These are project policy rules, not CVSS, AWS severity, or measured exploitability.
Resource tags are declared context and never proof of network reachability.
"""

import json


ACTION_STATES = {"open", "remediate", "exception-expired", "review-needed"}
CLOSED_STATES = {"provider-resolved", "provider-archived", "provider-suppressed"}
SEVERITY_ORDER = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PRIORITY_POLICY = "local-v1"


def context_for(finding):
    resources = json.loads(finding["raw"]).get("Resources", [])
    context = []
    for resource in resources:
        tags = {str(k).lower(): str(v).strip().lower()
                for k, v in (resource.get("Tags") or {}).items()}
        environment = tags.get("environment", tags.get("env", "unknown"))
        if environment == "prod":
            environment = "production"
        exposed_tag = tags.get("internetexposed", "unknown")
        exposed = {"true": True, "false": False}.get(exposed_tag)
        context.append({"resource": resource["Id"], "environment": environment,
                        "internet_exposed": exposed})
    return sorted(context, key=lambda item: (item["resource"], item["environment"], str(item["internet_exposed"])))


def priority_for(finding, state):
    severity = finding["severity"]
    context = context_for(finding)
    # Production and exposure must refer to the SAME resource.
    exposed_production = any(r["environment"] == "production" and r["internet_exposed"] is True
                             for r in context)
    reasons = ["Source severity: " + severity + "."]
    if severity == "CRITICAL":
        priority = "P1"
        reasons.append("Critical source severity requires first review.")
    elif severity == "HIGH" and exposed_production:
        priority = "P1"
        reasons.append("A single resource is tagged production and InternetExposed=true.")
    elif severity in ("HIGH", "UNKNOWN"):
        priority = "P2"
        reasons.append("High or missing source severity requires prompt review.")
    elif severity == "MEDIUM" and exposed_production:
        priority = "P2"
        reasons.append("Medium severity is raised for a resource tagged production and InternetExposed=true.")
    elif severity == "MEDIUM":
        priority = "P3"
        reasons.append("Medium source severity; schedule investigation.")
    else:
        priority = "P4"
        reasons.append("Low or informational source severity; routine review.")
    if state in ("exception-expired", "review-needed"):
        priority = min(priority, "P2")
        reasons.append("Expired or changed exception needs renewed analyst review (at least P2).")
    if any(r["environment"] == "unknown" or r["internet_exposed"] is None for r in context):
        reasons.append("Some asset context is unknown; missing tags do not establish safety.")
    return {"priority": priority, "priority_policy": PRIORITY_POLICY,
            "priority_reasons": reasons, "context": context}


def snapshot_for(finding, state):
    summary = {key: finding[key] for key in (
        "id", "product_arn", "finding_id", "account", "title", "severity", "owner",
        "owner_source", "record_state", "workflow", "source_updated", "last_seen", "decision",
    )}
    summary.update(state=state, actionable=state in ACTION_STATES)
    summary.update(priority_for(finding, state))
    return summary


def diff_snapshots(before, after):
    """One net comparison per finding, regardless of duplicates within a batch."""
    changes = []
    for current in sorted(after.values(), key=lambda row: row["id"]):
        previous = before.get(current["id"])

        def add(kind, old, new):
            changes.append({"finding": current["id"], "title": current["title"],
                            "kind": kind, "before": old, "after": new})

        if previous is None:
            add("new-finding", None, {"severity": current["severity"], "owner": current["owner"],
                                      "state": current["state"], "priority": current["priority"]})
            continue
        if previous["severity"] != current["severity"]:
            old_rank, new_rank = (SEVERITY_ORDER.get(r["severity"]) for r in (previous, current))
            kind = "severity-changed"
            if old_rank is not None and new_rank is not None:
                kind = "severity-increased" if new_rank > old_rank else "severity-decreased"
            add(kind, previous["severity"], current["severity"])
        if previous["owner"] != current["owner"]:
            add("owner-changed", previous["owner"], current["owner"])
        if previous["context"] != current["context"]:
            add("context-changed", previous["context"], current["context"])
        if previous["priority"] != current["priority"]:
            add("priority-changed", previous["priority"], current["priority"])
        if previous["decision"] != current["decision"]:
            add("decision-changed", previous["decision"], current["decision"])
        if previous["state"] != current["state"]:
            if current["state"] in CLOSED_STATES:
                kind = current["state"]
            elif previous["state"] in CLOSED_STATES:
                kind = "provider-reopened"
            elif current["state"] == "review-needed":
                kind = "exception-review-required"
            elif current["state"] == "exception-expired":
                kind = "exception-expired"
            else:
                kind = "triage-state-changed"
            add(kind, previous["state"], current["state"])
    return changes
