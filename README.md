# Cloud Findings Triage Bot

A Python CLI for collecting AWS Security Hub CSPM findings, assigning ownership, recording triage decisions, and tracking changes between imports. Includes explainable prioritization, Markdown/CSV reports, and a systemd deployment configuration.

## Start here

Python 3.9+ on Linux or macOS is sufficient for the local demo and test suite. No AWS account or third-party Python package is needed. Live AWS collection requires Boto3.

Run these commands from this project directory:

```sh
python3 demo.py --out reports/my-demo
python3 -m unittest discover -s tests -v
```

Open `reports/my-demo/day2/report.md`, then `reports/my-demo/day3/report.md` and `reports/my-demo/day3-repeat/report.md`. The demo uses a fixed three-day clock and synthetic AWS findings, including an intentionally stale duplicate. It creates a local SQLite database. To repeat it, choose a new output directory. Reports and databases are generated locally and excluded from version control.

| Demonstration | Expected result |
| --- | --- |
| Import five day-one records | Four findings; one stale duplicate ignored |
| Route findings | Resource Owner/Team tags first; account fallback second; otherwise UNASSIGNED |
| Record remediation and a temporary risk acceptance | Reason, analyst name, expiry, and prior state retained |
| Import day-two updates | Report shows bucket resolution, key severity increase, ownership change, and exception review |
| Import day-three updates | Detect bucket reopening and two new findings |
| Compare two HIGH findings | Production/public resource receives P1; development/public resource receives P2, with written reasons |
| Inspect final report | Six findings retained; five actionable; three P1 |
| Repeat day-three import | Zero new change events |

## Behavior

- Finding identity uses `(ProductArn, Id)`, not the title. Repeated imports do not create duplicate work items.
- Older source updates cannot overwrite newer evidence.
- Local analyst decisions survive imports and remain separate from the provider workflow.
- Risk acceptances and false-positive decisions require an expiry. Expired exceptions return to the queue; changed source timestamps trigger review even before expiry.
- Resolved and archived findings remain available as evidence.
- Complete input validation and API retrieval precede the database transaction, so a failed second API page cannot leave a half-imported run.
- Reports show the last successful import and distinguish provider status from local triage.
- Successful imports retain snapshots and before/after changes: severity, ownership, declared context, local decisions, resolution, and reopening.
- A documented local policy explains each priority using source severity, asset context, and exception status. Source severity is never overwritten.
- Reports include owner workload and a trend of inventory counts across imports. Snapshot timestamps distinguish historical counts from current triage state.
- Existing v1 databases gain the new history tables automatically. Historical changes before that upgrade are marked unavailable, not reconstructed.

See [Priority policy](docs/PRIORITY_POLICY.md) for the exact rules and assumptions. The 49 automated tests cover ingestion, state transitions, transactional rollback, schema upgrades, locking, permissions, and report-publication failures.

## Linux deployment support

The project includes a systemd oneshot service and daily timer, a dedicated non-login account, restricted file permissions, JSON journal logging, an overlap lock, and a report freshness check. It starts with synthetic data; AWS mode is optional and uses separate state.

Try the worker locally on macOS or Linux:

```sh
python3 -m triage.worker --config examples/worker-local.json
python3 -m triage.worker --config examples/worker-local.json --health
```

See [Linux deployment](docs/LINUX.md) for installation, service operations, failure recovery, and AWS role setup. Local validation covers the POSIX worker and installer staging on macOS. Ubuntu/systemd execution requires a Linux host; the included Actions workflow checks that deployment. Live AWS integration is not yet validated.

## Use the CLI yourself

```sh
# Use a separate database from the scripted demo.
python3 -m triage ingest examples/day1.json --owners examples/owners.json
python3 -m triage list

# IDs below are for a fresh database; inspect `list` when using another database.
python3 -m triage triage 1 remediate --actor analyst --reason "Verified public bucket policy; owner will remove it"
python3 -m triage history 1
python3 -m triage report --out reports/my-first-report

# Test updates and repeatability.
python3 -m triage ingest examples/day2.json --owners examples/owners.json
python3 -m triage ingest examples/day2.json --owners examples/owners.json
python3 -m triage report --out reports/my-second-report

# Inspect net changes and historical counts; use --run to revisit an older import.
python3 -m triage changes
python3 -m triage changes --run 2
python3 -m triage trend
```

The decisions are `open`, `remediate`, `accepted-risk`, and `false-positive`. For either exception, pass `--expires` with a future timezone-aware timestamp, such as `2026-10-20T17:00:00Z` while that date is still in the future. Every decision requires `--actor` and `--reason`. The actor is a self-reported name, not an authenticated identity.

The global `--db` argument precedes the command:

```sh
python3 -m triage --db reports/my-demo/demo.db history 3
python3 -m triage --db reports/my-demo/demo.db changes --run 3
```

## Optional AWS connection

This adapter reads **Security Hub CSPM ASFF findings through GetFindings**. It does not implement the separate OCSF/GetFindingsV2 format. A region with Security Hub CSPM already enabled and usable AWS credentials is needed. This project does not enable cloud services or create cloud resources.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-aws.txt
.venv/bin/python -m triage --db data/aws.db sync --region us-west-2 --profile your-profile --owners examples/owners.json
.venv/bin/python -m triage --db data/aws.db report --out reports/aws
```

Replace the example account ownership map with your own. Boto3 uses its normal credential chain; do not add access keys to source code. The adapter paginates and uses bounded SDK retries. It reads all provider states so updates can close findings locally. It never sends local decisions back to AWS.

The relevant API permission is `securityhub:GetFindings`; use the policy example in `docs/read-policy.json`, alongside whatever credential/role-assumption permissions your environment requires. Only one configured region is queried per invocation. Aggregation depends on your existing AWS setup.

The optional adapter is tested with a fake paginated client. **Live AWS authentication, permissions, and account behavior have not been verified.**

Official references: [Boto3 GetFindings paginator](https://docs.aws.amazon.com/boto3/latest/reference/services/securityhub/paginator/GetFindings.html), [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html).

## Project map

```text
triage/core.py          Normalize evidence, SQLite storage, triage state
triage/sources.py       Local JSON and optional AWS ingestion
triage/insights.py      Explained priority rules and before/after comparisons
triage/worker.py        Locked collection/report job, JSON logs, freshness checks
triage/reporting.py     Markdown and CSV output
triage/__main__.py      Command-line interface
examples/              Synthetic three-day findings and owner mapping
tests/                 Core, change-tracking, priority, and upgrade tests
deploy/linux/          systemd service/timer and fixture-mode configuration
scripts/install-linux.sh  First-install helper with dry-run/staging modes
.github/workflows/linux.yml  Prepared Ubuntu/systemd verification job
docs/LINUX.md           Linux deployment, operations, and failure-recovery lab
docs/RUNBOOK.md         Daily operation and troubleshooting
docs/DESIGN.md          Scope, architecture, and trade-offs
docs/PRIORITY_POLICY.md Exact rules, assumptions, and example decisions
```

## Scope boundaries

This is a single-analyst local tool. It is not a cloud misconfiguration scanner: it processes findings from an existing source. Deduplication is by source identity, not cross-tool semantic similarity. Tag enrichment uses the tags supplied in findings; it does not call a separate inventory API. The P1-P4 ordering is a local review policy, not CVSS, an AWS rating, an SLA, or a claim of exploitability. Exposure tags are declared metadata and are not proof of network reachability.

The database stores the latest raw evidence, local decision history, and compact snapshots of the accumulated inventory at each successful import. It does not retain every raw historical provider payload. Snapshot storage grows with findings multiplied by successful imports; no retention policy is installed. All source updates invalidate a temporary exception for review; this conservative choice can create extra work for sources that update timestamps frequently. Imports are materialized in memory, making this version suitable for a small lab/account rather than a large organization. Absence from an import is never treated as resolution.

Local databases and generated reports may contain account/resource data when live AWS is used. Generated data is git-ignored. Source code and example fixtures contain only synthetic data.
