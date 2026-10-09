# Daily operator runbook

## Import and report

1. Run a local import or the optional AWS sync against the intended database.
2. Check the exit status. A failure must not be presented as a fresh successful report.
3. Generate reports only after a successful import. Review source, last successful import time, received/new/stale counts, and the change summary. Use `changes --run ID` to inspect an earlier successful import.
4. Work through the P1/P2 queue and its written reasons. Review reopened findings, severity increases, missing owners, expired exceptions, and exceptions requiring renewed review. Confirm declared asset tags against source evidence before relying on them.
5. Verify source evidence and record a local decision with a concrete reason. For remediation, name the owner and the specific next action in the reason.
6. After the owner fixes a resource, import the provider's updated finding. A local `remediate` decision alone never proves resolution.

For a scheduler you configure yourself, run from the project directory and chain success explicitly:

```sh
python3 -m triage --db data/aws.db sync --region us-west-2 --profile your-profile --owners examples/owners.json && python3 -m triage --db data/aws.db report --out reports/latest
```

Use absolute executable/project paths in a real scheduler. For the Linux worker, systemd service/timer, health checks, and failure recovery, follow `LINUX.md`. The installer leaves the units stopped and disabled until activated by the operator. The project does not send notifications.

## Triage examples

- **Remediate:** "Confirmed inbound TCP/22 from 0.0.0.0/0; developer-infrastructure to restrict source CIDRs and verify access."
- **Accepted risk:** "Service owner plans credential rotation during the scheduled migration; exception expires at the end of that window." Set a concrete expiry and record the owner's actual approval when applicable.
- **False positive:** "Verified the scanner evaluated an outdated resource configuration; attached source evidence reference; recheck before expiry."

Do not label a finding a false positive merely because it is inconvenient or low priority. The tool records the analyst's judgment; it does not validate the underlying cloud condition.

## Read the new report sections

- **What changed:** net transitions from the previous successful snapshot. A single finding may have several events, such as both increased severity and a changed owner. First imports label findings new; old untracked runs explicitly lack history.
- **Work queue:** current actionable findings, sorted by explained local priority. Provider severity remains visible separately.
- **Owner workload:** actionable counts and P1 counts by owner; an owner string listing several teams represents shared ownership, not duplicated findings.
- **Recent import trend:** historical inventory counts frozen at collection time. Decisions or expiries occurring later may make the current queue differ from the last point.

`python3 -m triage changes` defaults to the latest run. A duplicate rerun usually has no events; use `--run` to inspect the earlier changed run. `python3 -m triage trend --limit 7` returns recent counts as JSON.

## Troubleshooting

| Symptom | Check and action |
| --- | --- |
| Invalid finding or timestamp | Inspect required Id, ProductArn, AwsAccountId, Title, UpdatedAt, Resources. Timezones are mandatory. Fix the input and rerun; the rejected batch was not applied. |
| Missing AWS package | Install requirements-aws.txt in a virtual environment. Local fixture mode has no dependency. |
| Credentials expired or AccessDenied | Verify the intended AWS profile/role and GetFindings permission. Renew credentials through the normal account workflow. |
| AWS region returns no findings | Confirm the intended region/account, service enablement, and existing aggregation. Empty input does not close older findings. |
| Duplicate findings remain | Check ProductArn and Id. Different source identities are intentionally separate, even when titles match. |
| Owner is UNASSIGNED | Add an account fallback mapping or supply source resource Owner/Team tags, then reimport current evidence. |
| Exception appears again | Check expiry and source UpdatedAt. Review the new evidence before recording another exception. |
| Report looks old | Compare generated time against last successful import. Generating a report does not refresh AWS data. |
| SQLite database locked | Stop the overlapping writer and retry. This version assumes a single analyst/job. |
| HIGH finding appears as P1 | Inspect the priority reason and same-resource production/exposure tags. P1 is local priority; the source HIGH severity has not been changed. |
| Change summary is empty after rerunning | The replay had no net tracked changes. Inspect the earlier import with `changes --run ID`. |
| An old run says untracked | It predates snapshots. New imports collect history; previous changes cannot be reconstructed from the latest evidence. |

## Recovery

Stop writers before copying the database for backup. Keep the database with its source environment: mixing sample data and real AWS data obscures coverage. A lost local database can be repopulated from source findings, but local analyst decisions require a backup to recover. Store raw imports separately if you need complete historical provider evidence.
