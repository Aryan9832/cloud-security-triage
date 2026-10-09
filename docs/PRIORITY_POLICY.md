# Local review priority: local-v1

The tool preserves provider severity and calculates a separate review priority. These rules are a transparent project policy, not CVSS, an AWS rating, a validated risk model, or a remediation SLA.

## Rules

Apply the first matching severity/context rule, then the exception rule:

| Condition | Priority | Reason |
| --- | --- | --- |
| CRITICAL severity | P1 | First review regardless of tags |
| HIGH plus a resource tagged production and InternetExposed=true | P1 | High severity with declared production exposure |
| HIGH or UNKNOWN severity | P2 | Prompt review; missing severity must be investigated |
| MEDIUM plus a resource tagged production and InternetExposed=true | P2 | Raise review priority for declared production exposure |
| Other MEDIUM | P3 | Schedule investigation |
| LOW or INFORMATIONAL | P4 | Routine review |
| Exception expired or source changed since exception review | At least P2 | Require renewed analyst review; never reduce a P1 |

Only actionable findings appear in the queue. A P1 attached to an archived finding or an unexpired accepted risk does not put that finding in the current work queue. The state remains visible with the priority in evidence details.

## Where context comes from

Resource tags are read from ASFF `Resources[].Tags`. Keys are case-insensitive. `Environment` (or `Env`) supplies the environment; `prod` is normalized to `production`. `InternetExposed` accepts explicit `true` or `false`, case-insensitively. Missing or unrecognized values are unknown.

Production and exposure must belong to the same resource. Production on resource A and public exposure on resource B do not combine into a production-exposure boost. All resource context used in a decision is retained in the import snapshot and report.

The tool never infers exposure from the title, looks up a live route table, or tests a network connection. A tag claiming `false` is not proof that a resource is private. Missing tags do not establish safety. Analysts still validate the source evidence before taking action.

## Example from the demo

| Finding | Source severity | Declared environment | Declared exposure | Priority |
| --- | --- | --- | --- | --- |
| Production PostgreSQL ingress | HIGH | production | true | P1 |
| Development admin ingress | HIGH | development | true | P2 |
| Changed access-key exception | HIGH | production | unknown | P2, renewed review |

The first two rows have equal source severity but different queue placement. The input tags, matching rule, final priority, and regression tests make that difference explicit.

## What to change after real feedback

Calibrate priorities with a security team before relying on them operationally. Candidate inputs include verified reachability, data sensitivity, exploit evidence, and asset criticality. Add only inputs with a reliable source and a testable rule; retain unknown states instead of inventing a value. Version policy changes so historical decisions remain explainable.
