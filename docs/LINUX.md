# Linux deployment and operations lab

Run the collection pipeline as a restricted systemd service with a dedicated account, scheduled execution, JSON journal logs, process locking, and report-health checks.

**Validation status:** the POSIX worker, permissions, installer staging, and 49 automated tests have been validated on macOS. Ubuntu/systemd deployment is covered by the included CI workflow and the verification checklist below; check the latest Actions result for Linux execution evidence. Live AWS remains untested.

## 1. Run the worker locally first

From the project root on macOS or Linux:

```sh
python3 -m triage.worker --config examples/worker-local.json
python3 -m triage.worker --config examples/worker-local.json --health
```

Expected events: `job_started`, `collection_succeeded`, and `job_succeeded`, followed by a health result with `healthy: true`. The worker imports five synthetic records into four findings. Reports are under `reports/linux-local/fixture/reports/latest/`. Running again is supported: each completed run gets its own report bundle and updates the `latest` symlink.

No scheduler, service account, cloud resource, or VM is created by these local commands.

## 2. Install on an Ubuntu host

Target: Ubuntu 22.04 or 24.04 with Python 3.9+ and systemd as the service manager. Use an existing VM or EC2 host and copy this project into a working directory there. A plain container without a booted systemd is insufficient for the service-management exercise.

From the project root on that Ubuntu host:

```sh
sudo apt-get update
sudo apt-get install -y python3-venv
bash scripts/install-linux.sh --dry-run
sudo bash scripts/install-linux.sh --install
```

The installer copies only application modules, synthetic fixtures, configuration, and the two unit files. It creates a virtual environment without installing AWS dependencies, a non-login `cloud-triage` account, and private application state. It refuses existing application/configuration/state paths or an existing account/group with that name. It is a first-install helper, not an automatic updater. If an installation fails partway, inspect the named paths before retrying; it never deletes a prior installation to recover.

The service and timer are left stopped/disabled. No live AWS call is made.

| Path | Owner / permissions | Purpose |
| --- | --- | --- |
| `/opt/cloud-triage` | root; directories 755, source files 644 | Application and virtual environment |
| `/etc/cloud-triage` | root:cloud-triage; 750 | Service-readable configuration directory |
| `/etc/cloud-triage/config.json` | root:cloud-triage; 640 | Mode and file paths |
| `/etc/cloud-triage/owners.json` | root:cloud-triage; 640 | Account ownership map |
| `/var/lib/cloud-triage` | cloud-triage; 700 | Lock, database, status, and reports |
| `/etc/systemd/system/cloud-triage.*` | root; 644 | Service and timer units |

To inspect the file layout without installing, run `bash scripts/install-linux.sh --stage /absolute/new/directory`. Staging needs no root and creates no account, virtual environment, or active service. Staged unit files still contain their intended production paths; staging does not validate systemd execution.

## 3. Start and inspect a real Linux run

```sh
sudo systemd-analyze verify /etc/systemd/system/cloud-triage.service /etc/systemd/system/cloud-triage.timer
sudo systemctl start cloud-triage.service
sudo systemctl show cloud-triage.service -p Result -p ExecMainStatus -p User -p Group
sudo journalctl -u cloud-triage.service --no-pager -n 30 -o cat
sudo sed -n '1,70p' /var/lib/cloud-triage/fixture/reports/latest/report.md
```

The service is `Type=oneshot`: after a successful run it normally becomes inactive. Check `Result=success`, `ExecMainStatus=0`, the journal, and the report rather than expecting a continuously running process.

Run the read-only health check as the actual service user:

```sh
cd /opt/cloud-triage
sudo -u cloud-triage /opt/cloud-triage/venv/bin/python -m triage.worker --config /etc/cloud-triage/config.json --health
```

It exits 0 for a healthy completed collection/report, or 1 if stale, missing, invalid, or preceded by a failed/incomplete latest attempt. The default freshness threshold is 26 hours; use `--max-age-hours` to adjust it. It also checks that both output files exist and `latest` matches the success record. This is application-pipeline health, not proof of complete cloud coverage or a secure environment. The health command is not itself scheduled and does not send notifications.

## 4. Check the Linux permissions and service restrictions

```sh
id cloud-triage
sudo stat -c '%U %G %a %n' /etc/cloud-triage/config.json /var/lib/cloud-triage /var/lib/cloud-triage/fixture/triage.db
sudo -u cloud-triage test ! -w /opt/cloud-triage/triage/core.py
sudo -u cloud-triage test -w /var/lib/cloud-triage
sudo systemctl cat cloud-triage.service
sudo systemd-analyze security cloud-triage.service
```

The service user can write its state directory but cannot edit the root-owned application or configuration. The unit uses a restrictive umask, no privilege escalation, a read-only system filesystem, hidden home directories, private temporary space/devices, and restricted address families. `StateDirectory` provides the dedicated writable state location. Outbound networking remains available for the optional AWS reader. The systemd security assessment is a diagnostic, not a guarantee of security.

## 5. Enable a daily run

```sh
sudo systemctl enable --now cloud-triage.timer
systemctl list-timers cloud-triage.timer --all
systemd-analyze calendar '*-*-* 14:00:00 UTC'
```

The example timer runs daily at 14:00 UTC (7:00 a.m. Phoenix) plus up to five minutes of randomized delay. `Persistent=true` allows a missed calendar activation to be caught up when the timer becomes active. This does not reconstruct all findings that existed while the host was offline.

To pause collection while retaining application data:

```sh
sudo systemctl disable --now cloud-triage.timer
```

That stops future scheduling; it does not cancel a job already running. Wait for the oneshot service to finish before backing up the database or changing a live installation.

## 6. Practice a failure and recovery

1. In fixture mode, inspect the current journal and note the `latest` symlink target with `sudo readlink /var/lib/cloud-triage/fixture/reports/latest`.
2. Use `sudoedit /etc/cloud-triage/config.json` and temporarily change `fixture_path` to `/opt/cloud-triage/examples/missing.json`.
3. Start the service. Expect a nonzero result and `job_failed` / `FileNotFoundError` in the journal. The old report remains published.
4. Run the health command. Expect exit 1 even though the old successful report is still recent.
5. Restore `fixture_path` to `/opt/cloud-triage/examples/day1.json`, start the service again, and verify success plus healthy output.

No intentionally exposed AWS resources are needed for this exercise. Runtime logs contain event names, mode, run IDs, counts, and error types; they omit raw findings and exception messages. For detailed input-validation diagnostics, use the original CLI against the relevant fixture under the service account after stopping the scheduler.

## 7. Optional live AWS mode

On an EC2 host, use an instance IAM role with the required read permission from `docs/read-policy.json`. Use the AWS account's normal credential/role process. The default worker does not require keys in configuration. Because the unit hides home directories, it does not inherit your interactive user's `~/.aws` profile files; a profile configured only in your shell will not automatically work in the service.

Install the optional SDK into the application environment:

```sh
sudo /opt/cloud-triage/venv/bin/python -m pip install -r /opt/cloud-triage/requirements-aws.txt
sudoedit /etc/cloud-triage/config.json
```

Replace the config contents with the following, using your actual region:

```json
{
  "mode": "aws",
  "region": "us-west-2",
  "state_dir": "/var/lib/cloud-triage",
  "owners_path": "/etc/cloud-triage/owners.json"
}
```

Edit the ownership map for your accounts. Security Hub CSPM must already be enabled with readable findings in the selected region. Start the service manually, inspect journal counts and source evidence, and compare several records with the console before enabling the timer for live operation.

AWS data is stored beneath `/var/lib/cloud-triage/aws/`; synthetic data remains beneath `/var/lib/cloud-triage/fixture/`. For multiple AWS inventory scopes, use separately configured service instances/state directories; do not repeatedly repoint one AWS database at unrelated accounts/regions.

The project does not provision EC2, attach roles, change network rules, or enable paid AWS services.

## Runtime behavior

- A POSIX advisory file lock prevents overlapping worker runs. A second worker exits 75; a killed process releases the lock. Manual uses of the older CLI do not participate in the worker lock, so avoid running them against this database during scheduled collection.
- The database import is transactional. Report generation happens after that transaction: if reporting fails, the database may contain the successful import while the published report still belongs to the prior success. The failure status makes this visible.
- Reports are written into a new private directory. Only after both files are written is `latest` replaced with a relative symlink. Readers opening a file see a completed bundle; readers needing both files consistently should resolve `latest` once and use that bundle path.
- Status and success JSON are individually replaced atomically. A crash between publication and status updates may leave an incomplete attempt or a pointer/record mismatch; the health check flags it rather than claiming success.
- A 10-minute systemd startup timeout bounds a stuck oneshot job. A timeout or abrupt kill may leave `last-attempt.json` as `running`; the health check flags that state.
- Historical reports/snapshots are retained. No automatic retention cleanup is installed; plan backups and storage before sustained use.

## Ubuntu validation checklist

- Unit verification succeeds on Ubuntu.
- The service runs as `cloud-triage` and exits 0 in fixture mode.
- Journal events show the expected collection counts.
- Database/report files have private permissions.
- The health check detects a failed and a stale run.
- The failure drill retains the last completed report and recovers after configuration is restored.
- The timer shows its next activation in `systemctl list-timers`.

`.github/workflows/linux.yml` defines an Ubuntu 24.04 job that runs the tests, installs the fixture service, verifies the units, starts the service, and checks health. The workflow requires the project at the repository root with Actions enabled. A workflow definition alone does not demonstrate a successful deployment; inspect the run result and logs.

Official references: [systemd execution and isolation settings](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml), [systemd timers](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml).
