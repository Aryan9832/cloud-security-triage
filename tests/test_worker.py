from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from triage.core import Store
from triage.sources import read_file
from triage.worker import JobBusy, health, job_lock, load_config, main, run_once


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 12, 9, tzinfo=timezone.utc)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.config = {"mode": "fixture", "state_dir": str(self.base / "state"),
                       "fixture_path": str(ROOT / "examples/day1.json"),
                       "owners_path": str(ROOT / "examples/owners.json")}
        self.logs = io.StringIO()

    def run_job(self, config=None):
        with redirect_stdout(self.logs):
            return run_once(config or self.config, NOW)

    def test_success_publishes_complete_report_with_private_permissions(self):
        result = self.run_job()
        latest = self.base / "state/fixture/reports/latest"
        self.assertTrue(latest.is_symlink())
        self.assertEqual(latest.resolve(), Path(result["report_dir"]))
        self.assertTrue((latest / "report.md").is_file())
        self.assertTrue((latest / "findings.csv").is_file())
        self.assertEqual(stat.S_IMODE((self.base / "state/fixture/triage.db").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((latest / "report.md").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.base / "state/fixture").stat().st_mode), 0o700)
        self.assertTrue(health(self.config, now=NOW)["healthy"])
        events = [json.loads(line)["event"] for line in self.logs.getvalue().splitlines()]
        self.assertEqual(events, ["job_started", "collection_succeeded", "job_succeeded"])

    def test_repeated_worker_is_idempotent_and_keeps_previous_report_bundle(self):
        first = self.run_job()
        second = self.run_job()
        self.assertEqual(second["stats"]["inserted"], 0)
        self.assertEqual(second["stats"]["updated"], 0)
        self.assertNotEqual(first["report_dir"], second["report_dir"])
        self.assertTrue((Path(first["report_dir"]) / "report.md").exists())
        store = Store(self.base / "state/fixture/triage.db")
        self.addCleanup(store.close)
        self.assertEqual(store.changes()["changes"], [])

    def test_collection_failure_keeps_last_report_and_marks_health_failed(self):
        previous = self.run_job()
        success_path = self.base / "state/fixture/last-success.json"
        original_success = success_path.read_bytes()
        with patch("triage.worker.read_file", side_effect=ValueError("confidential-raw-payload")):
            with self.assertRaises(ValueError):
                self.run_job()
        self.assertEqual(success_path.read_bytes(), original_success)
        self.assertEqual((self.base / "state/fixture/reports/latest").resolve(), Path(previous["report_dir"]))
        self.assertFalse(health(self.config, now=NOW)["healthy"])
        self.assertNotIn("confidential-raw-payload", self.logs.getvalue())
        self.assertIn("job_failed", self.logs.getvalue())

    def test_reporting_failure_does_not_publish_partial_bundle(self):
        previous = self.run_job()
        with patch("triage.worker.write_reports", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.run_job()
        self.assertEqual((self.base / "state/fixture/reports/latest").resolve(), Path(previous["report_dir"]))
        attempt = json.loads((self.base / "state/fixture/last-attempt.json").read_text())
        self.assertEqual(attempt["phase"], "reporting")
        self.assertFalse(health(self.config, now=NOW)["healthy"])

    def test_overlapping_worker_cannot_change_status_or_inventory(self):
        self.run_job()
        original = (self.base / "state/fixture/last-attempt.json").read_bytes()
        with job_lock(self.config["state_dir"]):
            with self.assertRaises(JobBusy):
                self.run_job()
        self.assertEqual((self.base / "state/fixture/last-attempt.json").read_bytes(), original)
        self.assertEqual(self.run_job()["run_id"], 2)

    def test_health_detects_old_and_future_success_timestamps(self):
        self.run_job()
        self.assertFalse(health(self.config, now=NOW + timedelta(hours=27))["healthy"])
        self.assertFalse(health(self.config, now=NOW - timedelta(hours=1))["healthy"])
        self.assertTrue(health(self.config, now=NOW + timedelta(hours=25))["healthy"])

    def test_health_checks_do_not_create_state_on_an_uninitialized_host(self):
        self.assertFalse(health(self.config, now=NOW)["healthy"])
        self.assertFalse(Path(self.config["state_dir"]).exists())

    def test_missing_report_is_unhealthy_even_with_recent_success(self):
        result = self.run_job()
        (Path(result["report_dir"]) / "findings.csv").unlink()
        self.assertIn("a published report file is missing", health(self.config, now=NOW)["reasons"])

    def test_aws_and_fixture_modes_use_separate_databases(self):
        self.run_job()
        aws_config = dict(self.config, mode="aws", region="us-west-2")
        records = read_file(ROOT / "examples/day1.json")
        with patch("triage.worker.aws_findings", return_value=iter(records)) as reader:
            result = self.run_job(aws_config)
        reader.assert_called_once_with("us-west-2", None)
        self.assertEqual(result["run_id"], 1)
        self.assertTrue((self.base / "state/aws/triage.db").exists())
        self.assertTrue((self.base / "state/fixture/triage.db").exists())

    def test_config_relative_paths_resolve_beside_config_not_working_directory(self):
        path = self.base / "config.json"
        path.write_text(json.dumps({"mode": "fixture", "state_dir": "state", "fixture_path": "findings.json"}))
        config = load_config(path)
        self.assertEqual(config["state_dir"], str((self.base / "state").resolve()))
        self.assertEqual(config["fixture_path"], str((self.base / "findings.json").resolve()))

    def test_bad_configuration_is_rejected_before_state_creation(self):
        path = self.base / "config.json"
        cases = [{"mode": "aws", "state_dir": "state"},
                 {"mode": "fixture", "state_dir": "state", "typo": True},
                 {"mode": "fixture", "state_dir": "state", "fixture_path": []}]
        for case in cases:
            path.write_text(json.dumps(case))
            with self.assertRaises(ValueError):
                load_config(path)
        self.assertFalse((self.base / "state").exists())

    def test_umask_is_restored_after_failure(self):
        old = os.umask(0o027)
        try:
            with patch("triage.worker.read_file", side_effect=ValueError("bad input")):
                with self.assertRaises(ValueError):
                    self.run_job()
            observed = os.umask(0o027)
            self.assertEqual(observed, 0o027)
        finally:
            os.umask(old)

    def test_cli_exit_codes_are_usable_by_a_service_manager(self):
        path = self.base / "config.json"
        path.write_text(json.dumps(self.config))
        with redirect_stdout(self.logs):
            self.assertEqual(main(["--config", str(path), "--health"]), 1)
            self.assertEqual(main(["--config", str(path)]), 0)
            self.assertEqual(main(["--config", str(path), "--health"]), 0)
            with job_lock(self.config["state_dir"]):
                self.assertEqual(main(["--config", str(path)]), 75)


class InstallerTests(unittest.TestCase):
    def test_staging_handles_spaces_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            stage = Path(folder) / "staged linux package"
            command = ["bash", str(ROOT / "scripts/install-linux.sh"), "--stage", str(stage)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((stage / "opt/cloud-triage/triage/worker.py").is_file())
            self.assertTrue((stage / "etc/systemd/system/cloud-triage.service").is_file())
            self.assertEqual(stat.S_IMODE((stage / "etc/cloud-triage/config.json").stat().st_mode), 0o640)
            repeated = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 2)

    def test_installer_dry_run_and_shell_syntax(self):
        script = str(ROOT / "scripts/install-linux.sh")
        self.assertEqual(subprocess.run(["bash", "-n", script], capture_output=True).returncode, 0)
        result = subprocess.run(["bash", script, "--dry-run"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("no changes", result.stdout)


if __name__ == "__main__":
    unittest.main()
