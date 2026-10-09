import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from triage.core import Store, effective_state, normalize
from triage.insights import priority_for
from triage.reporting import write_reports
from triage.sources import read_file, read_owners


ROOT = Path(__file__).resolve().parents[1]
DAY1 = datetime(2026, 10, 9, 9, tzinfo=timezone.utc)
DAY2 = datetime(2026, 10, 10, 9, tzinfo=timezone.utc)
DAY3 = datetime(2026, 10, 11, 9, tzinfo=timezone.utc)


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.day1 = read_file(ROOT / "examples/day1.json")
        self.day2 = read_file(ROOT / "examples/day2.json")
        self.day3 = read_file(ROOT / "examples/day3.json")
        self.owners = read_owners(ROOT / "examples/owners.json")

    def ingest(self, records=None, now=DAY1):
        return self.store.ingest(self.day1 if records is None else records, self.owners, now=now)

    def kinds(self):
        return [event["kind"] for event in self.store.changes()["changes"]]

    def test_initial_snapshot_tracks_four_findings_not_five_input_records(self):
        self.ingest()
        result = self.store.changes()
        self.assertEqual(result["baseline_kind"], "first-import")
        self.assertEqual(self.kinds(), ["new-finding"] * 4)
        self.assertEqual(len(self.store.snapshots(result["run_id"])), 4)

    def test_repeat_import_adds_no_changes(self):
        self.ingest()
        self.ingest()
        self.assertEqual(self.store.changes()["baseline_kind"], "previous-run")
        self.assertEqual(self.store.changes()["baseline_run_id"], 1)
        self.assertEqual(self.kinds(), [])
        self.assertEqual(len(self.store.changes(1)["changes"]), 4)

    def test_changes_keep_before_after_evidence_for_owner_and_severity(self):
        self.ingest()
        self.ingest(self.day2, DAY2)
        changes = {e["kind"]: e for e in self.store.changes()["changes"] if e["finding"] == 3}
        self.assertEqual(changes["severity-increased"]["before"], "MEDIUM")
        self.assertEqual(changes["severity-increased"]["after"], "HIGH")
        self.assertEqual(changes["owner-changed"]["before"], "platform-security")
        self.assertEqual(changes["owner-changed"]["after"], "identity-platform")
        self.assertIn("provider-resolved", self.kinds())

    def test_net_change_only_even_when_batch_contains_multiple_updates(self):
        self.ingest()
        middle = copy.deepcopy(self.day2[1])
        middle["UpdatedAt"] = "2026-10-10T07:00:00Z"
        middle["Severity"]["Label"] = "LOW"
        self.ingest([middle, self.day2[1]], DAY2)
        changes = self.store.changes()["changes"]
        severity_changes = [c for c in changes if c["kind"].startswith("severity-")]
        self.assertEqual(len(severity_changes), 1)
        self.assertEqual((severity_changes[0]["before"], severity_changes[0]["after"]), ("MEDIUM", "HIGH"))

    def test_old_input_and_missing_findings_do_not_fabricate_resolutions(self):
        self.ingest()
        self.ingest([self.day1[-1]], DAY2)
        self.assertEqual(self.kinds(), [])
        self.assertEqual(self.store.trend()[-1]["total"], 4)
        self.assertEqual(self.store.trend()[-1]["actionable"], 3)

    def test_reopened_finding_is_labeled_and_retains_remediation_decision(self):
        self.ingest()
        self.store.decide(1, "remediate", "Remove public policy", "analyst", now=DAY1)
        self.ingest(self.day2, DAY2)
        self.ingest(self.day3, DAY3)
        event = next(e for e in self.store.changes()["changes"] if e["kind"] == "provider-reopened")
        self.assertEqual((event["before"], event["after"]), ("provider-resolved", "remediate"))
        self.assertEqual(self.store.snapshots(3)[1]["decision"], "remediate")

    def test_timestamp_refresh_alone_is_not_reported_as_changed_risk(self):
        self.ingest()
        refreshed = copy.deepcopy(self.day1[0])
        refreshed["UpdatedAt"] = "2026-10-10T08:00:00Z"
        self.ingest([refreshed], DAY2)
        self.assertEqual(self.kinds(), [])

    def test_exception_expiry_without_new_evidence_is_visible_at_next_import(self):
        self.ingest()
        self.store.decide(3, "accepted-risk", "Temporary migration", "analyst", "2026-10-10T09:00:00Z", DAY1)
        self.ingest([], DAY1)  # Snapshot accepted state.
        self.ingest([], DAY2)
        self.assertIn("exception-expired", self.kinds())
        self.assertEqual(self.store.snapshots(3)[3]["priority"], "P2")

    def test_priority_distinguishes_same_severity_production_and_development(self):
        production, development = [priority_for(normalize(f, {}), "open") for f in self.day3[:2]]
        self.assertEqual(production["priority"], "P1")
        self.assertEqual(development["priority"], "P2")
        self.assertIn("tagged production", " ".join(production["priority_reasons"]))

    def test_cannot_combine_production_from_one_resource_with_exposure_from_another(self):
        finding = copy.deepcopy(self.day3[0])
        second = copy.deepcopy(finding["Resources"][0])
        finding["Resources"][0]["Tags"]["InternetExposed"] = "false"
        second["Id"] += "-dev"
        second["Tags"]["Environment"] = "development"
        finding["Resources"].append(second)
        self.assertEqual(priority_for(normalize(finding, {}), "open")["priority"], "P2")

    def test_missing_tags_do_not_imply_internet_exposure_or_safety(self):
        finding = copy.deepcopy(self.day3[0])
        del finding["Resources"][0]["Tags"]
        policy = priority_for(normalize(finding, {}), "open")
        self.assertEqual(policy["priority"], "P2")
        self.assertIsNone(policy["context"][0]["internet_exposed"])
        self.assertIn("do not establish safety", " ".join(policy["priority_reasons"]))

    def test_tags_are_case_insensitive_and_medium_context_can_raise_priority(self):
        finding = copy.deepcopy(self.day3[0])
        finding["Severity"]["Label"] = "MEDIUM"
        finding["Resources"][0]["Tags"] = {"ENV": "Prod", "INTERNETEXPOSED": "TRUE"}
        self.assertEqual(priority_for(normalize(finding, {}), "open")["priority"], "P2")

    def test_snapshot_history_is_immutable_when_local_triage_changes(self):
        self.ingest()
        first = self.store.snapshots(1)
        self.store.decide(1, "remediate", "Remove public policy", "analyst", now=DAY2)
        self.assertEqual(self.store.snapshots(1), first)
        self.assertEqual(self.store.current_snapshot(DAY2)[1]["decision"], "remediate")

    def test_snapshot_write_failure_rolls_back_findings_and_run(self):
        self.ingest()
        original_rows = self.store.findings()
        with patch("triage.core.diff_snapshots", side_effect=RuntimeError("snapshot failure")):
            with self.assertRaisesRegex(RuntimeError, "snapshot failure"):
                self.ingest(self.day2, DAY2)
        self.assertEqual(self.store.findings(), original_rows)
        self.assertEqual(self.store.latest_run()["id"], 1)
        self.assertEqual(len(self.store.trend()), 1)

    def test_v1_database_upgrade_preserves_data_without_fabricating_history(self):
        self.ingest()
        self.store.decide(1, "remediate", "Existing decision", "analyst", now=DAY1)
        # Recreate the v1 schema in this disposable test database only.
        with self.store.db:
            for table in ("finding_changes", "run_snapshots", "run_analytics"):
                self.store.db.execute("DROP TABLE " + table)
        self.store.close()
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.assertEqual(self.store.changes(1)["baseline_kind"], "untracked")
        self.ingest()
        self.assertEqual(self.store.changes()["baseline_kind"], "existing-inventory")
        self.assertEqual(self.kinds(), [])
        self.assertEqual(self.store.history(1)[0]["reason"], "Existing decision")
        self.assertEqual(len(self.store.findings()), 4)

    def test_empty_tracked_baseline_is_distinct_from_an_untracked_run(self):
        self.ingest([])
        self.ingest()
        self.assertEqual(self.store.changes()["baseline_kind"], "previous-run")
        self.assertEqual(self.kinds(), ["new-finding"] * 4)

    def test_report_contains_changes_reasons_and_import_trend(self):
        self.ingest()
        self.ingest(self.day2, DAY2)
        self.ingest(self.day3, DAY3)
        markdown, _ = write_reports(self.store, self.temp.name, DAY3)
        text = markdown.read_text()
        for phrase in ("What changed", "provider-reopened", "Owner workload", "Recent import trend", "Why this priority"):
            self.assertIn(phrase, text)
        self.assertLess(text.index("Production PostgreSQL security group"), text.index("Development admin endpoint"))
        self.assertEqual(self.store.trend()[-1]["p1"], 3)
        self.assertEqual(self.store.trend()[-1]["actionable"], 5)

    def test_historical_changes_do_not_use_current_title(self):
        self.ingest()
        original_title = self.store.changes(1)["changes"][0]["title"]
        edited = copy.deepcopy(self.day1[0])
        edited["Title"] = "Different title today"
        edited["UpdatedAt"] = "2026-10-10T08:00:00Z"
        self.ingest([edited], DAY2)
        self.assertEqual(self.store.changes(1)["changes"][0]["title"], original_title)


if __name__ == "__main__":
    unittest.main()
