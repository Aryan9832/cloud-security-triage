import copy
import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from triage.core import Store, actionable, effective_state, timestamp
from triage.reporting import write_reports
from triage.sources import aws_findings, read_file, read_owners


ROOT = Path(__file__).resolve().parents[1]
DAY1 = datetime(2026, 10, 9, 9, tzinfo=timezone.utc)
DAY2 = datetime(2026, 10, 10, 9, tzinfo=timezone.utc)


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "test.db")
        self.addCleanup(self.store.close)
        self.records = read_file(ROOT / "examples/day1.json")
        self.owners = read_owners(ROOT / "examples/owners.json")

    def ingest(self):
        return self.store.ingest(self.records, self.owners, now=DAY1)

    def row(self, finding_id):
        return next(r for r in self.store.findings() if r["finding_id"] == finding_id)

    def test_duplicate_and_stale_input_do_not_downgrade_finding(self):
        stats = self.ingest()
        self.assertEqual(stats, dict(received=5, inserted=4, updated=0, unchanged=0, stale=1))
        self.assertEqual(self.row("demo/s3-public-access")["severity"], "HIGH")
        self.assertEqual(len(self.store.findings()), 4)

    def test_repeated_import_is_idempotent_and_preserves_triage(self):
        self.ingest()
        self.store.decide(1, "remediate", "Remove public policy", "analyst", now=DAY1)
        stats = self.ingest()
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(stats["unchanged"], 4)
        self.assertEqual(self.row("demo/s3-public-access")["decision"], "remediate")
        self.assertEqual(len(self.store.history(1)), 1)

    def test_identity_includes_product_not_just_finding_id(self):
        self.ingest()
        other = copy.deepcopy(self.records[0])
        other["ProductArn"] = "arn:aws:securityhub:us-west-2::product/example/scanner"
        self.store.ingest([other], now=DAY1)
        self.assertEqual(len(self.store.findings()), 5)

    def test_owner_tag_then_account_fallback_then_unassigned(self):
        self.ingest()
        self.assertEqual(self.row("demo/s3-public-access")["owner"], "data-platform")
        self.assertEqual(self.row("demo/stale-key")["owner_source"], "account fallback")
        self.assertEqual(self.row("demo/volume-encryption")["owner"], "UNASSIGNED")

    def test_invalid_batch_rolls_back_all_records(self):
        broken = copy.deepcopy(self.records[1])
        del broken["Id"]
        with self.assertRaisesRegex(ValueError, "Id"):
            self.store.ingest([self.records[0], broken], now=DAY1)
        self.assertEqual(self.store.findings(), [])
        self.assertIsNone(self.store.latest_run())

    def test_mid_pagination_failure_does_not_commit_partial_inventory(self):
        def fails():
            yield self.records[0]
            raise RuntimeError("second page unavailable")
        with self.assertRaisesRegex(RuntimeError, "second page"):
            self.store.ingest(fails(), now=DAY1)
        self.assertEqual(self.store.findings(), [])
        self.assertIsNone(self.store.latest_run())

    def test_expiry_required_and_reopens_queue(self):
        self.ingest()
        for decision in ("accepted-risk", "false-positive"):
            with self.assertRaisesRegex(ValueError, "require"):
                self.store.decide(3, decision, "Review", "analyst", now=DAY1)
        self.store.decide(3, "accepted-risk", "Migration scheduled", "analyst",
                          "2026-10-10T09:00:00Z", DAY1)
        row = self.row("demo/stale-key")
        self.assertFalse(actionable(row, DAY1))
        self.assertEqual(effective_state(row, DAY2), "exception-expired")
        self.assertTrue(actionable(row, DAY2))

    def test_changed_finding_returns_exception_to_review(self):
        self.ingest()
        self.store.decide(3, "accepted-risk", "Migration scheduled", "analyst",
                          "2026-10-20T09:00:00Z", DAY1)
        self.store.ingest(read_file(ROOT / "examples/day2.json"), self.owners, now=DAY2)
        row = self.row("demo/stale-key")
        self.assertEqual(row["decision"], "accepted-risk")
        self.assertEqual(effective_state(row, DAY2), "review-needed")
        self.assertTrue(actionable(row, DAY2))
        self.assertEqual(len(self.store.history(3)), 1)

    def test_resolved_and_archived_not_actionable(self):
        self.ingest()
        self.store.ingest(read_file(ROOT / "examples/day2.json"), now=DAY2)
        self.assertEqual(effective_state(self.row("demo/s3-public-access"), DAY2), "provider-resolved")
        self.assertFalse(actionable(self.row("demo/volume-encryption"), DAY2))

    def test_omitted_finding_is_not_automatically_closed(self):
        self.ingest()
        self.store.ingest([], now=DAY2)
        self.assertTrue(actionable(self.row("demo/ssh-exposure"), DAY2))

    def test_timezone_offsets_compare_chronologically(self):
        self.assertEqual(timestamp("2026-10-09T10:00:00+02:00"), timestamp("2026-10-09T08:00:00Z"))
        with self.assertRaisesRegex(ValueError, "timezone"):
            timestamp("2026-10-09T08:00:00")

    def test_decision_audit_records_prior_state_and_reason(self):
        self.ingest()
        self.store.decide(1, "remediate", "Evidence verified", "aryan", now=DAY1)
        self.store.decide(1, "open", "Need owner confirmation", "aryan", now=DAY2)
        history = self.store.history(1)
        self.assertEqual([h["previous"] for h in history], ["open", "remediate"])
        self.assertEqual(history[1]["reason"], "Need owner confirmation")
        self.assertEqual(history[1]["actor"], "aryan")

    def test_invalid_decisions_leave_no_audit_entry(self):
        self.ingest()
        with self.assertRaisesRegex(ValueError, "future"):
            self.store.decide(3, "accepted-risk", "Migration", "analyst", "2026-10-01T00:00:00Z", DAY1)
        with self.assertRaisesRegex(ValueError, "blank"):
            self.store.decide(3, "remediate", " ", "analyst", now=DAY1)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.store.decide(999, "open", "Review", "analyst", now=DAY1)
        self.assertEqual(self.store.history(3), [])

    def test_csv_formula_and_markdown_escaping(self):
        hostile = copy.deepcopy(self.records[0])
        hostile["Title"] = '=HYPERLINK("https://example.invalid")|<script>\nnext'
        self.store.ingest([hostile], now=DAY1)
        markdown, csv_path = write_reports(self.store, self.temp.name, DAY1)
        with csv_path.open(newline="") as handle:
            row = next(csv.DictReader(handle))
        self.assertTrue(row["title"].startswith("'="))
        self.assertIn("\\|&lt;script&gt; next", markdown.read_text())
        self.assertNotIn("<script>", markdown.read_text())

    def test_aws_adapter_uses_every_page_without_hiding_closed_findings(self):
        client = Mock()
        client.get_paginator.return_value.paginate.return_value = [
            {"Findings": self.records[:2]}, {"Findings": self.records[2:]}]
        self.assertEqual(list(aws_findings("us-west-2", client=client)), self.records)
        client.get_paginator.assert_called_once_with("get_findings")
        client.get_paginator.return_value.paginate.assert_called_once_with(PaginationConfig={"PageSize": 100})

    def test_report_queue_counts_match_inventory(self):
        self.ingest()
        markdown, csv_path = write_reports(self.store, self.temp.name, DAY1)
        self.assertIn("Findings: **4** · Needs action: **3**", markdown.read_text())
        with csv_path.open(newline="") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 4)


if __name__ == "__main__":
    unittest.main()
