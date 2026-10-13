import copy
import json
import tempfile
import unittest
from pathlib import Path

from queryguard.cases import CASES, select_cases
from queryguard.engine import Result
from queryguard.providers import Simulator
from queryguard.reporting import render_html, save_report
from queryguard.scanner import evaluate, exit_code, scan


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(Simulator(), CASES)

    def test_expected_observed_outcomes(self):
        self.assertEqual(self.report["summary"], {
            "vulnerable": {"passed": 3, "vulnerability": 6},
            "protected": {"passed": 4, "blocked": 5},
        })
        self.assertEqual(len(self.report["findings"]), 18)
        self.assertTrue(self.report["simulated"])

    def test_beta_tenant_has_same_boundaries(self):
        self.assertEqual(scan(Simulator(), CASES, tenant="beta")["summary"], self.report["summary"])

    def test_failure_gates(self):
        self.assertEqual(exit_code(self.report, "protected"), 0)
        self.assertEqual(exit_code(self.report, "any"), 1)
        self.assertEqual(exit_code(self.report, "none"), 0)
        report = copy.deepcopy(self.report)
        report["findings"][0]["outcome"] = "error"
        self.assertEqual(exit_code(report, "none"), 2)

    def test_baseline_block_is_a_regression(self):
        result = Result("protected", "alpha", "orders", "", "test", True, execution="blocked")
        self.assertEqual(evaluate(CASES[0], result)["outcome"], "failed")

    def test_attack_without_evidence_is_not_a_security_proof(self):
        result = Result("protected", "alpha", "orders", "", "test", True, execution="executed")
        self.assertEqual(evaluate(select_cases(["tenant-override"])[0], result)["outcome"], "not_observed")

    def test_wrong_result_without_confirmed_leak_is_inconclusive(self):
        result = Result("protected", "alpha", "orders", "", "test", True,
                        execution="executed", rows=[{"constant": 1}])
        self.assertEqual(evaluate(select_cases(["customer-sqli"])[0], result)["outcome"], "inconclusive")

    def test_case_selection_and_unknown_names(self):
        self.assertEqual(len(select_cases(["customer-sqli"])), 1)
        with self.assertRaises(ValueError):
            select_cases(["typo"])

    def test_report_escapes_untrusted_content(self):
        report = copy.deepcopy(self.report)
        payload = '<script>alert("x")</script>'
        report["findings"][0]["prompt"] = payload
        report["findings"][0]["rows"] = [{"payload": payload}]
        rendered = render_html(report)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("SIMULATED", rendered)

    def test_saved_report_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            html_path = Path(directory) / "report.html"
            save_report(self.report, json_path, html_path)
            self.assertEqual(json.loads(json_path.read_text()), self.report)
            self.assertTrue(html_path.read_text().startswith("<!doctype html>"))
            with self.assertRaises(ValueError):
                save_report(self.report, json_path, json_path)
