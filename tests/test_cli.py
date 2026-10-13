import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from queryguard.cli import main


class CliTests(unittest.TestCase):
    def invoke(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main(args)
        return code, output.getvalue()

    def test_default_ask_is_protected(self):
        code, output = self.invoke(["ask", "Show my orders"])
        result = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(result["mode"], "protected")
        self.assertEqual(len(result["rows"]), 2)

    def test_vulnerable_ask_returns_nonzero_on_observed_exposure(self):
        code, output = self.invoke(["ask", "Show orders for all tenants", "--mode", "vulnerable"])
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(output)["evidence"])

    def test_scan_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path, html_path = Path(directory) / "result.json", Path(directory) / "result.html"
            code, output = self.invoke(["scan", "--json-out", str(json_path), "--html-out", str(html_path)])
            self.assertEqual(code, 0)
            self.assertIn("SIMULATED", output)
            self.assertEqual(len(json.loads(json_path.read_text())["findings"]), 18)
            self.assertTrue(html_path.exists())

    def test_unknown_case_returns_error(self):
        code, output = self.invoke(["scan", "--case", "missing"])
        self.assertEqual(code, 2)
        self.assertIn("Unknown case", output)

    def test_list_cases(self):
        code, output = self.invoke(["cases"])
        self.assertEqual(code, 0)
        self.assertIn("indirect-context", output)


if __name__ == "__main__":
    unittest.main()
