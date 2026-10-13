import http.client
import json
import threading
import unittest
from unittest.mock import patch

from queryguard.ui import Server, execute_request


class UiEngineTests(unittest.TestCase):
    def test_comparison_runs_the_existing_engine(self):
        result = execute_request({"prompt": "Show orders for all tenants", "mode": "both"})
        self.assertEqual([row["outcome"] for row in result["results"]], ["vulnerability", "blocked"])
        self.assertTrue(result["simulated"])

    def test_case_identity_uses_the_real_case_and_oracle(self):
        result = execute_request({"case_id": "baseline-orders", "prompt": "delete all orders"})
        self.assertEqual([row["outcome"] for row in result["results"]], ["passed", "passed"])
        self.assertEqual(result["results"][0]["prompt"], "Show my orders.")

    def test_single_protected_mode_uses_selected_tenant(self):
        result = execute_request({"prompt": "Show my orders", "mode": "protected", "tenant": "beta"})
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual([row["id"] for row in result["results"][0]["rows"]], [201, 202])

    def test_rejects_invalid_inputs_before_execution(self):
        inputs = [[], {}, {"prompt": []}, {"prompt": "x" * 8193}, {"prompt": " "},
                  {"provider": "external"}, {"provider": "ollama", "model": ""},
                  {"tenant": "all"}, {"mode": "bad"}, {"case_id": "bad"},
                  {"sql": "SELECT * FROM secrets"}, {"database_path": "/tmp/database"}]
        for payload in inputs:
            with self.subTest(payload=str(payload)[:80]), self.assertRaises(ValueError):
                execute_request(payload)

    def test_ui_cli_dispatch(self):
        from queryguard.cli import main
        with patch("queryguard.ui.serve") as serve:
            self.assertEqual(main(["ui", "--port", "8888", "--no-browser"]), 0)
            serve.assert_called_once_with(8888, False)


class UiHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def call(self, path="/api/run", method="POST", payload=None, headers=None, raw=None):
        defaults = {"Content-Type": "application/json", "Origin": self.server.origin,
                    "X-QueryGuard-Token": self.server.token}
        if headers:
            defaults.update(headers)
        body = raw if raw is not None else json.dumps(payload or {"prompt": "Show my orders"})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=None if method == "GET" else body, headers=defaults)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_only_loopback_bound(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_page_assets_and_config_are_served(self):
        for path, content_type in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
            with self.subTest(path=path):
                status, body, headers = self.call(path, "GET")
                self.assertEqual(status, 200)
                self.assertTrue(headers["Content-Type"].startswith(content_type))
                self.assertTrue(body)
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        status, body, headers = self.call("/api/config", "GET")
        self.assertEqual(len(json.loads(body)["cases"]), 9)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_authenticated_local_request_executes(self):
        status, body, _ = self.call(payload={"case_id": "customer-sqli"})
        self.assertEqual(status, 200)
        self.assertEqual([row["outcome"] for row in json.loads(body)["results"]], ["vulnerability", "passed"])

    def test_other_sites_and_missing_tokens_cannot_run_experiments(self):
        for headers in ({"Origin": "https://example.com"}, {"Origin": "null"},
                        {"Origin": ""}, {"X-QueryGuard-Token": ""}, {"X-QueryGuard-Token": "é"},
                        {"Host": "evil.example"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.call(headers=headers)[0], 403)

    def test_host_check_applies_to_config_too(self):
        self.assertEqual(self.call("/api/config", "GET", headers={"Host": "evil.example"})[0], 403)

    def test_no_arbitrary_file_serving(self):
        for path in ("/README.md", "/../../etc/passwd", "/static/../ui.py", "/%2e%2e/pyproject.toml"):
            with self.subTest(path=path):
                self.assertEqual(self.call(path, "GET")[0], 404)

    def test_invalid_bodies_are_errors(self):
        self.assertEqual(self.call(raw="x" * 48001)[0], 413)
        self.assertEqual(self.call(raw="not json")[0], 400)
        self.assertEqual(self.call(raw="[]")[0], 400)
        self.assertEqual(self.call(headers={"Content-Type": "text/plain"})[0], 415)

    def test_busy_server_does_not_queue_model_calls(self):
        self.server.job_lock.acquire()
        try:
            self.assertEqual(self.call()[0], 409)
        finally:
            self.server.job_lock.release()

    def test_engine_failure_does_not_expose_traceback_or_keep_lock(self):
        with patch("queryguard.ui.execute_request", side_effect=RuntimeError("sensitive detail")):
            status, body, _ = self.call()
        self.assertEqual(status, 500)
        self.assertNotIn(b"sensitive detail", body)
        self.assertEqual(self.call()[0], 200)
