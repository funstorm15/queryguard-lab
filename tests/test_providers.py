import io
import json
import unittest
import urllib.error
from unittest.mock import Mock

from queryguard.policy import Context
from queryguard.providers import NoRedirect, Ollama, ProviderError


class ProviderTests(unittest.TestCase):
    def provider_with_response(self, body):
        provider = Ollama("installed-test-model")
        provider.opener = Mock()
        provider.opener.open.return_value = io.BytesIO(body)
        return provider

    def test_ollama_request_and_response_contract(self):
        provider = self.provider_with_response(json.dumps({
            "done": True, "message": {"content": '{"action":"list_orders"}'}
        }).encode())
        output = provider.generate("orders", "protected", Context(), "untrusted instruction")
        self.assertEqual(json.loads(output), {"action": "list_orders"})
        request = provider.opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(payload["model"], "installed-test-model")
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["format"], "json")
        self.assertIn("untrusted instruction", payload["messages"][1]["content"])
        self.assertFalse(provider.simulated)

    def test_bad_incomplete_and_large_responses_are_errors(self):
        responses = [b"not json", b"[]", b"{}", b"x" * 65_537,
                     b'{"done":false,"message":{"content":"{}"}}',
                     b'{"done":true,"message":{}}',
                     b'{"done":true,"done_reason":"length","message":{"content":"{}"}}']
        for response in responses:
            with self.subTest(response=response[:70]), self.assertRaises(ProviderError):
                self.provider_with_response(response).generate("orders", "protected", Context())

    def test_connection_failure_is_reported(self):
        provider = Ollama("test")
        provider.opener = Mock()
        provider.opener.open.side_effect = urllib.error.URLError("offline")
        with self.assertRaises(ProviderError):
            provider.generate("orders", "protected", Context())

    def test_nonlocal_endpoints_and_ambiguous_urls_rejected(self):
        for url in ("https://example.com", "http://example.com", "file:///tmp/a", "http://localhost/path",
                    "http://user:pass@localhost", "http://localhost?x=y", "http://localhost#x", "http://localhost:bad"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Ollama("test", url)

    def test_invalid_model_and_timeout_rejected(self):
        for timeout in (0, -1, 301, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                Ollama("test", timeout=timeout)
        with self.assertRaises(ValueError):
            Ollama(" ")

    def test_redirects_rejected(self):
        with self.assertRaises(ProviderError):
            NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://example.com")
