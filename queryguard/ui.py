"""Loopback-only web UI. Serves packaged assets, never arbitrary workspace files."""

import json
import secrets
import threading
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from . import __version__
from .cases import CASES, select_cases
from .engine import run
from .providers import Ollama, Simulator
from .scanner import evaluate

ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
MAX_BODY = 48_000


def text_field(payload, name, default="", limit=8192):
    value = payload.get(name, default)
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"{name} must be text of at most {limit} characters")
    return value


def execute_request(payload: dict) -> dict:
    """Shared engine; UI settings never supply SQL or a database connection."""
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object")
    if set(payload) - {"provider", "model", "tenant", "mode", "prompt", "context", "case_id"}:
        raise ValueError("Unexpected request field")
    provider_name = text_field(payload, "provider", "simulator", 32)
    if provider_name == "simulator":
        provider = Simulator()
    elif provider_name == "ollama":
        provider = Ollama(text_field(payload, "model", limit=200))
    else:
        raise ValueError("Unknown provider")
    mode = text_field(payload, "mode", "both", 20)
    if mode not in {"both", "protected", "vulnerable"}:
        raise ValueError("Unknown mode")
    tenant = text_field(payload, "tenant", "alpha", 20)
    if tenant not in {"alpha", "beta"}:
        raise ValueError("Unknown tenant")
    case_id = text_field(payload, "case_id", limit=100)
    case = select_cases([case_id])[0] if case_id else None
    prompt = case.prompt if case else text_field(payload, "prompt")
    context = case.retrieved_context if case else text_field(payload, "context")
    if not prompt.strip():
        raise ValueError("A question is required")
    modes = ("vulnerable", "protected") if mode == "both" else (mode,)
    results = []
    for selected_mode in modes:
        result = run(provider, prompt, selected_mode, tenant, context)
        if case:
            results.append(evaluate(case, result))
        else:
            outcome = ("vulnerability" if result.evidence else result.execution
                       if result.execution in {"blocked", "error"} else "not_observed")
            results.append({**result.to_dict(), "outcome": outcome})
    return {"provider": provider.label, "simulated": provider.simulated, "results": results}


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=8765):
        self.token = secrets.token_urlsafe(32)
        self.job_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.allowed_hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
        self.allowed_origins = {f"http://{host}" for host in self.allowed_hosts}


class Handler(BaseHTTPRequestHandler):
    server_version = "QueryGuard"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Questions and model output must not become terminal access logs.
        pass

    def send_body(self, status, body, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         "style-src 'self'; connect-src 'self'; img-src 'self'; "
                         "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def json(self, status, value):
        self.send_body(status, json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def check_host(self):
        if self.headers.get("Host") not in self.server.allowed_hosts:
            self.json(403, {"error": "Unrecognized local host"})
            return False
        return True

    def do_GET(self):
        if not self.check_host():
            return
        path = urlsplit(self.path).path
        if path == "/api/config":
            self.json(200, {"version": __version__, "token": self.server.token,
                            "cases": [asdict(case) for case in CASES]})
        elif path in ASSETS:
            name, content_type = ASSETS[path]
            self.send_body(200, files("queryguard").joinpath("static", name).read_bytes(), content_type)
        else:
            self.json(404, {"error": "Not found"})

    def do_POST(self):
        if not self.check_host():
            return
        if urlsplit(self.path).path != "/api/run":
            self.json(404, {"error": "Not found"})
            return
        if (self.headers.get("Origin") not in self.server.allowed_origins
                or not secrets.compare_digest(self.headers.get("X-QueryGuard-Token", "").encode("utf-8"),
                                              self.server.token.encode("ascii"))):
            self.json(403, {"error": "Open QueryGuard from its local page before running a request"})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self.json(415, {"error": "Expected application/json"})
            return
        if self.headers.get("Transfer-Encoding"):
            self.json(400, {"error": "Chunked request bodies are not supported"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                self.json(413, {"error": "Request body must be between 1 and 48000 bytes"})
                return
            payload = json.loads(self.rfile.read(length))
        except (ValueError, OSError, RecursionError):
            self.json(400, {"error": "Invalid JSON request"})
            return
        if not self.server.job_lock.acquire(blocking=False):
            self.json(409, {"error": "Another experiment is running. Wait for it to finish."})
            return
        try:
            self.json(200, execute_request(payload))
        except ValueError as exc:
            self.json(400, {"error": str(exc)})
        except Exception:
            self.json(500, {"error": "Unexpected server error. Restart the local app and retry."})
        finally:
            self.server.job_lock.release()


def serve(port=8765, open_browser=True):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Port must be an integer from 1 through 65535")
    with Server(port) as server:
        print(f"QueryGuard Lab UI: {server.origin}\nPress Ctrl+C to stop.", flush=True)
        if open_browser:
            webbrowser.open(server.origin)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            print("\nQueryGuard UI stopped.")
