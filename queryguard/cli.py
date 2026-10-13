"""CLI entry point. Run directly with python -m queryguard."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .cases import CASES, select_cases
from .engine import run
from .providers import Ollama, Simulator
from .reporting import save_report
from .scanner import exit_code, scan


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="QueryGuard Lab — LLM-to-SQL security experiments on synthetic data")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("cases", help="List built-in cases")
    ui = sub.add_parser("ui", help="Open the local browser interface")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--no-browser", action="store_true", help="Start without opening a browser")
    for command in ("scan", "ask"):
        child = sub.add_parser(command, help="Run the case suite" if command == "scan" else "Try a single question")
        child.add_argument("--provider", choices=("simulator", "ollama"), default="simulator")
        child.add_argument("--model", help="Exact installed Ollama model name (required with --provider ollama)")
        child.add_argument("--ollama-url", default="http://127.0.0.1:11434")
        child.add_argument("--timeout", type=float, default=60, help="Ollama request timeout in seconds (maximum 300)")
        child.add_argument("--tenant", choices=("alpha", "beta"), default="alpha",
                           help="Trusted application identity for this local experiment")
        if command == "scan":
            child.add_argument("--mode", choices=("both", "vulnerable", "protected"), default="both")
            child.add_argument("--case", action="append", dest="cases", help="Case ID; repeat to select several")
            child.add_argument("--json-out", default="reports/report.json")
            child.add_argument("--html-out", default="reports/report.html")
            child.add_argument("--fail-on", choices=("any", "protected", "none"), default="protected",
                               help="Violation exit gate; errors and baseline failures always exit 2")
        else:
            child.add_argument("question")
            child.add_argument("--mode", choices=("protected", "vulnerable"), default="protected")
            child.add_argument("--context-file", type=Path, help="UTF-8 file of untrusted retrieved reference text")
    return root


def main(argv=None) -> int:
    root = parser()
    args = root.parse_args(argv)
    if args.command == "cases":
        for case in CASES:
            print(f"{case.id:20} {case.category:26} {case.title}")
        return 0
    try:
        if args.command == "ui":
            from .ui import serve
            serve(args.port, not args.no_browser)
            return 0
        if args.provider == "ollama":
            if not args.model:
                root.error("--model is required with --provider ollama")
            provider = Ollama(args.model, args.ollama_url, args.timeout)
        else:
            if args.model:
                root.error("--model requires --provider ollama")
            provider = Simulator()
        if args.command == "ask":
            context = args.context_file.read_text(encoding="utf-8") if args.context_file else ""
            result = run(provider, args.question, args.mode, args.tenant, context)
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            return 2 if result.execution == "error" else 1 if result.evidence else 0
        cases = select_cases(args.cases)
        modes = ("vulnerable", "protected") if args.mode == "both" else (args.mode,)
        print(f"QueryGuard Lab {__version__} | {provider.label}", flush=True)
        print("SIMULATED completions; no real LLM tested." if provider.simulated
              else "Real model experiment; each case uses a fresh synthetic database.", flush=True)
        report = scan(provider, cases, modes, args.tenant)
        save_report(report, args.json_out, args.html_out)
        for item in report["findings"]:
            print(f"{item['mode']:11} {item['case_id']:20} {item['outcome']}")
        print("\nSummary: " + json.dumps(report["summary"], sort_keys=True))
        print(f"JSON: {Path(args.json_out).resolve()}\nHTML: {Path(args.html_out).resolve()}")
        return exit_code(report, args.fail_on)
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"queryguard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
