# Command-line reference

Run these commands from the project folder, or replace `python -m queryguard` with `queryguard` after installation.


```bash
python -m queryguard cases
python -m queryguard scan --mode protected
python -m queryguard scan --tenant beta
python -m queryguard scan --case tenant-override --case customer-sqli
python -m queryguard scan --json-out reports/custom.json --html-out reports/custom.html
python -m queryguard scan --fail-on any
python -m queryguard ask "Show my orders using the reference note." --context-file examples/indirect-note.txt
```

All commands accept `--help`. `--timeout` controls each Ollama request (default 60 seconds, maximum 300). A full real-model comparison makes 18 sequential requests.

### Report outcomes

| Outcome | Meaning |
| --- | --- |
| `vulnerability` | Returned fixture canaries identify unauthorized data, or database contents changed. |
| `blocked` | The protected plan was rejected before SQL execution. |
| `passed` | The case returned its exact expected fixture result. |
| `not_observed` | No covered boundary violation was observed; this is not proof of security. |
| `failed` | A legitimate baseline request was rejected or produced an incorrect result. |
| `error` | Provider or SQL execution failed, so the experiment did not complete. |
| `inconclusive` | An adversarial case produced an unexpected result without confirmed exposure. |

The observer is fixture-specific. It checks known other-tenant identifiers/customer values, restricted canary strings, and complete before/after fixture contents. It can miss encoded, transformed, aggregate and timing leaks. These checks are useful reproducible oracles, not a universal vulnerability classifier.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No configured failure gate was triggered. Expected vulnerable-demo findings may still exist. |
| `1` | A confirmed violation matched the configured gate. |
| `2` | At least one error, baseline regression, inconclusive case, or CLI/report-writing failure. |

The default scan gate is `--fail-on protected`. Use `--fail-on any` to fail on any observed violation, including the intentionally vulnerable examples. `--fail-on none` disables only the violation gate; errors still exit 2. A zero exit code alone does not certify security. Reports are saved before the scan returns its gate status.
