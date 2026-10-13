"""Self-contained, escaped HTML reports; no scripts or external assets."""

import html
import json
from pathlib import Path


def render_html(report: dict) -> str:
    def esc(value):
        return html.escape(str(value), quote=True)

    def pretty(value):
        return esc(json.dumps(value, indent=2, ensure_ascii=False))

    cards = []
    for mode, summary in report["summary"].items():
        total = sum(summary.values())
        count = summary.get("vulnerability", 0)
        cards.append(f'<section class="card"><div class="eyebrow">{esc(mode)} FLOW</div>'
                     f'<div class="metric">{count}<span> / {total}</span></div>'
                     '<p>Observed boundary violations</p>'
                     f'<div class="bar"><span style="width:{100 * count / max(total, 1):.2f}%"></span></div>'
                     f'<p class="muted">{esc(" · ".join(f"{v} {k}" for k, v in summary.items()))}</p></section>')
    details = []
    for item in report["findings"]:
        evidence = "".join(f"<li>{esc(line)}</li>" for line in item["evidence"])
        if not evidence:
            evidence = "<li>No fixture boundary violation was observed. Check the outcome and limitations.</li>"
        context = (f'<h4>Retrieved reference (untrusted)</h4><pre>{esc(item["retrieved_context"])}</pre>'
                   if item["retrieved_context"] else "")
        details.append(f'''<details>
          <summary><span class="case">{esc(item['title'])}<small>{esc(item['case_id'])} · {esc(item['category'])}</small></span>
          <span class="mode">{esc(item['mode'])}</span><span class="badge {esc(item['outcome'])}">{esc(item['outcome'].replace('_', ' '))}</span></summary>
          <div class="detail"><h4>User input</h4><pre>{esc(item['prompt'])}</pre>{context}
          <div class="columns"><section><h4>Raw model / simulator output</h4><pre>{esc(item['model_output'])}</pre></section>
          <section><h4>Executed query</h4><pre>{esc(item['sql'] or 'No query executed')}</pre><p>Bound values</p><pre>{pretty(item['parameters'])}</pre></section></div>
          <h4>Returned rows</h4><pre>{pretty(item['rows'])}</pre>
          <p>Execution: {esc(item['execution'])} · Truncated: {esc(item['truncated'])}</p>
          <p class="muted">{esc(item['error'])}</p><h4>Observed evidence</h4><ul>{evidence}</ul>
          <h4>Recommended control</h4><p>{esc(item['remediation'])}</p></div></details>''')
    label = "SIMULATED · SCRIPTED COMPLETIONS" if report["simulated"] else "REAL MODEL · SINGLE EXPERIMENT"
    limits = "".join(f"<li>{esc(line)}</li>" for line in report["limitations"])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>QueryGuard Lab — Security report</title><style>
:root{{color-scheme:light;--ink:#182b39;--muted:#526571;--line:#d8e2e6;--paper:#f3f6f7;--teal:#0b736a;--red:#b53632}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,sans-serif}}
header{{background:#142e39;color:#fff;padding:48px max(24px,calc((100vw - 1100px)/2))}}
.eyebrow{{font-size:12px;font-weight:750;letter-spacing:.13em;text-transform:uppercase}}header .eyebrow{{color:#91d5c7}}
h1{{font-size:clamp(30px,5vw,52px);letter-spacing:-.04em;margin:8px 0}}header p{{color:#c4d6dc;margin:0;max-width:760px}}
main{{max-width:1148px;margin:auto;padding:28px 24px 60px}}.notice{{border-left:4px solid var(--teal);padding:14px 18px;background:#e5f2ef;margin-bottom:24px}}
.cards,.columns{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}}.card{{background:white;border:1px solid var(--line);border-radius:12px;padding:24px}}
.metric{{font-size:56px;line-height:1.2;font-weight:750;margin-top:10px}}.metric span{{font-size:23px;color:var(--muted);font-weight:450}}
.card p{{margin:7px 0}}.muted,small{{color:var(--muted)}}.bar{{height:6px;background:#e5ecef;border-radius:4px;margin:20px 0 12px;overflow:hidden}}.bar span{{display:block;background:var(--red);height:100%}}
h2{{font-size:24px;margin:32px 0 12px}}h4{{margin:16px 0 6px}}details{{background:white;border:1px solid var(--line);border-radius:8px;margin:10px 0;overflow:hidden}}
summary{{display:flex;align-items:center;gap:16px;padding:18px;cursor:pointer}}summary::before{{content:'+';font-size:22px;color:var(--teal)}}details[open] summary::before{{content:'−'}}
.case{{flex:1;font-weight:650}}small{{display:block;font-size:12px;font-weight:400}}.mode{{font-size:13px}}
.badge{{font-size:12px;min-width:100px;text-align:center;border-radius:20px;padding:4px 10px;background:#e9eef1}}
.vulnerability,.failed,.error{{background:#fce4e2;color:#922922}}.blocked,.passed{{background:#dff3eb;color:#135b46}}
.detail{{padding:0 24px 24px;border-top:1px solid var(--line)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f6;padding:14px;border-radius:6px;font:13px/1.65 ui-monospace,monospace}}
footer{{font-size:12px;color:var(--muted);margin-top:28px}}@media(max-width:650px){{.cards,.columns{{grid-template-columns:1fr}}summary{{gap:9px;flex-wrap:wrap}}.case{{flex-basis:75%}}.mode{{margin-left:24px}}header{{padding:32px 24px}}}}
</style></head><body><header><div class="eyebrow">QueryGuard / Security experiments</div><h1>What did the query return?</h1>
<p>The same test cases, run with and without application-level query controls.</p></header><main>
<div class="notice"><strong>{esc(label)}</strong><br>{esc(report['provider'])} · Tenant: {esc(report['tenant'])}<br>{esc(report['scope'])}</div>
<div class="cards">{''.join(cards)}</div><h2>Case-by-case evidence</h2><p class="muted">Expand a case to inspect inputs, generated output, SQL, returned data and remediation.</p>
{''.join(details)}<h2>Interpretation &amp; limitations</h2><ul>{limits}</ul>
<p><strong>Outcome key:</strong> vulnerability = observed boundary violation; blocked = plan rejected; passed = expected fixture result;
not observed = no violation detected; failed = baseline regression; error = incomplete execution; inconclusive = unexpected result without confirmed exposure.</p>
<footer>QueryGuard Lab {esc(report['tool_version'])} · {esc(report['created_at'])} · Report schema {esc(report['schema_version'])}</footer>
</main></body></html>'''


def save_report(report: dict, json_path: str | Path, html_path: str | Path) -> None:
    if Path(json_path).resolve() == Path(html_path).resolve():
        raise ValueError("JSON and HTML output paths must differ")
    for path, content in (
        (Path(json_path), json.dumps(report, indent=2, ensure_ascii=False) + "\n"),
        (Path(html_path), render_html(report)),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
