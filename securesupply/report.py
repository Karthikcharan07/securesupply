import html
import json
from collections import Counter
from pathlib import Path


def write_reports(report: dict, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    def esc(x):
        return html.escape(str(x), quote=True)

    checks = "".join(
        f"<tr><td>{esc(c['tool'])}</td><td>{esc(c['status'])}</td><td>{esc(c['detail'])}</td></tr>"
        for c in report["checks"]
    )
    findings = [f for c in report["checks"] for f in c["findings"]]
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{esc(f[k])}</td>"
            for k in ("tool", "rule", "severity", "message", "file", "line", "package", "fixes")
        )
        + "</tr>"
        for f in findings
    )
    counts = dict(Counter(f["severity"] for f in findings))
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SecureSupply report</title><style>body{{font:16px system-ui;background:#101827;color:#e7edf6;padding:36px}}
table{{border-collapse:collapse;width:100%;margin:24px 0}}td,th{{padding:12px;border:1px solid #42516a;text-align:left}}
h1{{color:#74e0cb}}.wrap{{overflow:auto}}</style><h1>SecureSupply</h1>
<p>UTC: {esc(report["created_at"])} · Exit: {report["exit_code"]}</p>
<p>{esc(report["gate_message"])}</p><p>Scope: {esc(report["scope"])}</p>
<p>Severities: {esc(counts)}</p><table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>{checks}</table>
<div class="wrap"><table><tr><th>Tool</th><th>Rule</th><th>Severity</th><th>Finding</th><th>File</th>
<th>Line</th><th>Package</th><th>Fix versions</th></tr>{rows}</table></div>
<p>Missing or skipped checks do not establish security. Review findings before remediation.</p></html>"""
    (output / "report.html").write_text(page, encoding="utf-8")
