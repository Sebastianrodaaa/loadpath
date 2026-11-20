"""Terminal and self-contained HTML reports."""

from html import escape
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .receipts import coverage_summary


def terminal(findings, errors=()):
    console = Console(highlight=False)
    table = Table(title="loadpath · loader coverage", expand=True)
    for heading in ("Rule", "Severity", "Call site", "Loader / artifact", "Coverage"):
        table.add_column(heading, overflow="fold")
    for f in findings:
        cells = [
            f.rule,
            f.severity,
            f"{f.file}:{f.line}:{f.col}",
            f"{f.loader}\n{f.expression}\n{f.resolved_artifact or 'unresolved'}" + (f"\n{f.args}" if f.args else ""),
            f.coverage,
        ]
        table.add_row(*(Text(cell) for cell in cells))
    console.print(table)
    summary = coverage_summary(findings)
    console.print(f"Coverage: {summary['covered']}/{summary['resolvable']} resolvable sites; {summary['unresolved']} unresolved")
    console.print(f"Data-only sites: {summary['not_required']} not-required (excluded from coverage)")
    console.print("Coverage is evidence of scanner scope, not safety.")
    for error in errors:
        console.print(error, style="red", markup=False)


def html_report(findings, errors=()):
    summary = coverage_summary(findings)
    svg, rows = [], []
    for i, f in enumerate(findings):
        y = 45 + i * 74
        color = {"covered": "#b7e4cd", "not-required": "#929298", "unresolved": "#929298"}.get(f.coverage, "#cfb58b")
        location = f"{Path(f.file).name}:{f.line}:{f.col}"
        artifact = Path(f.resolved_artifact).name if f.resolved_artifact else f.expression
        receipt = ", ".join(f"{r['scanner']} {r['version']}" for r in f.receipts) or "No matching receipt"
        if f.coverage == "not-required":
            receipt = "Data-only · no receipt required"
        labels = [(f.loader, f"{f.rule} · {location}"), (artifact, f.expression), (receipt, f.coverage)]
        svg.append(f'<path d="M 350 {y + 28} H 400 M 750 {y + 28} H 800" stroke="{color}" stroke-width="1.3" marker-end="url(#arrow)" stroke-dasharray="4 4"/>')
        for x, (title, subtitle) in zip((0, 400, 800), labels):
            full = f"{title} — {subtitle}"
            title = title if len(title) <= 39 else title[:36] + "…"
            subtitle = subtitle if len(subtitle) <= 46 else subtitle[:43] + "…"
            svg.append(
                f'<g><title>{escape(full)}</title><rect x="{x}" y="{y}" width="350" height="56" rx="6" '
                f'fill="#141416" stroke="#343439"/><circle cx="{x + 16}" cy="{y + 20}" r="3" fill="{color}"/>'
                f'<text x="{x + 28}" y="{y + 24}" fill="#eeeef0">{escape(title)}</text>'
                f'<text x="{x + 16}" y="{y + 43}" fill="{color}" font-size="10">{escape(subtitle)}</text></g>'
            )
        status_class = "covered" if f.coverage == "covered" else "neutral" if f.coverage in {"not-required", "unresolved"} else "gap"
        rows.append(
            f'<tr><td><span class="rule">{f.rule}</span><span class="location" title="{escape(f.file, quote=True)}">{escape(location)}</span></td>'
            f'<td><strong>{escape(f.loader)}</strong><code>{escape(f.expression)}</code><span class="detail">{escape(f.message)}</span>'
            f'<span class="detail">{escape(str(f.args) if f.args else "")}</span>'
            f'<span class="detail">{escape("; ".join(f.context))}</span></td><td><span class="severity">{escape(f.severity)}</span></td>'
            f'<td><span class="status {status_class}">{escape(f.coverage)}</span></td></tr>'
        )
    percent = summary["percent"] or 0
    percentage = f"{percent:g}%" if summary["percent"] is not None else "—"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>loadpath · coverage receipt</title><style>
:root{{
color-scheme:dark}}
*{{
box-sizing:border-box}}
body{{
margin:0;
background:#0b0b0d;
color:#eeeef0;
font:14px system-ui,sans-serif}}

main{{
max-width:1280px;
padding:38px 36px;
margin:auto}}
header{{
display:flex;
justify-content:space-between;
align-items:center;
border-bottom:1px solid #29292e;
padding-bottom:24px}}

.brand{{
font-size:30px;
letter-spacing:-1px;
font-weight:650}}
.brand span{{
color:#85858d;
font-size:12px;
font-family:monospace;
letter-spacing:0;
margin-left:14px}}

.tag{{
border:1px solid #36363b;
border-radius:20px;
padding:7px 12px;
color:#aaaab1;
font:11px monospace}}

h1{{
font-size:35px;
letter-spacing:-1.2px;
margin:27px 0 8px}}
p{{
color:#92929c;
line-height:1.6;
margin:6px 0}}
.eyebrow{{
font:10px monospace;
letter-spacing:1.5px;
color:#8a8a94}}

.metrics{{
display:grid;
grid-template-columns:repeat(4,1fr);
gap:12px;
margin:23px 0}}
.metric{{
border:1px solid #2d2d33;
border-radius:8px;
padding:16px 20px;
background:#111113}}

.metric b{{
font-size:31px;
font-weight:500;
display:block;
letter-spacing:-1px}}
.metric span{{
font:10px monospace;
text-transform:uppercase;
letter-spacing:1px;
color:#93939d}}

.panel{{
border:1px solid #2d2d33;
border-radius:8px;
padding:22px 24px;
background:#101012;
margin:20px 0}}
.section-head{{
display:flex;
justify-content:space-between;
align-items:center;
gap:16px}}

h2{{
font-size:16px;
margin:0;
font-weight:550}}
.muted{{
font:11px monospace;
color:#85858f}}
.bar{{
height:7px;
background:#2c2c32;
border-radius:5px;
overflow:hidden;
margin:15px 0 10px}}

.bar span{{
display:block;
height:100%;
background:#d9e3dd}}
.legend{{
font:11px monospace;
color:#9696a0;
display:flex;
justify-content:space-between}}

.graph{{
overflow-x:auto;
margin-top:25px}}
.graph svg{{
display:block;
width:100%;
min-width:850px;
font:12px monospace}}

.graph-label{{
fill:#888892;
font-size:10px;
letter-spacing:1.2px}}
.table-wrap{{
overflow-x:auto;
margin-top:14px}}

table{{
width:100%;
border-collapse:collapse;
table-layout:fixed;
font-size:12px}}
th{{
font:10px monospace;
color:#82828c;
letter-spacing:1px;
text-transform:uppercase;
text-align:left;
padding:14px 10px}}

td{{
padding:13px 10px;
border-top:1px solid #28282d;
vertical-align:top;
overflow-wrap:anywhere}}
th:first-child{{
width:18%}}
th:nth-child(2){{
width:53%}}
th:nth-child(3){{
width:9%}}
th:last-child{{
width:20%}}

.rule{{
font:11px monospace;
color:#d9d9e0}}
.location,.detail{{
display:block;
color:#85858e;
font-size:11px;
line-height:1.5;
margin-top:4px}}

strong{{
font:12px monospace;
color:#e3e3e8}}
code{{
display:block;
color:#b3b3bd;
font:11px monospace;
margin-top:5px;
overflow-wrap:anywhere}}

.severity{{
font:10px monospace;
text-transform:uppercase;
color:#aaaab2}}
.status{{
display:inline-block;
font:10px monospace;
border:1px solid;
border-radius:4px;
padding:5px 7px;
white-space:nowrap}}

.covered{{
color:#b7e4cd;
border-color:#335042;
background:#12231a}}
.gap{{
color:#cfb58b;
border-color:#4a3f30;
background:#211d17}}

.neutral{{
color:#a3a3af;
border-color:#3d3d45;
background:#1c1c22}}
.error{{
color:#dfb0a8}}
footer{{
display:flex;
justify-content:space-between;
border-top:1px solid #29292e;
margin-top:26px;
padding-top:15px;
font:10px monospace;
color:#73737e}}

@media(max-width:700px){{
main{{
padding:20px 16px}}
.brand span,.tag{{
display:none}}
.metrics{{
grid-template-columns:repeat(2,1fr)}}
h1{{
font-size:27px}}
.panel{{
padding:16px}}
table{{
min-width:760px}}
.legend,footer{{
gap:12px;
flex-wrap:wrap}}
}}

</style>
</head>
<body>
<main>
<header>
<div class="brand"><svg width="27" height="27" viewBox="0 0 64 64" aria-hidden="true" style="vertical-align:-3px;margin-right:5px">
<path d="M12 12 H32 V32 H52 M12 52 H32 V32" fill="none" stroke="#bbb" stroke-width="3"/>
<path d="M7 7 H17 V17 H7 Z M7 47 H17 V57 H7 Z M47 27 H57 V37 H47 Z" fill="#111" stroke="#eee" stroke-width="2"/>
<circle cx="32" cy="32" r="3" fill="#eee"/></svg> loadpath<span>SOURCE → ARTIFACT → SCANNER</span>
</div>
<span class="tag">OFFLINE / STATIC ANALYSIS</span>
</header>
<h1>A scan is not a loading path.</h1>
<p>Trace the code that loads your models to the evidence that covers it. Coverage is not a safety verdict.</p>
<div class="metrics">
<div class="metric">
<b>{len(findings):02d}</b>
<span>Loading call sites</span>
</div>
<div class="metric">
<b>{percentage}</b>
<span>Required coverage</span>
</div>
<div class="metric">
<b>{summary["unresolved"]:02d}</b>
<span>Unresolved paths</span>
</div>
<div class="metric">
<b>{summary["not_required"]:02d}</b>
<span>Data-only / not-required</span>
</div>
</div>
<section class="panel">
<div class="section-head">
<h2>{summary["covered"]} / {summary["resolvable"]} resolvable call sites covered</h2>
<span class="muted">HASH + FORMAT + COMPLETION</span>
</div>
<div class="bar" role="meter" aria-label="Coverage" aria-valuenow="{percent}" aria-valuemin="0" aria-valuemax="100">
<span style="width:{percent}%">
</span>
</div>
<div class="legend">
<span>Missing files stay in the denominator.</span>
<span>{summary["unresolved"]} unresolved · {summary["not_required"]} data-only excluded</span>
</div>
<div class="graph">
<svg role="img" aria-label="Call-site to artifact to receipt graph" viewBox="0 0 1150 {max(115, len(findings) * 74 + 56)}">
<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10" fill="#7d7d85"/>
</marker>
</defs>
<text x="0" y="16" class="graph-label">01 / CALL SITE</text>
<text x="400" y="16" class="graph-label">02 / ARTIFACT</text>
<text x="800" y="16" class="graph-label">03 / SCANNER EVIDENCE</text>{"".join(svg)}</svg>
</div>
</section>
<section class="panel">
<div class="section-head">
<h2>Findings &amp; loading context</h2>
<span class="muted">RISK ≠ COVERAGE</span>
</div>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Call site</th>
<th>Loader / risk context</th>
<th>Risk</th>
<th>Coverage</th>
</tr>
</thead>
<tbody>{"".join(rows)}</tbody>
</table>
</div>
</section>
{"".join(f'<p class="error">{escape(e)}</p>' for e in errors)}
<footer>
<span>loadpath / coverage receipt</span>
<span>Literal paths are lexical. Dynamic data flows remain unknown.</span>
</footer>
</main>
</body>
</html>'''
