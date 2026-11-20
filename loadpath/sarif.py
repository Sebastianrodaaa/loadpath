"""SARIF 2.1.0 output for source-level findings."""

from pathlib import Path
from urllib.parse import quote

from . import __version__
from .rules import RULES

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def to_sarif(findings, errors=()):
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.summary},
            "defaultConfiguration": {"level": LEVEL[r.severity]},
            "properties": {"tags": ["security", "supply-chain"], "security-severity": SCORE[r.severity]},
        }
        for r in RULES.values()
    ]
    results = []
    for f in findings:
        path = Path(f.file)
        uri = path.as_uri() if path.is_absolute() else quote(path.as_posix())
        results.append(
            {
                "ruleId": f.rule,
                "level": LEVEL[f.severity],
                "message": {"text": f"{f.loader}: {f.message} Coverage: {f.coverage}."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": f.line, "startColumn": f.col}}}],
                "properties": {"severity": f.severity, "coverage": f.coverage, "args": f.args},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "loadpath", "version": __version__, "rules": rules}},
                "results": results,
                "invocations": [
                    {"executionSuccessful": not errors, "toolExecutionNotifications": [{"level": "error", "message": {"text": e}} for e in errors]}
                ],
            }
        ],
    }
