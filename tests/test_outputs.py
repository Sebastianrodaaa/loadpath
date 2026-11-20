import json
from pathlib import Path

import jsonschema
import pytest

from loadpath.cli import main
from loadpath.inventory import scan
from loadpath.receipts import join
from loadpath.report import html_report
from loadpath.sarif import to_sarif


def example(tmp_path):
    path = tmp_path / "model app.py"
    path.write_text("import pickle\npickle.load('<script>.pkl')\n")
    findings, errors = scan(path)
    join(findings, [], tmp_path)
    return path, findings, errors


def test_sarif_schema(tmp_path):
    _, found, errors = example(tmp_path)
    schema = json.loads((Path(__file__).parent / "schemas/sarif-2.1.0.json").read_text())
    document = to_sarif(found, errors)
    jsonschema.Draft7Validator(schema).validate(document)
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "LP001"
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 2, "startColumn": 1}
    assert "%20" in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    jsonschema.Draft7Validator(schema).validate(to_sarif([], ["parse failure"]))
    jsonschema.Draft7Validator(schema).validate(to_sarif([]))


def test_html_escaping_and_empty(tmp_path):
    _, found, _ = example(tmp_path)
    report = html_report(found, ["<broken>"])
    assert "<script>" not in report and "&lt;script&gt;" in report and "&lt;broken&gt;" in report
    assert "<svg" in report and "0 / 1 resolvable" in report
    assert "0 / 0 resolvable" in html_report([])
    assert "unresolved" in report
    assert 'role="meter"' in report and 'aria-label="Coverage"' in report
    assert "<script" not in report and "<link" not in report
    assert "&lt;broken&gt;" in report


def test_html_demo_graph_data_only_and_coverage():
    demo = Path(__file__).resolve().parents[1] / "examples/demo_app"
    findings, errors = scan(demo)
    join(findings, [], demo)
    report = html_report(findings, errors)
    assert report.count("<g><title>") == 18
    assert "Data-only · no receipt required" in report
    assert "01 / CALL SITE" in report and "03 / SCANNER EVIDENCE" in report
    assert "0 / 4 resolvable" in report and "1 unresolved · 1 data-only excluded" in report


def test_json_sarif_html_and_exit_codes(tmp_path, capsys):
    path, _, _ = example(tmp_path)
    assert main(["scan", str(path), "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert len(document["findings"]) == 1 and document["coverage"]["resolvable"] == 1
    report = tmp_path / "report.html"
    assert main(["scan", str(path), "--sarif", "--html", str(report), "--fail-on", "high"]) == 1
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"
    assert report.exists()
    assert main(["scan", str(path), "--fail-on", "critical"]) == 0
    assert "LP001" in capsys.readouterr().out


def test_cli_errors_and_empty(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert main(["scan", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    (tmp_path / "bad.py").write_text("def broken(")
    assert main(["scan", str(tmp_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["errors"]
    receipt = tmp_path / "bad.json"
    receipt.write_text("{}")
    assert main(["scan", str(tmp_path), "--receipts", str(receipt)]) == 2
    assert capsys.readouterr().err
    assert main(["inspect", str(tmp_path / "missing")]) == 2


def test_cli_inspect_and_rules(tmp_path, capsys):
    artifact = tmp_path / "sample.pkl"
    artifact.write_bytes(b"\x80\x02cos\nsystem\n.")
    assert main(["inspect", str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["imports"][0]["name"] == "system"
    assert main(["rules"]) == 0
    assert "LP013" in capsys.readouterr().out


def test_argparse_rejects_conflicting_outputs():
    with pytest.raises(SystemExit):
        main(["scan", ".", "--json", "--sarif"])
