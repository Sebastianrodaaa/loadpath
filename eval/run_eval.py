"""Exact call-site scoring against a literal-name regex baseline."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from eval.build_corpus import FAMILIES
from loadpath.inventory import scan

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [(rule, loader, re.compile(r"\b" + re.escape(loader) + r"\s*\(")) for rule, loader, _ in FAMILIES]


def baseline(source):
    result = []
    for rule, loader, pattern in PATTERNS:
        for match in pattern.finditer(source):
            pos = match.start()
            result.append({"rule": rule, "loader": loader, "line": source.count("\n", 0, pos) + 1, "col": pos - source.rfind("\n", 0, pos)})
    return result


def key(record):
    return record["rule"], record["loader"], record["line"], record["col"]


def metrics(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
    }


def evaluate(corpus=ROOT / "eval/corpus"):
    labels = json.loads((corpus / "labels.json").read_text())
    counts = {name: Counter() for name in ("loadpath", "regex")}
    details = []
    for case in labels["cases"]:
        path = corpus / case["file"]
        source = path.read_text()
        if hashlib.sha256(source.encode()).hexdigest() != case["sha256"]:
            raise ValueError(f"Corpus hash mismatch: {path}")
        findings, errors = scan(path)
        if errors:
            raise ValueError(errors)
        expected = set(map(key, case["expected"]))
        predictions = {"loadpath": [f.to_dict() for f in findings], "regex": baseline(source)}
        entry = {"file": case["file"], "kind": case["kind"], "expected": case["expected"], "systems": {}}
        for system, records in predictions.items():
            predicted = set(map(key, records))
            for label, values in (("tp", predicted & expected), ("fp", predicted - expected), ("fn", expected - predicted)):
                for rule, *_ in values:
                    counts[system][rule, label] += 1
            entry["systems"][system] = {
                "predicted": [{k: r[k] for k in ("rule", "loader", "line", "col")} for r in records],
                "fp": len(predicted - expected),
                "fn": len(expected - predicted),
            }
        details.append(entry)
    systems = {}
    for system, counter in counts.items():
        family = {rule: metrics(*(counter[rule, label] for label in ("tp", "fp", "fn"))) for rule, _, _ in FAMILIES}
        systems[system] = {"overall": metrics(*(sum(v[label] for v in family.values()) for label in ("tp", "fp", "fn"))), "families": family}
    return {
        "dataset": {
            "snippets": len(details),
            "positive_sites": sum(len(c["expected"]) for c in labels["cases"]),
            "negative_snippets": sum(not c["expected"] for c in labels["cases"]),
            "synthetic": True,
            "label_sha256": hashlib.sha256((corpus / "labels.json").read_bytes()).hexdigest(),
        },
        "method": "Exact rule+canonical loader+line+column match; no held-out claim; comments/strings retained for regex.",
        "systems": systems,
        "cases": details,
    }


def main():
    result = evaluate()
    (ROOT / "results/eval.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"dataset": result["dataset"], "systems": {k: v["overall"] for k, v in result["systems"].items()}}, indent=2))


if __name__ == "__main__":
    main()
