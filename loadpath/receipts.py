"""Scanner evidence adapters and conservative coverage joins."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .inspect import inspect_artifact
from .rules import RULES

# Version-pinned coverage declarations, not safety claims.
# https://github.com/mmaitre314/picklescan/blob/v1.0.4/src/picklescan/scanner.py
# https://github.com/protectai/modelscan/blob/0.8.8/modelscan/settings.py
# Only the exercised subset is admitted here. Nested archives, compressed joblib,
# remote code and custom framework loaders require evidence beyond a file scan.
SUPPORTED = {
    ("picklescan", "1.0.4"): {"pickle", "torch-zip", "numpy", "npz"},
    ("modelscan", "0.8.8"): {"pickle", "torch-zip", "numpy", "npz", "hdf5", "keras", "savedmodel"},
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def import_picklescan(result, *, artifact, digest, version):
    """Import the public ScanResult dataclass serialized with Enum values as strings.

    The CLI has no JSON flag or per-file hashes; capture each file separately.
    https://github.com/mmaitre314/picklescan/blob/v1.0.4/src/picklescan/cli.py
    """
    if not isinstance(result, dict) or not {"globals", "scanned_files", "scan_err"} <= result.keys():
        raise ValueError("Invalid picklescan ScanResult")
    if not isinstance(result["globals"], list) or type(result["scanned_files"]) is not int or type(result["scan_err"]) is not bool:
        raise ValueError("Invalid picklescan result fields")
    complete = result["scanned_files"] == 1 and not result["scan_err"]
    return [
        {
            "artifact": artifact,
            "sha256": digest,
            "scanner": "picklescan",
            "version": version,
            "formats": sorted(SUPPORTED.get(("picklescan", version), set())) if complete else [],
            "complete": complete,
            "evidence": result,
        }
    ]


def import_modelscan(report, hashes=None):
    """Import JSONReport; bind hashes captured at scan time, never current hashes.

    https://github.com/protectai/modelscan/blob/0.8.8/modelscan/modelscan.py
    Raw reports lack digests. Without a capture-time hash map they cannot cover a file.
    """
    try:
        summary = report["summary"]
        version = summary["modelscan_version"]
        root = Path(summary["absolute_path"])
        paths = summary["scanned"].get("scanned_files", [])
        errors = report["errors"]
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid modelscan JSON report") from exc
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths) or not isinstance(errors, list):
        raise ValueError("Invalid modelscan scanned_files/errors")
    receipts = []
    for path in paths:
        # Any scan error is conservative: it may affect completion of this artifact.
        full = str(root / path)
        receipts.append(
            {
                "artifact": full,
                "sha256": (hashes or {}).get(path),
                "scanner": "modelscan",
                "version": version,
                "formats": sorted(SUPPORTED.get(("modelscan", version), set())) if not errors else [],
                "complete": not errors,
                "evidence": {"issues": report.get("issues", []), "errors": errors},
            }
        )
    return receipts


def load_receipts(path):
    path = Path(path)
    document = json.loads(path.read_text())
    if isinstance(document, dict) and "summary" in document:
        entries = import_modelscan(document)
    elif isinstance(document, dict) and document.get("type") == "picklescan":
        entries = import_picklescan(document["result"], artifact=document["artifact"], digest=document.get("sha256"), version=document["version"])
    elif isinstance(document, dict) and document.get("type") == "modelscan":
        entries = import_modelscan(document["report"], document.get("hashes"))
    else:
        entries = document.get("receipts") if isinstance(document, dict) else document
    if not isinstance(entries, list):
        raise ValueError("Receipts must be a list or a supported scanner report")
    for entry in entries:
        if not isinstance(entry, dict) or not {"artifact", "sha256", "scanner", "version", "formats"} <= entry.keys():
            raise ValueError("Receipt requires artifact, sha256, scanner, version and formats")
        if not all(isinstance(entry[k], str) for k in ("artifact", "scanner", "version")):
            raise ValueError("Receipt paths, scanner and version must be strings")
        if not isinstance(entry["formats"], list) or not all(isinstance(f, str) for f in entry["formats"]):
            raise ValueError("Receipt formats must be strings")
        if "complete" in entry and type(entry["complete"]) is not bool:
            raise ValueError("Receipt complete must be boolean")
        digest = entry["sha256"]
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest)):
            raise ValueError("Receipt sha256 must be a lowercase hexadecimal digest")
        entry["artifact"] = str((path.parent / entry["artifact"]).resolve())
    return entries


def required_format(finding, path):
    info = inspect_artifact(path)
    kind = info["format"]
    if info["errors"]:
        return "incomplete-inspection"
    if finding.rule == "LP010" and finding.args.get("trust_remote_code") is True:
        return "remote-code"
    if finding.rule == "LP005":
        return "torchscript"
    if finding.rule == "LP012":
        return "skops"
    if finding.rule == "LP011":
        return "download"
    if kind == "joblib-compressed":
        return kind
    if kind in {"zip", "tar"}:
        return "nested-archive"
    if any(m.get("format") in {"zip", "tar", "torch-zip", "npz"} for m in info["members"]):
        return "nested-archive"
    if any(m.get("errors") for m in info["members"]):
        return "incomplete-inspection"
    expected = {
        "pickle": {"pickle"},
        "joblib": {"pickle"},
        "torch": {"torch-zip"},
        "keras": {"hdf5", "keras"},
        "savedmodel": {"savedmodel"},
        "numpy": {"numpy", "npz"},
        "safetensors": {"safetensors"},
    }
    if kind not in expected.get(RULES[finding.rule].format, {kind}):
        return "loader-format-mismatch"
    return kind


def join(findings, receipts, base):
    """Relative source artifact strings are interpreted against an explicit base."""
    base = Path(base).resolve()
    for finding in findings:
        finding.receipts = []
        if finding.rule == "LP013":
            finding.coverage = "not-required"
            if finding.resolved_artifact is not None:
                finding.resolved_artifact = str((base / finding.resolved_artifact).resolve())
            continue
        if finding.resolved_artifact is None:
            finding.coverage = "unresolved"
            continue
        path = (base / finding.resolved_artifact).resolve()
        finding.resolved_artifact = str(path)
        matches = [r for r in receipts if Path(r["artifact"]).resolve() == path]
        if not path.is_file():
            finding.coverage = "uncovered"
            finding.message += " Artifact is missing or not a regular file."
            continue
        try:
            digest = sha256(path)
            fmt = required_format(finding, path)
        except (OSError, ValueError) as exc:
            finding.coverage = "uncovered"
            finding.message += f" Inspection unavailable: {exc}"
            continue
        for receipt in matches:
            declared = set(receipt["formats"])
            key = (receipt["scanner"], receipt["version"])
            # Unknown scanners use their explicit native declaration; known scanners
            # cannot claim more than the versioned supported-format table.
            allowed = declared & SUPPORTED[key] if key in SUPPORTED else declared if receipt["scanner"] not in {"picklescan", "modelscan"} else set()
            if not receipt.get("sha256"):
                status = "uncovered"
            elif receipt["sha256"] != digest:
                status = "stale-hash"
            elif fmt not in allowed:
                status = "unsupported-format"
            elif not receipt.get("complete", True):
                status = "uncovered"
            else:
                status = "covered"
            finding.receipts.append({**receipt, "status": status, "required_format": fmt})
        statuses = {r["status"] for r in finding.receipts}
        finding.coverage = next((s for s in ("covered", "stale-hash", "unsupported-format", "uncovered") if s in statuses), "uncovered")
    return findings


def coverage_summary(findings):
    required = [f for f in findings if f.coverage != "not-required"]
    resolved = [f for f in required if f.resolved_artifact is not None]
    covered = sum(f.coverage == "covered" for f in resolved)
    return {
        "resolvable": len(resolved),
        "covered": covered,
        "unresolved": len(required) - len(resolved),
        "not_required": len(findings) - len(required),
        "percent": round(100 * covered / len(resolved), 1) if resolved else None,
    }
