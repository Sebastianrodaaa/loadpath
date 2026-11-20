"""One scanner/file per process, with object deserialization disabled."""

import _pickle
import contextlib
import io
import json
import pickle
import sys
from dataclasses import asdict
from importlib.metadata import version

import h5py  # noqa: F401
import numpy  # noqa: F401
from modelscan.modelscan import ModelScan
from picklescan.scanner import scan_file_path


def forbidden(*args, **kwargs):
    raise RuntimeError("Object deserialization is disabled during scanner measurement")


def classify(flags, scanned, errors):
    if flags:
        return "flagged+error" if errors else "flagged"
    return "error" if errors else "scanned-no-flag" if scanned else "skipped"


def main():
    scanner, path = sys.argv[1:]
    pickle.load = forbidden
    pickle.loads = forbidden
    pickle.Unpickler = forbidden
    pickle._Unpickler = forbidden
    _pickle.load = forbidden
    _pickle.loads = forbidden
    _pickle.Unpickler = forbidden
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        if scanner == "picklescan":
            result = asdict(scan_file_path(path))
            raw = json.loads(json.dumps(result, default=lambda item: item.value))
            flags = raw["issues_count"]
            scanned = raw["scanned_files"]
            errors = ["scan_err"] if raw["scan_err"] else []
            references = [f"{g['module']}.{g['name']}" for g in raw["globals"]]
        else:
            scan = ModelScan()
            raw = scan.scan(path)
            flags = raw["summary"]["total_issues"]
            scanned = raw["summary"]["scanned"]["total_scanned"]
            errors = raw["errors"]
            references = [f"{issue['module']}.{issue['operator']}" for issue in raw["issues"] if "module" in issue and "operator" in issue]
    status = classify(flags, scanned, errors)
    print(
        json.dumps(
            {
                "scanner": scanner,
                "version": version(scanner),
                "status": status,
                "flags": flags,
                "scanned": scanned,
                "errors": errors,
                "references": references,
                "raw": raw,
                "diagnostics": output.getvalue()[:12000],
            }
        )
    )


if __name__ == "__main__":
    main()
