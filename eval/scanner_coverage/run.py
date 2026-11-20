"""Record real scanner observations, independent of loadpath's coverage policy."""

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from loadpath.receipts import sha256

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).parent


def measure(artifact, scanner, timeout=45):
    try:
        result = subprocess.run(
            [sys.executable, "-m", "eval.scanner_coverage.worker", scanner, str(artifact)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode:
            return {"status": "error", "exit_code": result.returncode, "diagnostics": result.stderr[-12000:]}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "error", "diagnostics": str(exc)}


def matrix_markdown(rows):
    lines = ["| Fixture | Wrapper path | picklescan | modelscan |", "|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['file']} | {row['path']} | {row['scanners']['picklescan']['status']} | {row['scanners']['modelscan']['status']} |")
    return "\n".join(lines) + "\n"


def main():
    manifest = json.loads((BASE / "manifest.json").read_text())
    rows = []
    for fixture in manifest["fixtures"]:
        artifact = BASE / "artifacts" / fixture["file"]
        if sha256(artifact) != fixture["sha256"]:
            raise ValueError(f"Fixture hash mismatch: {artifact}")
        row = {**fixture, "scanners": {}}
        for scanner in ("picklescan", "modelscan"):
            row["scanners"][scanner] = measure(artifact, scanner)
        if sha256(artifact) != fixture["sha256"]:
            raise ValueError(f"Fixture changed during scan: {artifact}")
        rows.append(row)
    result = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "versions": {name: version(name) for name in ("picklescan", "modelscan", "numpy", "h5py", "dill")},
        "method": "One subprocess per scanner/file; pickle/_pickle load, loads and Unpickler disabled. Flags are policy observations, not maliciousness.",
        "limitations": manifest["not_reproduced"],
        "sources": manifest["sources"],
        "fixtures": rows,
    }
    (ROOT / "results/scanner_coverage.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "results/scanner_coverage.md").write_text(matrix_markdown(rows))
    print(matrix_markdown(rows))


if __name__ == "__main__":
    main()
