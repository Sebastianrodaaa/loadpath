"""Build inert artifacts and capture real, per-file scanner evidence."""

import hashlib
import io
import json
import pickle
import struct
import subprocess
import sys
import zipfile
import zlib
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path

from picklescan.scanner import scan_file_path

from loadpath.receipts import import_modelscan, import_picklescan

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples/demo_app"


def main():
    clean = pickle.dumps({"scale": 1, "labels": ["red", "blue"]}, protocol=4)
    (DEMO / "clean.pkl").write_bytes(clean)
    (DEMO / "compressed.joblib").write_bytes(zlib.compress(clean))
    with zipfile.ZipFile(DEMO / "weights.pt", "w") as archive:
        archive.writestr("weights/data.pkl", clean)
        archive.writestr("weights/version", "3")
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("model.pkl", clean)
    with zipfile.ZipFile(DEMO / "nested.zip", "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
        archive.writestr("inner/model.pkl", clean)
    header = json.dumps({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    (DEMO / "weights.safetensors").write_bytes(struct.pack("<Q", len(header)) + header + b"\0" * 4)
    # GLOBAL names a function but does not invoke it; no REDUCE opcode is present.
    (DEMO / "global-reference.pkl").write_bytes(b"\x80\x02cos\nsystem\n.")
    receipts = []
    for name in ("clean.pkl", "compressed.joblib"):
        path = DEMO / name
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        result = asdict(scan_file_path(str(path)))
        result = json.loads(json.dumps(result, default=lambda value: value.value))
        assert before == hashlib.sha256(path.read_bytes()).hexdigest()
        capture = {"type": "picklescan", "version": version("picklescan"), "artifact": name, "sha256": before, "result": result}
        (DEMO / f"{name}.picklescan.json").write_text(json.dumps(capture, indent=2) + "\n")
        receipts.extend(import_picklescan(result, artifact=name, digest=before, version=version("picklescan")))
    (DEMO / "receipts.json").write_text(json.dumps({"receipts": receipts}, indent=2) + "\n")
    target = DEMO / "clean.pkl"
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    output = DEMO / "modelscan.raw.json"
    completed = subprocess.run([str(Path(sys.executable).parent / "modelscan"), "-p", str(target), "-r", "json", "-o", str(output)], check=False)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"modelscan exited {completed.returncode}")
    report = json.loads(output.read_text())
    assert digest == hashlib.sha256(target.read_bytes()).hexdigest()
    capture = {"type": "modelscan", "report": report, "hashes": {"clean.pkl": digest}}
    (DEMO / "clean.modelscan.json").write_text(json.dumps(capture, indent=2) + "\n")
    assert import_modelscan(report, capture["hashes"])
    print("Captured real picklescan and modelscan evidence; no fixture was deserialized.")


if __name__ == "__main__":
    main()
