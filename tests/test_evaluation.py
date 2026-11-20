import bz2
import gzip
import hashlib
import io
import json
import lzma
import pickletools
import struct
import subprocess
import tarfile
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.build_corpus import build
from eval.run_eval import baseline, evaluate, metrics
from eval.scanner_coverage import run as scanner_run
from eval.scanner_coverage.worker import classify, forbidden
from loadpath.inspect import pickle_imports
from scripts import registry_scan

ROOT = Path(__file__).resolve().parents[1]


def test_corpus_reproduces_labels_and_recorded_scores(tmp_path):
    cases = build(tmp_path)
    assert len(cases) >= 150
    assert json.loads((tmp_path / "labels.json").read_text()) == json.loads((ROOT / "eval/corpus/labels.json").read_text())
    assert {"negative-lookalike", "dynamic", "callback", "risk-argument"} <= {case["kind"] for case in cases}
    actual = evaluate(tmp_path)
    assert actual == json.loads((ROOT / "results/eval.json").read_text())
    assert actual["systems"]["loadpath"]["overall"]["fn"] > 0
    assert actual["systems"]["loadpath"]["overall"]["fp"] > 0


def test_empty_scoring_and_tampered_source(tmp_path):
    assert metrics(0, 0, 0) == {"tp": 0, "fp": 0, "fn": 0, "precision": 0, "recall": 0, "f1": 0}
    assert not baseline("import json\njson.load(stream)")
    assert baseline("# pickle.load(path)")[0]["loader"] == "pickle.load"
    (tmp_path / "labels.json").write_text('{"cases":[]}')
    assert evaluate(tmp_path)["dataset"]["snippets"] == 0
    cases = build(tmp_path)
    (tmp_path / cases[0]["file"]).write_text("pass")
    with pytest.raises(ValueError, match="hash mismatch"):
        evaluate(tmp_path)


def marker_references(data):
    if data.startswith(b"PK"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return [ref for name in archive.namelist() for ref in marker_references(archive.read(name))]
    if data[257:262] == b"ustar":
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            return [ref for member in archive if member.isfile() for ref in marker_references(archive.extractfile(member).read())]
    if data.startswith(b"\x93NUMPY"):
        offset = 10 if data[6] == 1 else 12
        size = struct.unpack("<H" if data[6] == 1 else "<I", data[8:offset])[0]
        return marker_references(data[offset + size :])
    for prefix, decompress in [
        (b"\x1f\x8b", gzip.decompress),
        (b"BZh", bz2.decompress),
        (b"\xfd7zXZ", lzma.decompress),
        (b"\x5d\0", lzma.decompress),
        (b"\x78", zlib.decompress),
    ]:
        if data.startswith(prefix):
            return marker_references(decompress(data))
    return [(ref["module"], ref["name"]) for ref in pickle_imports(data)[1]]


def test_scanner_manifest_markers_hashes_and_recorded_matrix():
    base = ROOT / "eval/scanner_coverage"
    manifest = json.loads((base / "manifest.json").read_text())
    result = json.loads((ROOT / "results/scanner_coverage.json").read_text())
    assert len(manifest["fixtures"]) >= 25
    assert len(result["fixtures"]) == len(manifest["fixtures"])
    for fixture, recorded in zip(manifest["fixtures"], result["fixtures"]):
        data = (base / "artifacts" / fixture["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == fixture["sha256"] == recorded["sha256"]
        assert fixture["file"] == recorded["file"]
        if fixture["marker_present"] and not fixture["file"].endswith(".h5"):
            assert {("os", "getcwd"), ("posix", "getcwd")} & set(marker_references(data))
        for name, scan in recorded["scanners"].items():
            assert scan["scanner"] == name
            assert scan["version"] == result["versions"][name]
            assert scan["status"] in {"flagged", "flagged+error", "error", "skipped", "scanned-no-flag", "timeout"}
            assert (scan["status"] in {"flagged", "flagged+error"}) == bool(scan["flags"])
            assert scan["status"] != "flagged" or not scan["errors"]
    assert scanner_run.matrix_markdown(result["fixtures"]) == (ROOT / "results/scanner_coverage.md").read_text()


def test_hdf5_control_marker_is_opaque_bytes():
    h5py = pytest.importorskip("h5py")
    with h5py.File(ROOT / "eval/scanner_coverage/artifacts/keras-metadata.h5", "r") as archive:
        assert ("os", "getcwd") in marker_references(bytes(archive["marker_reference"][()]))


def test_legacy_torch_tar_empty_storage_and_tensor_structure():
    with tarfile.open(ROOT / "eval/scanner_coverage/artifacts/torch-legacy-tar.pt") as archive:
        assert {member.name for member in archive} == {"storages", "tensors", "pickle"}
        storages = archive.extractfile("storages").read()
        operations = list(pickletools.genops(storages))
        assert operations[1][0].name == "BININT1" and operations[1][1] == 0
        views = list(pickletools.genops(storages[operations[-1][2] + 1 :]))
        assert views[1][0].name == "EMPTY_LIST"
        tensors = list(pickletools.genops(archive.extractfile("tensors").read()))
        assert tensors[1][0].name == "BININT1" and tensors[1][1] == 0


@pytest.mark.parametrize(
    "output,expected",
    [
        (SimpleNamespace(returncode=9, stderr="failed"), "error"),
        (SimpleNamespace(returncode=0, stdout="not-json"), "error"),
        (SimpleNamespace(returncode=0, stdout='{"status":"skipped"}'), "skipped"),
    ],
)
def test_scanner_process_result(monkeypatch, output, expected):
    monkeypatch.setattr(scanner_run.subprocess, "run", lambda *a, **kw: output)
    assert scanner_run.measure(Path("fixture"), "modelscan")["status"] == expected


def test_scanner_process_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("scanner", 1)

    monkeypatch.setattr(scanner_run.subprocess, "run", timeout)
    assert scanner_run.measure(Path("fixture"), "modelscan", timeout=1)["status"] == "timeout"


def test_worker_status_and_deserialization_guard():
    assert classify(1, 1, []) == "flagged"
    assert classify(1, 1, ["error"]) == "flagged+error"
    assert classify(0, 1, []) == "scanned-no-flag"
    assert classify(0, 0, []) == "skipped"
    assert classify(0, 0, ["error"]) == "error"
    with pytest.raises(RuntimeError, match="deserialization is disabled"):
        forbidden(b"")


def test_registry_aggregates_and_empty():
    result = json.loads((ROOT / "results/registry.json").read_text())
    assert registry_scan.summarize(result["repositories"]) == result["summary"]
    assert registry_scan.markdown(result) == (ROOT / "results/registry.md").read_text()
    assert all(len(record["commit"]) == 40 for record in result["repositories"])
    assert len(result["repositories"]) >= 30
    assert not (ROOT / ".registry-clones").exists()
    summary = registry_scan.summarize([])
    assert summary["call_sites"] == summary["repositories"] == 0
    assert summary["resolvable"]["share"] is None
    assert summary["risk_args"]["torch_weights_only_missing"]["share"] is None


@pytest.mark.parametrize("returncode", [0, 3])
def test_registry_always_removes_clone(monkeypatch, tmp_path, returncode):
    def fake_run(command, **kwargs):
        if "clone" in command:
            assert "--depth" in command and "1" in command
            Path(command[-1]).mkdir()
        return SimpleNamespace(stdout="a" * 40)

    monkeypatch.setattr(registry_scan, "run", fake_run)
    monkeypatch.setattr(
        registry_scan.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=returncode, stderr="scan failure", stdout='{"findings":[],"errors":[]}')
    )
    record = registry_scan.inventory_repo("owner/repo", tmp_path)
    assert record["status"] == ("ok" if returncode == 0 else "error")
    assert not (tmp_path / "owner__repo").exists()
    assert bool(record["errors"]) == bool(returncode)
