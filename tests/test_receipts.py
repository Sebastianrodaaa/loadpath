import json
import pickle
import zipfile
import zlib
from pathlib import Path

import pytest

from loadpath.inventory import scan
from loadpath.receipts import coverage_summary, import_modelscan, import_picklescan, join, load_receipts, sha256

DEMO = Path(__file__).resolve().parents[1] / "examples/demo_app"


@pytest.mark.parametrize("rebind", [
    "import unknown as P", "from unknown import path as P", "(P := dynamic)",
    "for P in paths:\n    pass", "with manager() as P:\n    pass",
    "P += suffix", "del P", "def f(P):\n    pickle.load(P)",
    "def f():\n    global P\n    pickle.load(P)",
    "def outer():\n    P = 'x.pkl'\n    def inner():\n        nonlocal P\n        pickle.load(P)",
    "def f():\n    pickle.load(P)\n    import unknown as P",
])
def test_rebinding_cannot_inherit_receipt(tmp_path, rebind):
    artifact = tmp_path / "x.pkl"
    artifact.write_bytes(b"\x80\x02N.")
    expression = "P = 'x.pkl'\n" + rebind
    if not rebind.startswith("def "):
        expression += "\npickle.load(P)"
    found = site(tmp_path, expression)
    join(found, [receipt(artifact)], tmp_path)
    assert len(found) == 1
    assert found[0].resolved_artifact is None
    assert found[0].coverage == "unresolved"


def site(tmp_path, expression="pickle.load('x.pkl')"):
    (tmp_path / "app.py").write_text("import pickle\nimport joblib\nimport torch\nimport numpy\n" + expression)
    found, errors = scan(tmp_path / "app.py")
    assert not errors
    return found


def receipt(path, **kwargs):
    return {"artifact": str(path.resolve()), "sha256": sha256(path), "scanner": "picklescan", "version": "1.0.4", "formats": ["pickle"], **kwargs}


def test_join_statuses(tmp_path):
    path = tmp_path / "x.pkl"
    path.write_bytes(pickle.dumps({}))
    found = site(tmp_path)
    join(found, [], tmp_path)
    assert found[0].coverage == "uncovered"
    good = receipt(path)
    join(found, [good], tmp_path)
    assert found[0].coverage == "covered"
    stale = receipt(path, sha256="0" * 64)
    join(found, [stale], tmp_path)
    assert found[0].coverage == "stale-hash"
    unsupported = receipt(path, formats=["hdf5"])
    join(found, [unsupported], tmp_path)
    assert found[0].coverage == "unsupported-format"
    join(found, [stale, good], tmp_path)
    assert found[0].coverage == "covered" and len(found[0].receipts) == 2
    join(found, [receipt(path, complete=False)], tmp_path)
    assert found[0].coverage == "uncovered"
    path.write_bytes(pickle.dumps({"changed": 1}))
    join(found, [good], tmp_path)
    assert found[0].coverage == "stale-hash"


def test_missing_unresolved_and_denominator(tmp_path):
    found = site(tmp_path, "pickle.load('missing.pkl')\npickle.load(dynamic)")
    join(found, [], tmp_path)
    assert [f.coverage for f in found] == ["uncovered", "unresolved"]
    assert coverage_summary(found) == {"resolvable": 1, "covered": 0, "unresolved": 1, "not_required": 0, "percent": 0.0}
    assert coverage_summary([])["percent"] is None


def test_known_versions_and_declared_formats(tmp_path):
    path = tmp_path / "x.pkl"
    path.write_bytes(pickle.dumps({}))
    found = site(tmp_path)
    join(found, [receipt(path, version="unknown")], tmp_path)
    assert found[0].coverage == "unsupported-format"
    join(found, [receipt(path, scanner="local-review", version="1")], tmp_path)
    assert found[0].coverage == "covered"


def test_compressed_joblib_and_nested(tmp_path):
    path = tmp_path / "x.joblib"
    path.write_bytes(zlib.compress(pickle.dumps({})))
    found = site(tmp_path, "joblib.load('x.joblib')")
    join(found, [receipt(path, formats=["pickle", "joblib-compressed"])], tmp_path)
    assert found[0].coverage == "unsupported-format"
    path = tmp_path / "x.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("x.pkl", pickle.dumps({}))
    found = site(tmp_path, "pickle.load('x.zip')")
    join(found, [receipt(path, formats=["pickle", "nested-archive"])], tmp_path)
    assert found[0].coverage == "unsupported-format"


def test_loader_mismatch_and_inspection_error(tmp_path):
    path = tmp_path / "x.pkl"
    path.write_bytes(pickle.dumps({}))
    found = site(tmp_path, "torch.load('x.pkl')")
    join(found, [receipt(path)], tmp_path)
    assert found[0].receipts[0]["required_format"] == "loader-format-mismatch"
    path.write_bytes(b"\x80\x04")
    found = site(tmp_path)
    join(found, [receipt(path)], tmp_path)
    assert found[0].coverage == "unsupported-format"


def test_relative_receipts_and_validation(tmp_path):
    path = tmp_path / "x.pkl"
    path.write_bytes(pickle.dumps({}))
    doc = tmp_path / "receipts.json"
    doc.write_text(json.dumps([receipt(path, artifact="x.pkl")]))
    assert load_receipts(doc)[0]["artifact"] == str(path)
    for bad in (
        {},
        {"receipts": [{}]},
        [receipt(path, sha256="bad")],
        [receipt(path, formats="pickle")],
        [receipt(path, artifact=1)],
        [receipt(path, complete="false")],
    ):
        doc.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            load_receipts(doc)
    doc.write_text("{")
    with pytest.raises(ValueError):
        load_receipts(doc)
    doc.write_text("[]")
    assert load_receipts(doc) == []


def test_real_picklescan_capture():
    capture = json.loads((DEMO / "clean.pkl.picklescan.json").read_text())
    assert capture["result"]["scanned_files"] == 1 and not capture["result"]["scan_err"]
    loaded = load_receipts(DEMO / "clean.pkl.picklescan.json")
    assert loaded[0]["sha256"] == sha256(DEMO / "clean.pkl")
    assert loaded[0]["formats"]
    result = {**capture["result"], "scan_err": True}
    assert not import_picklescan(result, artifact="x", digest="0" * 64, version="1.0.4")[0]["complete"]
    with pytest.raises(ValueError):
        import_picklescan({}, artifact="x", digest="", version="1")


def test_real_modelscan_capture():
    capture = json.loads((DEMO / "clean.modelscan.json").read_text())
    receipts = import_modelscan(capture["report"], capture["hashes"])
    assert receipts[0]["sha256"] == sha256(DEMO / "clean.pkl")
    assert receipts[0]["complete"]
    raw = load_receipts(DEMO / "modelscan.raw.json")
    assert raw[0]["sha256"] is None
    wrapped = load_receipts(DEMO / "clean.modelscan.json")
    assert wrapped[0]["sha256"] == raw[0]["evidence"].get("sha256", receipts[0]["sha256"])
    capture["report"]["errors"] = [{"source": "clean.pkl", "message": "failed"}]
    assert not import_modelscan(capture["report"], capture["hashes"])[0]["complete"]
    with pytest.raises(ValueError):
        import_modelscan({})


def test_raw_modelscan_never_invents_current_hash(tmp_path):
    capture = json.loads((DEMO / "clean.modelscan.json").read_text())
    capture["report"]["summary"]["absolute_path"] = str(tmp_path)
    path = tmp_path / "clean.pkl"
    path.write_bytes(pickle.dumps({}))
    report = tmp_path / "raw.json"
    report.write_text(json.dumps(capture["report"]))
    found = site(tmp_path, "pickle.load('clean.pkl')")
    join(found, load_receipts(report), tmp_path)
    assert found[0].coverage == "uncovered"


def test_demo_six_paths():
    found, errors = scan(DEMO)
    assert not errors and len(found) == 6
    join(found, load_receipts(DEMO / "receipts.json"), DEMO)
    assert [f.coverage for f in found] == ["covered", "uncovered", "uncovered", "unsupported-format", "unresolved", "not-required"]
    assert coverage_summary(found) == {"resolvable": 4, "covered": 1, "unresolved": 1, "not_required": 1, "percent": 25.0}


def test_data_only_sites_never_require_receipts(tmp_path):
    (tmp_path / "app.py").write_text("from safetensors.torch import load_file\nload_file('absent.safetensors')\nload_file(dynamic)")
    found, _ = scan(tmp_path)
    join(found, [], tmp_path)
    assert all(f.coverage == "not-required" for f in found)
    assert coverage_summary(found) == {"resolvable": 0, "covered": 0, "unresolved": 0, "not_required": 2, "percent": None}
