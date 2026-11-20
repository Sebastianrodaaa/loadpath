import io
import json
import lzma
import pickle
import struct
import tarfile
import zipfile
import zlib

import pytest

from loadpath.cli import main
from loadpath.inspect import MAX_BYTES, inspect_artifact, inspect_bytes
from loadpath.receipts import sha256


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


def test_never_deserializes(tmp_path, monkeypatch):
    data = pickle.dumps({"a": 1}, protocol=4)
    path = tmp_path / "dict.pkl"
    path.write_bytes(data)

    def forbidden(*args, **kwargs):
        raise AssertionError("deserialization executed")

    monkeypatch.setattr(pickle, "load", forbidden)
    monkeypatch.setattr(pickle, "loads", forbidden)
    assert inspect_artifact(path)["protocol"] == 4
    path.write_bytes(b"\x80\x02cos\nsystem\n.")
    assert inspect_artifact(path)["imports"][0]["module"] == "os"


def test_stack_global_and_memo():
    data = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93."
    result = inspect_bytes(data)
    assert result["imports"][0]["name"] == "system"
    data = b"\x80\x04\x8c\x02os\x940h\x00\x8c\x06system\x93."
    assert inspect_bytes(data)["imports"][0]["module"] == "os"
    assert inspect_bytes(b"\x80\x04\x93.")["imports"][0]["module"] == "<unresolved>"


@pytest.mark.parametrize("protocol", range(6))
def test_pickle_protocols(protocol):
    assert inspect_bytes(pickle.dumps({"x": 1}, protocol=protocol), "x.pkl")["protocol"] == protocol


def test_torch_nested_and_limits():
    pkl = pickle.dumps({"x": 1})
    assert inspect_bytes(zip_bytes({"weights/data.pkl": pkl}))["format"] == "torch-zip"
    nested = zip_bytes({"inner.zip": zip_bytes({"model.pkl": pkl})})
    assert inspect_bytes(nested)["members"][0]["members"][0]["format"] == "pickle"
    deep = inspect_bytes(zip_bytes({"again.zip": nested}))
    assert deep["members"][0]["members"][0]["errors"] == ["archive depth limit exceeded"]
    assert inspect_bytes(b"x" * (MAX_BYTES + 1))["errors"] == ["size limit exceeded"]
    many = inspect_bytes(zip_bytes({str(i): b"x" for i in range(65)}))
    assert "archive member limit exceeded" in many["errors"]
    limited = inspect_bytes(zip_bytes({"large": b"abc"}), budget={"bytes": 2, "members": 2})
    assert limited["members"][0]["errors"]


def test_tar_never_extracts(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo("../../outside.pkl")
        data = pickle.dumps({"x": 1})
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
    result = inspect_bytes(stream.getvalue())
    assert result["format"] == "tar" and result["members"][0]["format"] == "pickle"
    assert not (tmp_path / "outside.pkl").exists()


def test_headers():
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,)}\n"
    npy = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header
    assert inspect_bytes(npy)["header"]["descr"] == "|O"
    assert inspect_bytes(zip_bytes({"array.npy": npy}))["format"] == "npz"
    assert inspect_bytes(b"\x89HDF\r\n\x1a\n")["format"] == "hdf5"
    safe = json.dumps({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    assert inspect_bytes(struct.pack("<Q", len(safe)) + safe + b"\0" * 4)["format"] == "safetensors"
    assert inspect_bytes(zlib.compress(pickle.dumps({})))["format"] == "joblib-compressed"


def test_empty_and_corrupt(tmp_path):
    assert inspect_bytes(b"")["format"] == "unknown"
    assert inspect_bytes(b"\x80\x04")["errors"]
    assert inspect_bytes(b"PK\x03\x04broken")["errors"]
    assert inspect_bytes(b"\x93NUMPY")["errors"]
    with pytest.raises(ValueError):
        inspect_artifact(tmp_path)


def corrupt_deflated_zip():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("weights/data.pkl", b"\x80\x02N.")
        archive.writestr("good.pkl", b"\x80\x02N.")
    data = bytearray(stream.getvalue())
    name_size, extra_size = struct.unpack_from("<HH", data, 26)
    data[30 + name_size + extra_size] = 7
    return bytes(data)


def test_corrupt_deflate_member_does_not_abort_report(tmp_path, capsys):
    artifact = tmp_path / "model.pt"
    artifact.write_bytes(corrupt_deflated_zip())
    info = inspect_artifact(artifact)
    assert info["members"][0]["name"] == "weights/data.pkl"
    assert info["members"][0]["errors"]
    assert info["members"][1]["format"] == "pickle"
    source = tmp_path / "app.py"
    source.write_text("import torch\ntorch.load('model.pt')\ntorch.load('absent.pt')")
    receipts = tmp_path / "receipts.json"
    receipts.write_text(json.dumps([{
        "artifact": "model.pt", "sha256": sha256(artifact), "scanner": "picklescan",
        "version": "1.0.4", "formats": ["torch-zip"],
    }]))
    report = tmp_path / "report.html"
    assert main(["scan", str(source), "--receipts", str(receipts), "--json", "--html", str(report)]) == 0
    document = json.loads(capsys.readouterr().out)
    assert len(document["findings"]) == 2
    assert document["findings"][0]["coverage"] == "unsupported-format"
    assert document["findings"][0]["receipts"][0]["required_format"] == "incomplete-inspection"
    assert report.is_file() and "torch.load" in report.read_text()


@pytest.mark.parametrize("error", [
    zlib.error("invalid deflate"), zipfile.BadZipFile("bad CRC"), EOFError("truncated"),
    lzma.LZMAError("invalid LZMA"), OSError("Invalid data stream"),
])
def test_member_decompression_errors_are_isolated(monkeypatch, error):
    original = zipfile.ZipExtFile.read

    def read(stream, *args, **kwargs):
        if stream.name == "bad.pkl":
            raise error
        return original(stream, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipExtFile, "read", read)
    info = inspect_bytes(zip_bytes({"bad.pkl": b"bad", "good.pkl": b"\x80\x02N."}))
    assert info["members"][0]["errors"] == [str(error)]
    assert info["members"][1]["format"] == "pickle"


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("kind", ["deflate", "crc", "pickle"])
def test_inspect_cli_fails_on_member_errors(tmp_path, capsys, nested, kind):
    if kind == "deflate":
        data = corrupt_deflated_zip()
    elif kind == "crc":
        data = bytearray(zip_bytes({"model.pkl": b"\x80\x02N."}))
        data[30 + len("model.pkl")] ^= 1
        data = bytes(data)
    else:
        data = zip_bytes({"model.pkl": b"\x80\x02"})
    if nested:
        data = zip_bytes({"inner.zip": data})
    artifact = tmp_path / "model.zip"
    artifact.write_bytes(data)
    assert main(["inspect", str(artifact)]) == 2
    info = json.loads(capsys.readouterr().out)
    assert info["errors"]
    assert info["members"][0]["name"] in info["errors"][0]


@pytest.mark.parametrize("data", [b"", zip_bytes({"model.pkl": b"\x80\x02N."})])
def test_inspect_cli_accepts_error_free_members(tmp_path, capsys, data):
    artifact = tmp_path / "model.zip"
    artifact.write_bytes(data)
    assert main(["inspect", str(artifact)]) == 0
    assert not json.loads(capsys.readouterr().out)["errors"]
