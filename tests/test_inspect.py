import io
import json
import pickle
import struct
import tarfile
import zipfile
import zlib

import pytest

from loadpath.inspect import MAX_BYTES, inspect_artifact, inspect_bytes


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
