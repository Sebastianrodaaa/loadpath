"""Build marker references in public format wrappers, without loading any object."""

import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import pickle
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import dill
import h5py
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DESTINATION = Path(__file__).parent / "artifacts"


def marker(protocol=4):
    # GLOBAL is a function reference only: no REDUCE, arguments, or invocation.
    prefix = b"" if protocol < 2 else b"\x80" + bytes([protocol])
    return prefix + b"cos\ngetcwd\n."


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries.items():
            entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            archive.writestr(entry, data)
    return stream.getvalue()


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def build(destination=DESTINATION):
    destination.mkdir(exist_ok=True)
    fixtures = []

    def add(name, data, path, basis, validity="wrapper-only", marker_present=True, note=""):
        target = destination / name
        target.write_bytes(data)
        fixtures.append(
            {
                "file": name,
                "path": path,
                "basis": basis,
                "validity": validity,
                "marker_present": marker_present,
                "marker": "os.getcwd reference; not invoked" if marker_present else None,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "note": note,
            }
        )

    for protocol in range(6):
        # Real Pickler chooses the protocol-appropriate spelling and opcodes.
        add(f"pickle-protocol-{protocol}.pkl", pickle.dumps(os.getcwd, protocol=protocol), "pkl", "P7 raw pkl", "serializer-produced")
    raw = marker()
    torch_zip = zip_bytes({"archive/data.pkl": raw, "archive/version": b"3\n", "archive/byteorder": b"little"})
    legacy = tar_bytes({"storages": pickle.dumps(0, protocol=2) + pickle.dumps([], protocol=2), "tensors": pickle.dumps(0, protocol=2), "pickle": raw})
    add("torch-zip.pt", torch_zip, "zip→pkl", "P7 Table 1 archive→pkl")
    add("torch-legacy-tar.pt", legacy, "tar→pkl", "P7 case study tar members storages/tensors/pickle")
    add("nested-zip.zip", zip_bytes({"inner.zip": zip_bytes({"model.pkl": raw})}), "zip→zip→pkl", "P7 nested archives")
    add("nested-tar.tar", tar_bytes({"inner.tar": tar_bytes({"model.pkl": raw})}), "tar→tar→pkl", "P7 nested archives")
    add("model-archive.mar", zip_bytes({"weights.pt": torch_zip}), "zip→zip→pkl", "P7 TorchServe wrapper shape")
    add("model-tar-archive.mar", zip_bytes({"weights.pt": legacy}), "zip→tar→pkl", "P7 TorchServe wrapper shape")
    add("nemo-zip.nemo", tar_bytes({"model_weights.ckpt": torch_zip}), "tar→zip→pkl", "P7 NeMo wrapper shape")
    add("nemo-tar.nemo", tar_bytes({"model_weights.ckpt": legacy}), "tar→tar→pkl", "P7 NeMo wrapper shape")
    add("nemo-pickle.nemo", tar_bytes({"model.pkl": raw}), "tar→pkl", "P7 NeMo wrapper shape")
    for name, data, path in [
        ("torch-tar.tgz", gzip.compress(legacy, mtime=0), "gz→tar→pkl"),
        ("torch-zip-in-tar.tgz", gzip.compress(tar_bytes({"weights.pt": torch_zip}), mtime=0), "gz→tar→zip→pkl"),
        ("torch-tar-in-tar.tgz", gzip.compress(tar_bytes({"weights.pt": legacy}), mtime=0), "gz→tar→tar→pkl"),
    ]:
        add(name, data, path, "P7 compressed archives")
    compressors = {
        "zlib": zlib.compress,
        "gz": lambda d: gzip.compress(d, mtime=0),
        "bz2": bz2.compress,
        "lzma": lambda d: lzma.compress(d, format=lzma.FORMAT_ALONE),
        "xz": lzma.compress,
    }
    for kind, compress in compressors.items():
        data = compress(raw)
        add(f"joblib-{kind}.joblib", data, f"{kind}→pkl", "P7 Joblib compression", "standard compressed pickle stream")
        add(f"nemo-{kind}.nemo", tar_bytes({"model.joblib": data}), f"tar→{kind}→pkl", "P7 NeMo compression wrapper shape")
    # Valid object ndarray serialization, not an npy header with an unrelated pickle.
    array = np.array([os.getcwd], dtype=object)
    stream = io.BytesIO()
    np.save(stream, array, allow_pickle=True)
    npy = stream.getvalue()
    add("numpy-objects.npy", npy, "npy→pkl", "P7 NumPy raw pickle-bearing npy", "serializer-produced")
    add("numpy-objects.npz", zip_bytes({"objects.npy": npy}), "zip→npy→pkl", "P7 NumPy npz", "standard npz wrapper")
    add("numpy-raw-pickle.npy", raw, "pkl", "P7 numpy.load fallback for non-npy pickle", "pickle stream under npy suffix")
    add(
        "pandas-pickle.pkl",
        pickle.dumps({"marker": os.getcwd}, protocol=4),
        "pkl",
        "P6 pickle-based sharing; pandas consumer",
        "serializer-produced",
        note="Plain dict, not a DataFrame; read_pickle accepts ordinary pickled objects.",
    )
    add(
        "pandas-pickle.pkl.gz",
        gzip.compress(pickle.dumps({"marker": os.getcwd}), mtime=0),
        "gz→pkl",
        "Compressed pandas pickle stream",
        "standard compressed pickle stream",
    )
    add("dill-marker.dill", dill.dumps(os.getcwd), "pkl", "P6 Python object serialization", "serializer-produced")
    config = {"class_name": "Sequential", "config": {"name": "fixture", "layers": []}}
    config_bytes = json.dumps(config).encode()
    h5path = destination / "keras-metadata.h5"
    with h5py.File(h5path, "w") as model:
        model.attrs["model_config"] = config_bytes.decode()
        model.attrs["keras_version"] = "3.0.0"
        model.create_dataset("marker_reference", data=np.void(raw))
    add(
        "keras-metadata.h5",
        h5path.read_bytes(),
        "hdf5→opaque-pkl",
        "P6 HDF5 full-model container shape",
        note="Opaque marker dataset is not a documented Keras load sink; negative traversal control, not a bypass.",
    )
    add(
        "keras-pickle.keras",
        zip_bytes({"config.json": config_bytes, "metadata.json": b"{}", "assets/marker.pkl": raw}),
        "zip→pkl",
        "P7 .keras archive shape",
        note="Asset marker has no declared loading hook; no claim that load_model reaches it.",
    )
    add(
        "keras-npz.keras",
        zip_bytes({"config.json": config_bytes, "metadata.json": b"{}", "model.weights.npz": zip_bytes({"objects.npy": npy})}),
        "zip→zip→npy→pkl",
        "P7 .keras→.npz→.npy shape",
        note="Container shape only; no TensorFlow/Keras runtime validation.",
    )
    # A configuration policy control contains no executable function bytecode.
    lambda_config = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Lambda", "config": {"function": "placeholder"}}]}}
    add(
        "keras-lambda-control.keras",
        zip_bytes({"config.json": json.dumps(lambda_config).encode(), "assets/marker.pkl": raw}),
        "zip→config",
        "P6 Lambda configuration policy control",
        note="Inspect raw issues to distinguish marker detection from Lambda policy detection; no TensorFlow extra installed.",
    )
    safe_header = json.dumps({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    add(
        "safe-control.safetensors",
        struct.pack("<Q", len(safe_header)) + safe_header + b"\0" * 4,
        "data-only",
        "Negative control",
        "standard header",
        marker_present=False,
    )
    (destination.parent / "manifest.json").write_text(
        json.dumps(
            {
                "fixtures": fixtures,
                "not_reproduced": [
                    "lz4 and tar→lz4→pkl (optional codec not installed)",
                    "P7 malformed/polyglot variants and EDP cases",
                    "NeMo/TorchServe runtime loadability",
                    "P6 executable graph and custom-object vulnerabilities",
                ],
                "sources": [
                    "https://www.usenix.org/system/files/usenixsecurity26-liu-tong.pdf",
                    "https://arxiv.org/abs/2509.06703",
                    "https://github.com/pytorch/pytorch/blob/v2.6.0/torch/serialization.py",
                ],
                "warning": "Inert marker/wrapper study, not reproduction of 22 exploit paths; no model deserialization performed.",
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Built {len(fixtures)} inert format fixtures")
    return fixtures


if __name__ == "__main__":
    build()
