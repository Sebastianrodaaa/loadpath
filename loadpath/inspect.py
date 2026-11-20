"""Bounded format inspection. No object deserialization or model imports."""

from __future__ import annotations

import ast
import io
import json
import lzma
import pickletools
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 2
MAX_MEMBERS = 64
ARCHIVE_ERRORS = (OSError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, lzma.LZMAError)


def pickle_imports(data):
    imports, stack, memo = [], [], {}
    protocol = 0
    error = None
    try:
        for count, (op, arg, pos) in enumerate(pickletools.genops(data)):
            if count > 100000:
                raise ValueError("opcode limit exceeded")
            protocol = max(protocol, op.proto)
            if op.name == "PROTO":
                protocol = arg
            elif op.name == "GLOBAL":
                module, name = arg.split(" ", 1)
                imports.append({"module": module, "name": name, "offset": pos, "opcode": "GLOBAL"})
                stack.append(None)
            elif op.name in {"UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "STRING"}:
                stack.append(arg)
            elif op.name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                memo[int(arg)] = stack[-1] if stack else None
            elif op.name == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else None
            elif op.name in {"BINGET", "LONG_BINGET", "GET"}:
                stack.append(memo.get(int(arg)))
            elif op.name == "STACK_GLOBAL":
                name = stack.pop() if stack else None
                module = stack.pop() if stack else None
                imports.append({"module": module or "<unresolved>", "name": name or "<unresolved>", "offset": pos, "opcode": "STACK_GLOBAL"})
                stack.append(None)
            elif op.name in {"FRAME", "STOP"}:
                pass
            elif op.name == "POP":
                if stack:
                    stack.pop()
            elif op.name == "DUP":
                stack.append(stack[-1] if stack else None)
            else:
                # Unknown stack effects must never be interpreted as a known import.
                stack.clear()
    except (ValueError, UnicodeError, OverflowError, IndexError) as exc:
        error = str(exc)
    return protocol, imports, error


def inspect_bytes(data, name="<bytes>", depth=0, budget=None):
    if budget is None:
        budget = {"bytes": MAX_BYTES, "members": MAX_MEMBERS}
    result = {"name": name, "format": "unknown", "size": len(data), "members": [], "errors": []}
    if len(data) > MAX_BYTES:
        result["errors"].append("size limit exceeded")
        return result
    if data.startswith(b"\x93NUMPY"):
        result["format"] = "numpy"
        try:
            major = data[6]
            offset = 10 if major == 1 else 12
            size = struct.unpack("<H" if major == 1 else "<I", data[8:offset])[0]
            if major not in {1, 2, 3} or size > 65536 or offset + size > len(data):
                raise ValueError("invalid npy header")
            header = ast.literal_eval(data[offset : offset + size].decode("utf-8" if major == 3 else "latin1"))
            if not isinstance(header, dict):
                raise ValueError("invalid npy metadata")
            result["header"] = header
        except (ValueError, SyntaxError, struct.error, IndexError) as exc:
            result["errors"].append(str(exc))
        return result
    if data.startswith(b"\x89HDF\r\n\x1a\n"):
        result["format"] = "hdf5"
        return result
    if data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"\x04\x22\x4d\x18")) or (
        len(data) >= 2 and data[0] == 0x78 and int.from_bytes(data[:2], "big") % 31 == 0
    ):
        result["format"] = "joblib-compressed"
        return result
    if len(data) >= 8:
        size = int.from_bytes(data[:8], "little")
        if 2 <= size <= min(65536, len(data) - 8):
            try:
                header = json.loads(data[8 : 8 + size])
                if isinstance(header, dict) and all(
                    k == "__metadata__" or (isinstance(v, dict) and {"dtype", "shape", "data_offsets"} <= v.keys()) for k, v in header.items()
                ):
                    result.update(format="safetensors", header=header)
                    return result
            except (ValueError, UnicodeError):
                pass
    is_zip = data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06")
    is_tar = len(data) > 262 and data[257:262] == b"ustar"
    if is_zip or is_tar:
        result["format"] = "zip" if is_zip else "tar"
        if depth >= MAX_DEPTH:
            result["errors"].append("archive depth limit exceeded")
            return result
        try:
            archive = zipfile.ZipFile(io.BytesIO(data)) if is_zip else tarfile.open(fileobj=io.BytesIO(data), mode="r:")
            with archive:
                entries = archive.infolist() if is_zip else archive
                for entry in entries:
                    if budget["members"] <= 0:
                        result["errors"].append("archive member limit exceeded")
                        break
                    budget["members"] -= 1
                    member_name = entry.filename if is_zip else entry.name
                    size = entry.file_size if is_zip else entry.size
                    if entry.is_dir() if is_zip else not entry.isfile():
                        continue
                    if is_zip and member_name.endswith("/data.pkl"):
                        result["format"] = "torch-zip"
                    if is_zip and member_name.endswith(".npy") and result["format"] != "torch-zip":
                        result["format"] = "npz"
                    if size > budget["bytes"]:
                        result["members"].append({"name": member_name, "format": "unknown", "errors": ["archive byte limit exceeded"]})
                        continue
                    try:
                        stream = archive.open(entry) if is_zip else archive.extractfile(entry)
                        with stream:
                            member = stream.read(min(size + 1, budget["bytes"] + 1))
                        budget["bytes"] -= len(member)
                        result["members"].append(inspect_bytes(member, member_name, depth + 1, budget))
                    except ARCHIVE_ERRORS as exc:
                        budget["bytes"] -= min(size, budget["bytes"])
                        result["members"].append({"name": member_name, "format": "unknown", "errors": [str(exc)]})
        except ARCHIVE_ERRORS as exc:
            result["errors"].append(str(exc))
        for member in result["members"]:
            result["errors"].extend(f"{member['name']}: {error}" for error in member.get("errors", []))
        return result
    definite_pickle = data.startswith(b"\x80") or Path(name).suffix.lower() in {".pkl", ".pickle", ".joblib"}
    if definite_pickle or data[:1] in {b"c", b"(", b"}", b"I", b"N", b"l", b"d"}:
        protocol, imports, error = pickle_imports(data)
        if error and not definite_pickle:
            return result
        result.update(format="pickle", protocol=protocol, imports=imports)
        if error:
            result["errors"].append(error)
    return result


def inspect_artifact(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Artifact is not a regular file: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    return inspect_bytes(data, str(path))
