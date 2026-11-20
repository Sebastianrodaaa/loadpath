"""Construct labeled source-only fixtures; no snippet is imported or executed."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = [
    ("LP001", "pickle.load", "'model.pkl'"),
    ("LP002", "dill.load", "'model.dill'"),
    ("LP003", "joblib.load", "'model.joblib'"),
    ("LP004", "torch.load", "'weights.pt', weights_only=False"),
    ("LP005", "torch.jit.load", "'script.pt'"),
    ("LP006", "numpy.load", "'objects.npy', allow_pickle=True"),
    ("LP007", "pandas.read_pickle", "'frame.pkl'"),
    ("LP008", "tensorflow.keras.models.load_model", "'model.h5', safe_mode=False"),
    ("LP009", "tensorflow.saved_model.load", "'saved_model'"),
    ("LP010", "transformers.AutoModel.from_pretrained", "'owner/repo', trust_remote_code=True"),
    ("LP011", "huggingface_hub.hf_hub_download", "'owner/repo', filename='model.pkl'"),
    ("LP012", "skops.io.load", "'model.skops', trusted=['custom.Type']"),
    ("LP013", "safetensors.torch.load_file", "'weights.safetensors'"),
]


def build(destination=ROOT / "eval/corpus"):
    destination.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(source, family, loader=None, needle=None, kind="positive"):
        name = f"{len(cases):03d}_{family}_{kind}.py.txt"
        source += "\n"
        (destination / name).write_text(source)
        expected = []
        if loader:
            pos = source.rindex(needle)
            expected = [{"rule": family, "loader": loader, "line": source.count("\n", 0, pos) + 1, "col": pos - source.rfind("\n", 0, pos)}]
        cases.append({"file": name, "family": family, "kind": kind, "expected": expected, "sha256": hashlib.sha256(source.encode()).hexdigest()})

    for rule, loader, args in FAMILIES:
        root, tail = loader.split(".", 1)
        module, leaf = loader.rsplit(".", 1)
        calls = [
            (f"import {root}\n{loader}({args})", loader),
            (f"import {root} as lib\nlib.{tail}({args})", f"lib.{tail}"),
            (f"from {module} import {leaf}\n{leaf}({args})", leaf),
            (f"from {module} import {leaf} as restore\nrestore({args})", "restore"),
            (f"import {module} as lib\nlib.{leaf}({args})", f"lib.{leaf}"),
            (f"import {root}\ndef wrapper(path):\n    return {loader}(path)", loader),
            (f"import {root}\nPATH = 'model.bin'\n{loader}(PATH)", loader),
            (f"import {root}\nwith open('model.bin', 'rb') as stream:\n    {loader}(stream)", loader),
            (f"import {root}\ngetattr({module}, '{leaf}')({args})", "getattr"),
            (f"import importlib\nimportlib.import_module('{module}').{leaf}({args})", "importlib.import_module"),
        ]
        for i, (source, needle) in enumerate(calls):
            add(source, rule, loader, needle + "(", "dynamic" if i >= 8 else "positive")
        add(f"# Example text only: {loader}({args})\npass", rule, kind="negative-comment")
        add(f'example = "{loader}(path)"', rule, kind="negative-string")

    for flag in ("True", "False", "runtime_flag"):
        for rule, loader, kw in [
            ("LP004", "torch.load", "weights_only"),
            ("LP006", "numpy.load", "allow_pickle"),
            ("LP010", "transformers.AutoModel.from_pretrained", "trust_remote_code"),
        ]:
            add(f"import {loader.split('.')[0]}\n{loader}('model', {kw}={flag})", rule, loader, loader + "(", "risk-argument")
    for source in [
        "import json\njson.load(stream)",
        "import yaml\nyaml.safe_load(stream)",
        "def load(path):\n    return path\nload('file')",
        "from json import load\nload(stream)",
        "class Store:\n    def load(self, path):\n        return path\nStore().load('x')",
        "class torch:\n    @staticmethod\n    def load(path):\n        return path\ntorch.load('not-a-model')",
        "class joblib:\n    @staticmethod\n    def load(path):\n        return path\njoblib.load('not-a-model')",
        "import pickle as p\np = replacement\np.load('x')",
        "def f(torch):\n    return torch.load('local-object')",
        "from local_module import load\nload('file')",
        "import numpy\nnumpy.loadtxt('table')",
        "import torch\ntorch.load_state_dict(state)",
        "import yaml\nyaml.load(stream)",
        "import json as pickle\npickle.load(stream)",
        "import json as torch\ntorch.load(stream)",
    ]:
        add(source, "negative", kind="negative-lookalike")
    # Callback assignment and re-export chains are labeled semantic positives;
    # the inventory is intentionally not taught these cases during evaluation.
    for rule, loader, _ in FAMILIES[:5]:
        add(f"import {loader.split('.')[0]}\nrestore = {loader}\nrestore('model')", rule, loader, "restore(", "callback")
    (destination / "labels.json").write_text(json.dumps({"synthetic": True, "cases": cases}, indent=2) + "\n")
    print(f"Built {len(cases)} labeled snippets")
    return cases


if __name__ == "__main__":
    build()
