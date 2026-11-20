"""Loader policy, independent of artifact scanner verdicts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    summary: str
    format: str


RULES = {
    r.id: r
    for r in [
        Rule("LP001", "pickle-deserialization", "high", "Pickle deserialization can execute code.", "pickle"),
        Rule("LP002", "extended-pickle", "high", "dill and cloudpickle restore executable Python objects.", "pickle"),
        Rule("LP003", "joblib-load", "high", "Joblib may deserialize executable objects, including compressed streams.", "joblib"),
        Rule("LP004", "torch-load", "high", "Unrestricted torch.load can execute code; weights_only changes the loading policy.", "torch"),
        Rule("LP005", "torchscript-load", "high", "TorchScript is executable model code, not just weights.", "torchscript"),
        Rule("LP006", "numpy-pickle", "high", "allow_pickle=True permits object deserialization.", "numpy"),
        Rule("LP007", "pandas-pickle", "high", "read_pickle restores executable Python objects.", "pickle"),
        Rule("LP008", "keras-load", "medium", "safe_mode=False and legacy HDF5 models require special review.", "keras"),
        Rule("LP009", "savedmodel-load", "high", "SavedModel restores executable computation graphs.", "savedmodel"),
        Rule("LP010", "remote-model-code", "high", "trust_remote_code=True permits repository code execution.", "remote-code"),
        Rule("LP011", "hub-download", "info", "Download provenance is context, not scanner coverage.", "download"),
        Rule("LP012", "skops-load", "medium", "Review the trusted types passed to skops.io.load.", "skops"),
        Rule("LP013", "safetensors-load", "info", "Data-only safetensors loading; this is not a certificate for surrounding code.", "safetensors"),
    ]
}

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def classify(loader, args, artifact):
    if loader in {f"{m}.{f}" for m in ("pickle", "cPickle", "_pickle") for f in ("load", "loads", "Unpickler")}:
        return "LP001", "high", "Pickle can execute code."
    if loader in {f"{m}.{f}" for m in ("dill", "cloudpickle") for f in ("load", "loads", "Unpickler")}:
        return "LP002", "high", "Extended pickle can execute code."
    if loader == "joblib.load":
        return "LP003", "high", "Joblib can execute code."
    if loader == "torch.load":
        weights = args.get("weights_only", "<missing>")
        return (
            "LP004",
            "low" if weights is True and "pickle_module" not in args and "**kwargs" not in args else "high",
            (
                f"weights_only={weights!r}; PyTorch >=2.6 defaults to True when pickle_module is not passed; "
                "installed version and custom pickle_module are not inferred."
            ),
        )
    if loader == "torch.jit.load":
        return "LP005", "high", "TorchScript contains executable computation."
    if loader == "numpy.load":
        flag = args.get("allow_pickle", False)
        return "LP006", "high" if flag is True else "low" if flag is False else "medium", "Review allow_pickle; dynamic flags remain uncertain."
    if loader == "pandas.read_pickle":
        return "LP007", "high", "Pandas restores pickle objects."
    if loader in {
        "keras.models.load_model",
        "keras.saving.load_model",
        "keras.load_model",
        "tensorflow.keras.models.load_model",
        "tensorflow.keras.saving.load_model",
        "tensorflow.keras.load_model",
    }:
        legacy = isinstance(artifact, str) and artifact.lower().endswith((".h5", ".hdf5"))
        high = args.get("safe_mode") is False or legacy
        return (
            "LP008",
            "high" if high else "medium",
            (
                "Legacy HDF5 may contain Lambda configuration; safe_mode does not establish safety for .h5."
                if legacy
                else "Review custom_objects and safe_mode; disabling safe_mode permits unsafe Lambda restoration."
            ),
        )
    if loader == "tensorflow.saved_model.load":
        return "LP009", "high", "SavedModel can contain executable graphs."
    if loader.startswith("transformers.") and loader.endswith(".from_pretrained"):
        return "LP010", "high" if args.get("trust_remote_code") is True else "low", "Review trust_remote_code and repository revision."
    if loader in {"huggingface_hub.hf_hub_download", "huggingface_hub.snapshot_download"}:
        return "LP011", "info", "Downloaded path is dynamic; follow provenance into downstream loaders."
    if loader == "skops.io.load":
        return "LP012", "medium", "Trusted types are policy, not a safety guarantee."
    if loader in {"safetensors.safe_open", "safetensors.torch.load_file", "safetensors.numpy.load_file", "safetensors.flax.load_file"}:
        return "LP013", "info", "Data-only format; informational inventory."
    return None
