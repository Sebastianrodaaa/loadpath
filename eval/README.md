# Evaluation

Three independent measurements: source inventory accuracy, artifact scanner observations, and public source prevalence.
None measures malware detection, runtime reachability, or model safety. No source snippet or model is executed.

## Reproduce

From the repository root, after the normal development install:

```sh
.venv/bin/pip install -r eval/requirements.txt
.venv/bin/python -m eval.build_corpus
.venv/bin/python -m eval.run_eval
.venv/bin/python -m eval.scanner_coverage.build
.venv/bin/python -m eval.scanner_coverage.run
.venv/bin/python scripts/registry_scan.py --pins results/registry.json
.venv/bin/python scripts/plots.py
```

Registry replay needs network access and Git; all other measurements run locally on CPU. The first inventory run
without `--pins` samples current default branches; replay uses the saved full SHAs. A deleted/unavailable upstream
commit can prevent replay. Clones are depth one (including pin fetches), never installed/imported/executed, and deleted
in `finally`. No model files are downloaded separately. Plots only read the saved JSON.
Pinned measurement dependencies are in `eval/requirements.txt`; scanner results also record installed versions.
Binary output, HDF5 metadata, timings and capture timestamps are not promised byte-identical across platforms/reruns.

## Labeled source corpus

`corpus/labels.json` labels **185 source snippets** (144 positive sites, 41 negative snippets) with expected rule,
canonical loader, and one-based line/column. Empty `expected` means **none**. `.py.txt` keeps these source-only fixtures
out of project scans and accidental imports; the evaluator reads each explicitly. Every source and label manifest has
a SHA-256. Generation is deterministic; no snippet is imported or executed, and labels do not come from scanner output.

The 13 families use direct calls, module/from-import aliases, module attribute chains, wrapper bodies, simple constants,
open-file contexts, getattr, dynamic importlib imports and callback assignments. Explicit True/False/dynamic values
cover weights_only, allow_pickle and trust_remote_code. Safe lookalikes include json.load, yaml.safe_load, a local
load function, shadowed namespaces/parameters and comments/string examples.

Both systems receive identical files. The baseline is Python regex over canonical dotted loader spellings followed
by `(` (equivalent to a literal-name `rg` inventory), not a competing AST analyzer. It intentionally includes
comments/strings and cannot resolve aliases. A true positive requires an exact **rule + loader + line + column** match;
precision = TP/(TP+FP), recall = TP/(TP+FN), F1 is their harmonic mean (undefined empty terms reported as 0).
Overall is micro-aggregated; `results/eval.json` contains all 13 family metrics and every prediction/miss/false positive.

| System | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| loadpath | 113 | 3 | 31 | 0.9741 | 0.7847 | 0.8692 |
| literal regex | 61 | 31 | 83 | 0.6630 | 0.4236 | 0.5169 |

**Known weaknesses stay in the score:** 26 getattr/dynamic-import positives and five callback assignments are missed.
Namespace lookalikes (local classes named torch/joblib, and a torch parameter) account for the three false positives.
The AST tool is not changed to fit the corpus. Template-heavy synthetic snippets weight families evenly and were
written with knowledge of the inventory's design; this is **not held-out testing, a natural prevalence estimate,
or a ranking against sophisticated source-analysis tools**. Risk values are corpus coverage, not separately scored
classification labels; core risk-classification behavior is covered by pytest.

## Format × scanner observations

`scanner_coverage/build.py` writes **39 inert artifacts**, with manifest hashes and per-case validity notes.
`results/scanner_coverage.json` retains raw per-scanner reports, diagnostic output, scan counts, errors, versions,
and references. [The complete matrix](../results/scanner_coverage.md) is the headline artifact, not a malware score.

Every pickle-bearing fixture contains a harmless **os.getcwd function reference** (`posix.getcwd` when serialized
on Linux), never a call. Pickle protocols 0–5, object-array payloads and dill are serializer-produced. The manually
written marker is GLOBAL/STOP, never REDUCE. `numpy.save` writes the object array but it is never read back. Builders
use only serialization, bytes, archive/compression and HDF5 metadata APIs, not model loaders.

The worker calls real public scanner APIs with their default settings, **one process per scanner/artifact**, 45-second
timeout, and Python/C pickle load/loads/Unpickler entry points disabled. SHA-256 must match before and after both scans.
No fixture is loaded to validate it. Statuses:

- **flagged:** at least one default-policy scanner finding; harmless references can be classified critical.
- **flagged+error:** findings **and** errors; not a complete/clean scanner run.
- **scanned-no-flag:** scanner reports a scanned file and no issue/error; not proof of traversing the inner marker.
- **skipped:** no scanned file, finding or error; raw skip diagnostics are retained.
- **error / timeout:** failed parser/dependency/unsupported nesting or bounded runtime; never counted as clean.

### Research coverage and limits

[P7: The Art of Hide and Seek](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-tong), Table 1,
documents seven wrapper categories and 22 concrete loading paths. We reproduce public **byte-wrapper shapes**:
raw pickle; ZIP/TAR; zlib/gzip/bzip2/lzma/xz; gzip→TAR; TAR→compression; ZIP/TAR nested in ZIP/TAR; and
gzip→TAR→ZIP/TAR. Torch-like ZIP uses data.pkl/version/byteorder; the deprecated Torch TAR uses storages/tensors/pickle.
NeMo and TorchServe suffix/member shapes are included, not their runtimes. Joblib compression fixtures are standard
compressed pickle streams (no numpy-specific Joblib storage blocks). Pandas fixtures are ordinary dict pickle streams,
not DataFrames. NumPy .npy/.npz use a real serializer-produced object array; a raw-pickle .npy tests the fallback shape.

The legacy TAR's zero storage count, empty storage-view list and zero tensor count follow
[PyTorch 2.6's legacy_load structure](https://github.com/pytorch/pytorch/blob/v2.6.0/torch/serialization.py).
This is a source/byte-structure check, not a runtime load test.

**Wrapper-only does not mean framework-loadable.** Torch containers, nested archives, .mar/.nemo and .keras fixtures
are structural probes without runtime validation. They must not be described as confirmed scanner bypasses or as a
reproduction of all 22 working exploit paths. Optional lz4 variants, malformed/polyglot variants, EDP cases and
framework runtime validation are not reproduced and are listed in the manifest/results.

[P6: On the (In)Security of Loading Machine Learning Models](https://arxiv.org/abs/2509.06703) motivates the pickle,
dill, NumPy and Keras container controls, **not a claim of reproducing its six vulnerabilities**. Keras/HDF5 metadata
and Lambda-config controls contain no executable function bytecode. An opaque marker dataset in HDF5 is a traversal
negative control, **not a declared Keras deserialization sink**. A .keras asset has no loading hook. The .keras nested
npz fixture is a wrapper shape only. This environment has no TensorFlow extra: ModelScan's Keras dependency errors
are preserved even when an inner marker is flagged; no Keras policy-detection claim is made. No experiment here
proves that safe_mode or weights_only can be bypassed.

## Public source inventory

`data/repos.txt` is a curated **32-repository convenience sample**, not a random/representative sample or a claim of
current popularity by stars. Results include tests, examples and framework internals; repeated patterns are not deduplicated.
`results/registry.json` retains each commit SHA, finding, duration and parse/clone error; `results/registry.md` is the table.

- **7,409** static call sites, including informational data-only and download-context sites.
- **2,600 / 7,409 (35.09%)** have a literal lexical path; **4,809 (64.91%)** unresolved. These ratios use **all inventory
  sites**, unlike the required scanner-coverage denominator, which excludes LP013. Literal paths need not exist or
  denote local model artifacts (a hub identifier can also be a literal string).
- Of **673 torch.load sites**, **349 (51.86%)** omit weights_only, **50 (7.43%)** explicitly pass False,
  **264 (39.23%)** pass True; the remaining ten use other expressions.
- **12 / 172 (6.98%)** numpy.load sites explicitly set allow_pickle=True.
- **157 / 5,332 (2.94%)** inventoried Transformers from_pretrained sites explicitly set trust_remote_code=True.
- All 32 clones completed; **three partial repositories/four source parse errors** remain in peft, vllm and scikit-learn.
  Python 3.10 parser limitations/new syntax may contribute; no error was silently discarded or hand-corrected.

These counts inventory lexical sites and arguments, not execution or vulnerabilities. Missing weights_only is
version-sensitive (Torch >=2.6 defaults True in the common case); no installed runtime is inferred. Model/runtime
versions, wrapper dispatch and data flow remain unverified. Clones are removed; full SHAs are saved for replay.

## Core demo

The six-path demo has four required resolvable sites, one required unresolved site and one data-only not-required site;
one of the four required resolvable sites has coverage evidence (25%). Scanner completion is not artifact safety.
