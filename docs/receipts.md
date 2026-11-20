# Scanner receipts

Native JSON is a list, or `{"receipts": [...]}`. Paths are relative to the receipt document, not to the scanned source.

```json
{"receipts": [{"artifact": "clean.pkl", "sha256": "<64 lowercase hex characters>",
  "scanner": "picklescan", "version": "1.0.4", "formats": ["pickle"], "complete": true}]}
```

`complete` defaults to true for native receipts. A receipt is an assertion by its producer. Unknown scanner names use
the native explicit format declaration; known scanner names/versions cannot enlarge the table below. An unknown
version of a known scanner supports no formats until its coverage is reviewed.

| Scanner | Admitted subset | Not admitted |
|---|---|---|
| picklescan 1.0.4 | plain pickle, torch ZIP data.pkl, npy, npz | compressed joblib, nested archives, TorchScript, remote code, Keras, skops |
| modelscan 0.8.8 | plain pickle, torch ZIP data.pkl, npy, npz, HDF5, Keras, SavedModel | compressed joblib, nested archives, TorchScript, remote code, skops |

These are conservative coverage declarations, not an exhaustive list of upstream capabilities. Plain joblib pickle
streams can match `pickle`; compressed joblib streams cannot. A nominally supported format still needs an exact hash,
successful scan evidence, and matching loader semantics. ZIP wrappers are not blanket coverage of arbitrary contents.

Sources: [picklescan scanner](https://github.com/mmaitre314/picklescan/blob/v1.0.4/src/picklescan/scanner.py),
[picklescan CLI](https://github.com/mmaitre314/picklescan/blob/v1.0.4/src/picklescan/cli.py),
[ModelScan defaults](https://github.com/protectai/modelscan/blob/0.8.8/modelscan/settings.py),
[ModelScan report generation](https://github.com/protectai/modelscan/blob/0.8.8/modelscan/modelscan.py).
Pinned installed source and actual scans were also checked when building the demo.

## Real formats and adapters

picklescan's CLI emits text, not JSON. Its public `scan_file_path` API returns a `ScanResult` dataclass with `globals`,
`scanned_files`, `issues_count`, `infected_files`, and `scan_err`; each global has module/name/safety. The importer
accepts the dataclass serialized to JSON with enum values converted to strings, in a capture envelope:
`{"type":"picklescan","artifact":"clean.pkl","sha256":"...","version":"1.0.4","result":{...}}`.
Capture one artifact per invocation; aggregate counts cannot establish coverage for individual paths. The raw result
and any dangerous-global findings are retained. An infected result can be covered: coverage is not safety.

ModelScan's `-r json -o FILE` output contains `summary.modelscan_version`, `summary.absolute_path`,
`summary.scanned.scanned_files`, `issues`, `errors` and optional skipped-file data. The importer uses scanned files,
never just issue locations or zero-issue summaries. Raw ModelScan reports contain no artifact hashes: they import
as uncovered evidence unless wrapped at capture time as
`{"type":"modelscan","report":{...},"hashes":{"clean.pkl":"..."}}`.
The demo includes both raw and wrapped reports. Absolute source paths in raw output are preserved as real scanner
evidence, so the wrapped ModelScan capture may need regeneration after moving the checkout. Native demo picklescan
receipts use relative paths and are portable.

`scripts/build_fixtures.py` hashes before and after each scan, asserting stability; it never retroactively hashes a
historical report and calls it current. No adapter imports third-party scanner packages during normal scans.

An incomplete/error report cannot cover a supported format. A mismatched hash is stale; a current hash plus an
unadmitted format is unsupported even when the scanner itself reported errors. With multiple receipts, covered wins
the site rollup, then stale-hash, unsupported-format, uncovered. All individual statuses remain in JSON.

LP013 safetensors sites are data-only inventory (`not-required`) before receipt matching. They require no scanner
receipt and never enter required resolvable/unresolved counts or the coverage ratio, even for missing or dynamic paths.
An all-safetensors inventory has zero required sites and a null percentage, not zero-percent coverage.

The independent [scanner experiment](../eval/README.md) measures actual observations; it does not automatically expand
this conservative admission table. Scanners may flag particular archive contents without establishing every loader's
path semantics. The matrix preserves errors and skips alongside findings.
