# Results

Generate a local report with `loadpath scan examples/demo_app --receipts examples/demo_app/receipts.json --html results/report.html`.
No real-world detection rate is claimed by the demo. Scanner capture evidence lives beside the demo artifacts.

- `eval.json`: per-case and per-rule synthetic corpus accuracy, including misses/false positives.
- `scanner_coverage.json` / `.md`: real picklescan/modelscan format-wrapper observations and full raw reports.
- `registry.json` / `.md`: pinned public repository source inventory, parser errors and aggregates.
- `*-run.log`: captured measurement progress, not substitute evidence for the structured reports.

See [evaluation methods and limits](../eval/README.md) before interpreting these numbers. None is a safety verdict.
