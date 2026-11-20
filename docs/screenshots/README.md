# Screenshots

Render with `.venv/bin/python scripts/plots.py` from recorded results, using the reference project's black background,
monospace typography, grayscale bars/cells and subtle grid treatment:

- `scanner-coverage.png`: all 39 inert fixture observations, with flag/error/skip distinctions.
- `eval-baseline.png`: overall precision/recall/F1 and per-rule F1 against literal regex.
- `registry-loaders.png`: public source call sites grouped by root library (tests/examples included).

These are generated data plots, not screenshots of the HTML report or proof of runtime reachability.

- `banner.png`: pixel blackletter wordmark; render with `.venv/bin/python scripts/banner.py` (also writes `../art/logo.png`).
- `hero.png`: Chrome capture of `results/report.html`, including all six demo paths and the findings table.
- `demo.gif`: real CLI captures; record with `.venv/bin/python scripts/demo_gif.py`. The four final terminal states
  are also saved as `results/demo-preview.png` from the repository root.

To capture the report from the repository root on Linux:

```sh
.venv/bin/loadpath scan examples/demo_app --receipts examples/demo_app/receipts.json --html results/report.html
google-chrome --headless --no-sandbox --hide-scrollbars --window-size=1440,1710 \
  --screenshot="$PWD/docs/screenshots/hero.png" "file://$PWD/results/report.html"
```

Only use `--no-sandbox` for these trusted local fixtures in an isolated environment, not for browsing untrusted content.
