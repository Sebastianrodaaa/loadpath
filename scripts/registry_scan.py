"""Read-only source inventory of pinned public repositories; never execute their code."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, timeout=240, check=True, **kwargs)


def inventory_repo(repo, workspace, pin=None):
    destination = workspace / repo.replace("/", "__")
    record = {"repo": repo, "commit": None, "status": "error", "findings": [], "errors": []}
    started = time.monotonic()
    try:
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
        run(["git", "clone", "--depth", "1", "--filter=blob:none", "--quiet", f"https://github.com/{repo}.git", str(destination)], env=env)
        if pin:
            run(["git", "-C", str(destination), "fetch", "--depth", "1", "origin", pin], env=env)
            run(["git", "-C", str(destination), "checkout", "--detach", pin], env=env)
        record["commit"] = run(["git", "-C", str(destination), "rev-parse", "HEAD"]).stdout.strip()
        command = [str(Path(sys.executable).parent / "loadpath"), "scan", str(destination), "--json"]
        completed = subprocess.run(command, text=True, capture_output=True, timeout=240, check=False)
        if completed.returncode not in {0, 2}:
            raise ValueError(f"Inventory exit {completed.returncode}: {completed.stderr[:1000]}")
        report = json.loads(completed.stdout)
        for finding in report["findings"]:
            finding["file"] = str(Path(finding["file"]).relative_to(destination))
            if finding["resolved_artifact"]:
                finding["resolved_artifact"] = finding["resolved_artifact"].replace(str(destination), "<repo>")
            finding.pop("receipts", None)
        record.update(
            status="ok" if not report["errors"] else "partial",
            findings=report["findings"],
            errors=[e.replace(str(destination), "<repo>") for e in report["errors"]],
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        record["errors"] = [str(detail)[:3000]]
    finally:
        if destination.exists():
            shutil.rmtree(destination)
    record["seconds"] = round(time.monotonic() - started, 2)
    return record


def fraction(count, total):
    return {"count": count, "denominator": total, "share": round(count / total, 4) if total else None}


def summarize(records):
    findings = [f for record in records for f in record["findings"]]
    by_loader = Counter(f["loader"] for f in findings)
    torch = [f for f in findings if f["loader"] == "torch.load"]
    numpy = [f for f in findings if f["loader"] == "numpy.load"]
    remote = [f for f in findings if f["rule"] == "LP010"]
    return {
        "repositories": len(records),
        "completed": sum(r["status"] in {"ok", "partial"} for r in records),
        "failed": sum(r["status"] == "error" for r in records),
        "partial": sum(r["status"] == "partial" for r in records),
        "call_sites": len(findings),
        "by_loader": dict(by_loader.most_common()),
        "resolvable": fraction(sum(f["resolved_artifact"] is not None for f in findings), len(findings)),
        "unresolved": fraction(sum(f["resolved_artifact"] is None for f in findings), len(findings)),
        "risk_args": {
            "torch_weights_only_missing": fraction(sum("weights_only" not in f["args"] for f in torch), len(torch)),
            "torch_weights_only_false": fraction(sum(f["args"].get("weights_only") is False for f in torch), len(torch)),
            "torch_weights_only_true": fraction(sum(f["args"].get("weights_only") is True for f in torch), len(torch)),
            "numpy_allow_pickle_true": fraction(sum(f["args"].get("allow_pickle") is True for f in numpy), len(numpy)),
            "transformers_trust_remote_code_true": fraction(sum(f["args"].get("trust_remote_code") is True for f in remote), len(remote)),
        },
    }


def markdown(result):
    rows = [
        "# Public source loader inventory",
        "",
        "Static call sites, not executed paths or vulnerability findings.",
        "",
        "| Repository | Commit | Status | Call sites | Resolvable | Unresolved |",
        "|---|---|---|---:|---:|---:|",
    ]
    for r in result["repositories"]:
        resolved = sum(f["resolved_artifact"] is not None for f in r["findings"])
        rows.append(f"| {r['repo']} | `{r['commit'] or 'unavailable'}` | {r['status']} | {len(r['findings'])} | {resolved} | {len(r['findings']) - resolved} |")
    rows += [
        "",
        "## Headline summary",
        "",
        "```json",
        json.dumps(result["summary"], indent=2),
        "```",
        "",
        "Convenience sample; tests and examples are included. Parse errors remain in the JSON. Missing weights_only is",
        "version-sensitive context (Torch >=2.6 defaults to True), not proof of unsafe execution. Literal-path resolution",
        "does not establish that an artifact exists. No downloaded source is imported or executed; clones are deleted.",
    ]
    return "\n".join(rows) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", type=Path, default=ROOT / "data/repos.txt")
    parser.add_argument("--pins", type=Path, help="Prior registry.json supplying exact commits")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    repos = [line.strip() for line in args.repos.read_text().splitlines() if line.strip() and not line.startswith("#")]
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) for repo in repos):
        raise ValueError("Invalid repository identifier")
    pins = {r["repo"]: r["commit"] for r in json.loads(args.pins.read_text())["repositories"]} if args.pins else {}
    workspace = ROOT / ".registry-clones"
    workspace.mkdir(exist_ok=True)
    records = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(inventory_repo, repo, workspace, pins.get(repo)): repo for repo in repos}
            for future in as_completed(futures):
                record = future.result()
                records.append(record)
                print(f"{record['repo']}: {record['status']} · {len(record['findings'])} call sites", flush=True)
        records.sort(key=lambda r: repos.index(r["repo"]))
        result = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "selection": "Curated convenience sample from data/repos.txt",
            "loadpath_version": "0.1.0",
            "summary": summarize(records),
            "repositories": records,
        }
        (ROOT / "results/registry.json").write_text(json.dumps(result, indent=2) + "\n")
        (ROOT / "results/registry.md").write_text(markdown(result))
        print(json.dumps(result["summary"], indent=2))
    finally:
        if workspace.exists() and not any(workspace.iterdir()):
            workspace.rmdir()


if __name__ == "__main__":
    main()
