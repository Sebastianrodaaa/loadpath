"""Monochrome measurement plots from recorded results; no scanners or network calls."""

import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/screenshots"
STYLE = {
    "figure.facecolor": "black",
    "axes.facecolor": "black",
    "savefig.facecolor": "black",
    "text.color": "#ddd",
    "axes.labelcolor": "#bbb",
    "axes.edgecolor": "#444",
    "xtick.color": "#999",
    "ytick.color": "#999",
    "font.family": "monospace",
    "font.size": 10,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.color": "#1c1c1c",
    "legend.frameon": False,
}
STATUSES = {
    "flagged": ("#fff", "F"),
    "flagged+error": ("#ccc", "F/E"),
    "scanned-no-flag": ("#888", "N"),
    "skipped": ("#333", "S"),
    "error": ("#555", "E"),
    "timeout": ("#111", "T"),
}


def save(fig, name, out):
    fig.tight_layout()
    fig.savefig(out / f"{name}.png", dpi=140)
    plt.close(fig)


def scanner_plot(result, out=OUT):
    rows = result["fixtures"]
    names = ["picklescan", "modelscan"]
    statuses = list(STATUSES)
    values = [[statuses.index(row["scanners"][name]["status"]) for name in names] for row in rows]
    fig, ax = plt.subplots(figsize=(10.5, max(4, len(rows) * 0.31 + 2)))
    ax.imshow(values, aspect="auto", cmap=ListedColormap([v[0] for v in STATUSES.values()]), vmin=-0.5, vmax=len(statuses) - 0.5)
    ax.grid(False)
    ax.set_yticks(range(len(rows)), [row["file"] for row in rows], fontsize=8)
    ax.set_xticks(range(2), [f"{name} {result['versions'][name]}" for name in names])
    ax.xaxis.tick_top()
    for i, row in enumerate(rows):
        for j, name in enumerate(names):
            status = row["scanners"][name]["status"]
            ax.text(j, i, STATUSES[status][1], ha="center", va="center", color="black" if statuses.index(status) < 3 else "white", fontsize=8)
    ax.set_title(
        "loadpath · inert format-wrapper measurements\nFlags are scanner policy, not execution or safety; wrapper-only cases included.", pad=40, fontsize=11
    )
    fig.legend(
        handles=[Patch(facecolor=color, edgecolor="#999", label=f"{label}: {status}") for status, (color, label) in STATUSES.items()],
        loc="lower center",
        ncol=3,
        fontsize=8,
        bbox_to_anchor=(0.5, 0.005),
    )
    fig.tight_layout(rect=(0, 0.055, 1, 1))
    fig.savefig(out / "scanner-coverage.png", dpi=140)
    plt.close(fig)


def eval_plot(result, out=OUT):
    fig, (overall, families) = plt.subplots(1, 2, figsize=(12, 5.5), gridspec_kw={"width_ratios": [1, 1.2]})
    systems = result["systems"]
    for i, name in enumerate(("loadpath", "regex")):
        color = "#fff" if i == 0 else "#666"
        offsets = [j + (i - 0.5) * 0.36 for j in range(3)]
        scores = [systems[name]["overall"][metric] for metric in ("precision", "recall", "f1")]
        overall.bar(offsets, scores, width=0.34, color=color, label=name)
        for x, score in zip(offsets, scores):
            overall.text(x, score + 0.025, f"{score:.2f}", ha="center", fontsize=8)
        rules = list(systems[name]["families"])
        families.barh(
            [j + (i - 0.5) * 0.36 for j in range(len(rules))], [systems[name]["families"][r]["f1"] for r in rules], height=0.34, color=color, label=name
        )
    overall.set(xticks=[0, 1, 2], xticklabels=["precision", "recall", "F1"], ylim=(0, 1.14), title="Overall exact call-site scores")
    overall.legend(loc="upper right")
    families.set(yticks=range(len(rules)), yticklabels=rules, xlim=(0, 1.05), title="F1 by rule family", xlabel="F1")
    families.invert_yaxis()
    fig.suptitle(f"loadpath · {result['dataset']['snippets']} synthetic snippets · not a held-out benchmark", fontsize=12)
    save(fig, "eval-baseline", out)


def registry_counts(result):
    counts = Counter()
    for name, count in result["summary"]["by_loader"].items():
        counts[name.split(".")[0]] += count
    return counts.most_common()


def registry_plot(result, out=OUT):
    counts = registry_counts(result)
    fig, ax = plt.subplots(figsize=(10, 5.2))
    ax.barh([name for name, _ in counts], [count for _, count in counts], color="#ddd", edgecolor="#fff", lw=0.5)
    for i, (_, count) in enumerate(counts):
        ax.text(count + 30, i, f"{count:,}", va="center", fontsize=8)
    ax.invert_yaxis()
    total = result["summary"]["call_sites"]
    ax.set(
        xlim=(0, max(c for _, c in counts) * 1.14),
        xlabel="Static call sites, grouped by root library (not runtime calls)",
        title=f"{result['summary']['completed']} public repos · {total:,} call sites · tests/examples included",
    )
    fig.suptitle("loadpath · public source inventory, not vulnerability findings", fontsize=12)
    save(fig, "registry-loaders", out)


def main():
    results = {name: json.loads((ROOT / "results" / f"{name}.json").read_text()) for name in ("scanner_coverage", "eval", "registry")}
    OUT.mkdir(exist_ok=True)
    with plt.rc_context(STYLE):
        scanner_plot(results["scanner_coverage"])
        eval_plot(results["eval"])
        registry_plot(results["registry"])
    print("Wrote docs/screenshots/{scanner-coverage,eval-baseline,registry-loaders}.png")


if __name__ == "__main__":
    main()
