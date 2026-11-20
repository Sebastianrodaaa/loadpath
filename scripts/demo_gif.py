"""Monochrome terminal animation captured from real CLI subprocesses."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
WIDTH, HEIGHT, LINE, PAD = 1280, 680, 17, 24
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 13)


def run(command):
    env = {**os.environ, "PATH": str(ROOT / ".venv/bin") + os.pathsep + os.environ["PATH"], "NO_COLOR": "1", "COLUMNS": "148"}
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=30, check=True)
    return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr).rstrip().splitlines()


class Terminal:
    def __init__(self):
        self.lines, self.frames, self.durations, self.proofs = [], [], [], []

    def snap(self, duration):
        image = Image.new("L", (WIDTH, HEIGHT), 0)
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, WIDTH, 36), fill=19)
        for x in (20, 40, 60):
            draw.ellipse((x - 4, 14, x + 4, 22), outline=100)
        draw.text((WIDTH // 2, 18), "loadpath · real CLI capture · no model loaded", anchor="mm", fill=145, font=FONT)
        rows = (HEIGHT - 70) // LINE
        for i, line in enumerate(self.lines[-rows:]):
            draw.text(
                (PAD, 52 + i * LINE),
                line,
                fill=240 if line.startswith("$ ") else 130 if line.startswith("# ") else 200,
                font=BOLD if line.startswith("$ ") else FONT,
            )
        self.frames.append(image)
        self.durations.append(duration)

    def stage(self, command, caption, output):
        self.lines = ["# " + caption, "", "$ "]
        for i in range(0, len(command), 5):
            self.lines[-1] = "$ " + command[: i + 5]
            self.snap(45)
        self.snap(700)
        for line in output:
            self.lines.append(line)
            self.snap(65)
        self.snap(6500)
        self.proofs.append(self.frames[-1].copy())


def main():
    marker = ROOT / "examples/demo_app/global-reference.pkl"
    before = hashlib.sha256(marker.read_bytes()).hexdigest()
    terminal = Terminal()
    transcript = []
    stages = [
        (["loadpath", "scan", "examples/demo_app"], "1. inventory before scanner evidence: zero covered edges"),
        (["loadpath", "inspect", "examples/demo_app/global-reference.pkl"], "2. read GLOBAL opcodes; never import or deserialize the object"),
        (
            ["loadpath", "scan", "examples/demo_app", "--receipts", "examples/demo_app/receipts.json"],
            "3. a real hash-bound receipt closes one gap, not every loading path",
        ),
    ]
    for command, caption in stages:
        output = run(command)
        display = " ".join(command)
        terminal.stage(display, caption, output)
        transcript.extend(["$ " + display, *output, ""])
    sarif_lines = run(["loadpath", "scan", "examples/demo_app", "--receipts", "examples/demo_app/receipts.json", "--sarif"])
    sarif = "\n".join(sarif_lines) + "\n"
    (ROOT / "results/demo.sarif").write_text(sarif)
    document = json.loads(sarif)
    assert document["version"] == "2.1.0"
    command = "loadpath scan examples/demo_app --receipts examples/demo_app/receipts.json --sarif > results/demo.sarif"
    code = "import json; r=json.load(open('results/demo.sarif')); print('SARIF',r['version'],len(r['runs'][0]['results']),'findings')"
    output = run(["python", "-c", code])
    summary_command = f'python -c "{code}"'
    terminal.stage(command, "4. the same findings as SARIF 2.1.0 for code scanning", ["$ " + summary_command, *output])
    transcript.extend(["$ " + command, *sarif_lines, "$ " + summary_command, *output])
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == before
    (ROOT / "results/demo-transcript.txt").write_text("\n".join(transcript) + "\n")
    terminal.frames[0].save(
        ROOT / "docs/screenshots/demo.gif", save_all=True, append_images=terminal.frames[1:], duration=terminal.durations, loop=0, optimize=True
    )
    proof = Image.new("L", (WIDTH * 2, HEIGHT * 2))
    for i, frame in enumerate(terminal.proofs):
        proof.paste(frame, ((i % 2) * WIDTH, (i // 2) * HEIGHT))
    proof.save(ROOT / "results/demo-preview.png")
    print(f"Captured {len(terminal.frames)} frames, {sum(terminal.durations) / 1000:.1f}s; marker hash unchanged")


if __name__ == "__main__":
    main()
