"""
scripts/render_terminal.py
==========================
Render REAL captured command output into a terminal-styled PNG.

    python scripts/render_terminal.py

Why this exists
---------------
Several pieces of required evidence are console output (the project tree, the
dataset generator, the trainer, the pytest run). This script RUNS each command,
captures its genuine stdout/stderr and draws that text into an image.

It never accepts hand-written text. If a command fails, the failure is what
gets drawn — so a screenshot can never show a success that did not happen.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SHOTS = PROJECT_ROOT / "screenshots"

BG = (13, 17, 23)
FG = (201, 209, 217)
PROMPT = (86, 211, 100)
DIM = (125, 142, 161)
TITLE_BG = (22, 27, 34)

# (output_filename, window_title, shell_command, max_lines)
COMMANDS: List[Tuple[str, str, str, int]] = [
    ("01_project_structure.png", "Project structure",
     r"""python -c "
import os
SKIP={'.git','node_modules','__pycache__','.pytest_cache','.venv','dist','.vite'}
def tree(root,prefix=''):
    entries=sorted([e for e in os.listdir(root) if e not in SKIP and not e.endswith('.pyc')])
    dirs=[e for e in entries if os.path.isdir(os.path.join(root,e))]
    files=[e for e in entries if not os.path.isdir(os.path.join(root,e))]
    entries=dirs+files
    for i,e in enumerate(entries):
        last = i==len(entries)-1
        print(prefix + ('\\\\-- ' if last else '|-- ') + e)
        p=os.path.join(root,e)
        if os.path.isdir(p) and prefix.count('|')<3:
            tree(p, prefix + ('    ' if last else '|   '))
print('Phishing-Email-Detection-Awareness-Dashboard/')
tree('.')
" """, 120),

    ("02_dataset_generation.png", "Dataset generation",
     "python data/generate_dataset.py", 60),

    ("03_model_training.png", "Model training",
     "python ml/train_model.py", 60),

    ("23_test_results.png", "pytest - full suite",
     "python -m pytest tests/ -v --no-header -p no:warnings", 130),
]


def render(text: str, out_path: Path, title: str) -> None:
    from PIL import Image, ImageDraw, ImageFont

    def load_font(size: int):
        for name in ("DejaVuSansMono.ttf", "LiberationMono-Regular.ttf",
                     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
            try:
                return ImageFont.truetype(name, size)
            except OSError:
                continue
        return ImageFont.load_default()

    font = load_font(14)
    title_font = load_font(13)

    lines = text.replace("\t", "    ").split("\n")
    # Measure with the real font so nothing is clipped.
    probe = Image.new("RGB", (10, 10))
    pd = ImageDraw.Draw(probe)
    char_w = pd.textlength("M", font=font) or 8.4
    line_h = 20

    max_cols = max((len(l) for l in lines), default=40)
    width = int(min(max(720, max_cols * char_w + 56), 2100))
    bar = 34
    height = int(bar + 22 + len(lines) * line_h + 22)

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)

    # title bar with the familiar three dots
    d.rectangle([0, 0, width, bar], fill=TITLE_BG)
    for i, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([16 + i * 20, 12, 26 + i * 20, 22], fill=colour)
    d.text((92, 9), title, font=title_font, fill=DIM)

    y = bar + 14
    for line in lines:
        colour = FG
        stripped = line.lstrip()
        if stripped.startswith("$"):
            colour = PROMPT
        elif stripped.startswith(("PASSED", "ok", "OK")) or " PASSED" in line:
            colour = (86, 211, 100)
        elif stripped.startswith(("FAILED", "ERROR", "[error]")) or " FAILED" in line:
            colour = (248, 113, 113)
        elif stripped.startswith(("|--", "\\--", "+--")):
            colour = (125, 211, 252)
        elif stripped.startswith(("=", "-")) and len(set(stripped)) <= 3:
            colour = DIM
        d.text((22, y), line, font=font, fill=colour)
        y += line_h

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path)


def main() -> int:
    try:
        import PIL  # noqa: F401
    except ImportError:
        print("[error] Pillow is required:  pip install pillow")
        return 1

    SHOTS.mkdir(parents=True, exist_ok=True)
    failures = 0

    for filename, title, command, max_lines in COMMANDS:
        print(f"  {filename:<30} running: {command.strip().splitlines()[0][:52]}…")
        proc = subprocess.run(command, shell=True, cwd=PROJECT_ROOT,
                              capture_output=True, text=True, timeout=1800)
        output = (proc.stdout or "") + (proc.stderr or "")
        lines = [l.rstrip() for l in output.split("\n")]
        # Drop the logger's INFO chatter so the evidence stays readable.
        lines = [l for l in lines if "| INFO     | phishguard" not in l]
        while lines and not lines[-1]:
            lines.pop()
        if len(lines) > max_lines:
            head = lines[: max_lines - 12]
            tail = lines[-10:]
            lines = head + ["", f"    ... {len(lines) - max_lines + 2} lines omitted ...", ""] + tail

        display_cmd = " ".join(command.split()) if "\n" not in command.strip() else command.strip().split("\n")[0]
        if len(display_cmd) > 150:
            display_cmd = display_cmd[:147] + "..."
        body = f"$ {display_cmd}\n\n" + "\n".join(lines)
        render(body, SHOTS / filename, title)

        if proc.returncode != 0:
            failures += 1
            print(f"      exit code {proc.returncode} - the failure is visible in the image")

    print("-" * 70)
    print(f"  rendered {len(COMMANDS)} terminal screenshots into {SHOTS}")
    if failures:
        print(f"  WARNING: {failures} command(s) exited non-zero.")
        return 2
    print("  every command exited 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
