"""
Run pytest with a live progress bar (% complete).

Usage:
  python scripts/run_tests_with_progress.py
  python scripts/run_tests_with_progress.py -k test_actions
  python scripts/run_tests_with_progress.py tests/ -k "actions or threat_intel"

This wrapper:
  1) runs `python -m pytest --collect-only -q ...` to count tests
  2) runs `python -m pytest -vv ...` and prints a progress bar as tests finish
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List
from pathlib import Path


FINAL_STATUS_RE = re.compile(r"\s+(PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR)\s*(\[[^\]]+\])?\s*$")


def _run_collect(pytest_args: List[str]) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", *pytest_args]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
    if p.returncode != 0:
        raise RuntimeError(f"pytest collect failed:\n{p.stdout}\n{p.stderr}")
    # Each collected nodeid is printed as a line (blank lines ignored)
    return sum(1 for line in p.stdout.splitlines() if line.strip())


def _render_bar(done: int, total: int, width: int = 30) -> str:
    if total <= 0:
        return "[??????????????????????????????] 0% (0/0)"
    frac = min(1.0, max(0.0, done / total))
    filled = int(round(frac * width))
    bar = "[" + ("#" * filled) + ("-" * (width - filled)) + "]"
    pct = int(frac * 100)
    return f"{bar} {pct:3d}% ({done}/{total})"


def main() -> int:
    # We intentionally do NOT parse pytest flags here; we forward everything to pytest.
    # This lets you run: `python scripts/run_tests_with_progress.py -k test_actions`
    pytest_args = sys.argv[1:]
    total = _run_collect(pytest_args)

    # -vv prints each test line; we parse completions from the trailing status token
    cmd = [sys.executable, "-m", "pytest", "-vv", *pytest_args]
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    # Run from repo root (prevents pytest from crawling the entire drive if invoked from /)
    repo_root = Path(__file__).resolve().parent.parent
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        cwd=str(repo_root),
    )

    done = 0
    last_bar = ""

    assert proc.stdout is not None
    for line in proc.stdout:
        # Keep normal pytest output (so failures are visible)
        sys.stdout.write(line)
        sys.stdout.flush()

        if FINAL_STATUS_RE.search(line):
            done += 1
            bar = _render_bar(done, total)
            if bar != last_bar:
                # Progress line (carriage return to update in-place)
                sys.stdout.write("\r" + bar + " " * 10 + "\n")
                sys.stdout.flush()
                last_bar = bar

    rc = proc.wait()
    # Print final bar (useful when pytest exits early)
    sys.stdout.write(_render_bar(min(done, total), total) + "\n")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())


