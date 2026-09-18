"""Render a 0-100% progress bar for a `train_phishing_classifier.py` run.

The trainer logs machine-readable phase lines; this reads them back and turns
them into a live bar. Works against a run already in flight (it only reads the
log), which a bar inside the trainer cannot do.

    ai/markuplm/.venv/bin/python ai/markuplm/watch_progress.py <logfile>
    ai/markuplm/.venv/bin/python ai/markuplm/watch_progress.py <logfile> --once
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

BAR_WIDTH = 34

RE_CONFIG_EPOCHS = re.compile(r"'epochs': (\d+)")
RE_DOWNLOAD = re.compile(r"(train|test): downloading (\S+)")
RE_SHARD_DONE = re.compile(r"(train|test): (\S+\.parquet) -> (\d+) rows")
RE_PARSING = re.compile(r"Extracting nodes and xpaths")
RE_PARSED = re.compile(r"(train|val|test): (\d+) usable pages")
RE_STEP = re.compile(r"epoch (\d+) step (\d+)/(\d+) loss=([\d.]+) \(([\d.]+) min elapsed\)")
RE_EPOCH_DONE = re.compile(r"epoch (\d+) done:.*'f1_phishing': ([\d.]+)")
RE_BEST = re.compile(r"Best epoch: (\d+)")
RE_TEST = re.compile(r"TEST @([\d.]+): (.*)")
RE_ARTIFACT = re.compile(r"Artifact: (\S+)")


@dataclass
class State:
    epochs: int = 0
    phase: str = "starting"
    shards_done: int = 0
    shards_started: int = 0
    parsed: dict = None
    epoch: int = 0
    step: int = 0
    steps_per_epoch: int = 0
    loss: float = 0.0
    epoch_minutes: float = 0.0
    epoch_f1: list = None
    finished: bool = False
    test_lines: list = None

    def __post_init__(self):
        self.parsed = {}
        self.epoch_f1 = []
        self.test_lines = []

    @property
    def fraction(self) -> float:
        """Overall completion, weighting data prep as the first 10%."""
        if self.finished:
            return 1.0
        if self.steps_per_epoch and self.epochs:
            total = self.steps_per_epoch * self.epochs
            done = self.epoch * self.steps_per_epoch + self.step
            return 0.10 + 0.88 * min(done / total, 1.0)
        if self.phase == "parsing":
            return 0.08
        if self.shards_started:
            return 0.01 + 0.06 * (self.shards_done / max(self.shards_started, 1))
        return 0.0

    @property
    def eta_minutes(self) -> float | None:
        if self.finished or not (self.step and self.epoch_minutes and self.steps_per_epoch):
            return None
        rate = self.step / self.epoch_minutes  # steps per minute
        if rate <= 0:
            return None
        remaining = (self.epochs - self.epoch) * self.steps_per_epoch - self.step
        return remaining / rate


def parse(lines: list[str]) -> State:
    state = State()
    for line in lines:
        if match := RE_CONFIG_EPOCHS.search(line):
            state.epochs = int(match.group(1))
        if RE_DOWNLOAD.search(line):
            state.phase = "downloading"
            state.shards_started += 1
        if RE_SHARD_DONE.search(line):
            state.shards_done += 1
        if RE_PARSING.search(line):
            state.phase = "parsing"
        if match := RE_PARSED.search(line):
            state.parsed[match.group(1)] = int(match.group(2))
        if match := RE_STEP.search(line):
            state.phase = "training"
            state.epoch = int(match.group(1))
            state.step = int(match.group(2))
            state.steps_per_epoch = int(match.group(3))
            state.loss = float(match.group(4))
            state.epoch_minutes = float(match.group(5))
        if match := RE_EPOCH_DONE.search(line):
            state.epoch = int(match.group(1)) + 1
            state.step = 0
            state.epoch_minutes = 0.0
            state.epoch_f1.append((int(match.group(1)), float(match.group(2))))
            state.phase = "evaluating"
        if RE_BEST.search(line):
            state.phase = "final eval"
        if match := RE_TEST.search(line):
            state.test_lines.append(line.strip())
        if RE_ARTIFACT.search(line):
            state.finished = True
            state.phase = "done"
    return state


def render(state: State) -> str:
    fraction = state.fraction
    filled = int(BAR_WIDTH * fraction)
    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
    percent = f"{fraction * 100:5.1f}%"

    if state.phase == "downloading":
        detail = f"downloading shards {state.shards_done}/{state.shards_started}"
    elif state.phase == "parsing":
        detail = "parsing HTML -> nodes/xpaths " + (str(state.parsed) if state.parsed else "")
    elif state.phase == "training":
        detail = (
            f"epoch {state.epoch + 1}/{state.epochs}  "
            f"step {state.step}/{state.steps_per_epoch}  loss={state.loss:.4f}"
        )
        if (eta := state.eta_minutes) is not None:
            detail += f"  eta ~{eta:.0f}m"
    elif state.phase == "evaluating":
        last = f" last val F1={state.epoch_f1[-1][1]:.4f}" if state.epoch_f1 else ""
        detail = f"evaluating epoch {state.epoch}/{state.epochs}{last}"
    elif state.phase == "final eval":
        detail = "final eval on held-out test split"
    elif state.phase == "done":
        detail = "done"
    else:
        detail = state.phase

    return f"[{bar}] {percent}  {detail}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--once", action="store_true", help="print one snapshot and exit")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"log not found: {args.logfile}", file=sys.stderr)
        return 1

    while True:
        state = parse(args.logfile.read_text(errors="replace").splitlines())
        line = render(state)

        if args.once:
            print(line)
            for entry in state.test_lines:
                print(entry)
            return 0

        print("\r\033[K" + line, end="", flush=True)
        if state.finished:
            print()
            for entry in state.test_lines:
                print(entry)
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
