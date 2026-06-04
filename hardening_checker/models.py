"""Shared data models and the context the checks run in."""
import os
import subprocess
from dataclasses import dataclass, asdict
from typing import Callable, List, Optional, Tuple

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Result:
    check_id: str
    title: str
    status: str
    severity: str
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def default_runner(cmd: List[str]) -> Optional[Tuple[int, str]]:
    """Runs a command. Returns None if the command isn't found or errors out."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.returncode, p.stdout.strip()


class Context:
    """The environment the checks run in.

    root: filesystem root ("/" is the real system, any other path is for tests/demos)
    runner: function that runs external commands (replaced in tests)
    """

    def __init__(self, root: str = "/", runner: Optional[Callable] = None):
        self.root = root
        self.is_real = os.path.abspath(root) == "/"
        if runner is None:
            runner = default_runner if self.is_real else (lambda cmd: None)
        self.runner = runner

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def read(self, p: str) -> Optional[str]:
        try:
            with open(self.path(p), "r", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def run(self, cmd: List[str]) -> Optional[Tuple[int, str]]:
        return self.runner(cmd)


def compute_score(results: List[Result]) -> int:
    """Weighted score: PASS counts fully, WARN counts half, FAIL counts zero; SKIP is ignored."""
    total = earned = 0.0
    for r in results:
        if r.status == SKIP:
            continue
        w = SEVERITIES[r.severity]
        total += w
        if r.status == PASS:
            earned += w
        elif r.status == WARN:
            earned += w / 2
    return round(100 * earned / total) if total else 0
