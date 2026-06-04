"""Runs all the checks."""
from typing import List, Optional

from . import file_checks, ssh_checks, system_checks, user_checks
from .models import Context, Result

CHECKS = [ssh_checks.run, file_checks.run, user_checks.run, system_checks.run]


def run_all(ctx: Context, only: Optional[List[str]] = None) -> List[Result]:
    """only: list of ID prefixes (e.g. ['SSH', 'FILE']); None = everything."""
    results: List[Result] = []
    for fn in CHECKS:
        results.extend(fn(ctx))
    if only:
        results = [r for r in results if any(r.check_id.upper().startswith(p) for p in only)]
    return results
