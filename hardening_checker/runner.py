"""Runs all the checks."""
from typing import List, Optional

from . import file_checks, ssh_checks, system_checks, user_checks
from .models import Context, Result

# (ID prefixes the module produces, function)
CHECKS = [
    (("SSH",), ssh_checks.run),
    (("FILE",), file_checks.run),
    (("USR",), user_checks.run),
    (("SYS", "SVC", "FW"), system_checks.run),
]


def run_all(ctx: Context, only: Optional[List[str]] = None) -> List[Result]:
    """only: list of ID prefixes (e.g. ['SSH', 'FILE']); None or empty = everything."""
    prefixes = [p.strip().upper() for p in (only or []) if p and p.strip()]
    results: List[Result] = []
    for ids, fn in CHECKS:
        # don't run a module when none of its IDs can match the filter
        if prefixes and not any(i.startswith(p) or p.startswith(i) for i in ids for p in prefixes):
            continue
        results.extend(fn(ctx))
    if prefixes:
        results = [r for r in results if any(r.check_id.upper().startswith(p) for p in prefixes)]
    return results
