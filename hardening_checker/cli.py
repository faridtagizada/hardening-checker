"""Command-line interface."""
import argparse
import os
import sys
from typing import Callable, List

from . import __version__
from .models import Context, FAIL, SEVERITIES, Result
from .report import print_report, save_html, save_json
from .runner import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardening_checker",
        description="Checks the security configuration of a Linux system (read-only, changes nothing).")
    p.add_argument("--root", default="/", help="Filesystem root (default: /; use another path for tests/demos)")
    p.add_argument("--only", help="Only run checks whose ID starts with one of these prefixes, e.g.: SSH,FILE")
    p.add_argument("--json", metavar="FILE", help="Write a JSON report")
    p.add_argument("--html", metavar="FILE", help="Write an HTML report")
    p.add_argument("--fail-on", choices=list(SEVERITIES),
                   help="Exit with code 2 if there is a FAIL at this severity or higher (for CI)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def _write_report(save: Callable[[List[Result], str], None], results: List[Result],
                  path: str, label: str) -> bool:
    """Writes one report file (creating its directory). Returns False instead of raising."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        save(results, path)
    except OSError as exc:
        print(f"Error: could not write the {label} report to {path}: {exc}", file=sys.stderr)
        return False
    print(f"[+] {label} written: {path}")
    return True


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        # the report uses "≤", "↳" and "✎": a terminal that cannot encode them must not crash the run
        try:
            stream.reconfigure(errors="replace")    # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    if not os.path.isdir(args.root):
        print(f"Error: directory not found: {args.root}", file=sys.stderr)
        return 1
    only = None
    if args.only is not None:
        only = [x.strip().upper() for x in args.only.split(",") if x.strip()]
        if not only:
            print("Error: --only needs at least one ID prefix, e.g. SSH,FILE", file=sys.stderr)
            return 1
    results = run_all(Context(args.root), only)
    if not results:
        print("Error: no checks were selected", file=sys.stderr)
        return 1

    print_report(results, color=sys.stdout.isatty() and not args.no_color)
    written = True
    if args.json:
        written = _write_report(save_json, results, args.json, "JSON") and written
    if args.html:
        written = _write_report(save_html, results, args.html, "HTML") and written
    if not written:
        return 1

    if args.fail_on:
        limit = SEVERITIES[args.fail_on]
        if any(r.status == FAIL and SEVERITIES[r.severity] >= limit for r in results):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
