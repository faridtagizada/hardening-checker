"""Komanda sətri interfeysi."""
import argparse
import os
import sys

from . import __version__
from .models import Context, FAIL, SEVERITIES
from .report import print_report, save_html, save_json
from .runner import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardening_checker",
        description="Linux sisteminin təhlükəsizlik konfiqurasiyasını yoxlayır (yalnız oxuyur, heç nəyi dəyişmir).")
    p.add_argument("--root", default="/", help="Fayl sisteminin kökü (default: /; test/demo üçün başqa yol)")
    p.add_argument("--only", help="Yalnız bu ID prefikslərini yoxla, məs.: SSH,FILE")
    p.add_argument("--json", metavar="FAYL", help="JSON hesabatı yaz")
    p.add_argument("--html", metavar="FAYL", help="HTML hesabatı yaz")
    p.add_argument("--fail-on", choices=list(SEVERITIES),
                   help="Bu və ya daha yüksək ciddilikdə FAIL varsa çıxış kodu 2 olsun (CI üçün)")
    p.add_argument("--no-color", action="store_true", help="Rəngsiz çıxış")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"Xəta: qovluq tapılmadı: {args.root}", file=sys.stderr)
        return 1
    only = [x.strip().upper() for x in args.only.split(",")] if args.only else None
    results = run_all(Context(args.root), only)
    if not results:
        print("Xəta: heç bir yoxlama seçilmədi", file=sys.stderr)
        return 1

    print_report(results, color=sys.stdout.isatty() and not args.no_color)
    if args.json:
        save_json(results, args.json)
        print(f"[+] JSON yazıldı: {args.json}")
    if args.html:
        save_html(results, args.html)
        print(f"[+] HTML yazıldı: {args.html}")

    if args.fail_on:
        limit = SEVERITIES[args.fail_on]
        if any(r.status == FAIL and SEVERITIES[r.severity] >= limit for r in results):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
