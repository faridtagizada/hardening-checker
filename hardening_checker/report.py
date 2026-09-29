"""Hesabat: terminal, JSON, HTML."""
import html
import json
from collections import Counter
from datetime import datetime
from typing import List

from .models import Result, compute_score, PASS, FAIL, WARN, SKIP

COLORS = {PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m", SKIP: "\033[90m"}
RESET = "\033[0m"


def summary(results: List[Result]) -> dict:
    c = Counter(r.status for r in results)
    return {"pass": c[PASS], "fail": c[FAIL], "warn": c[WARN], "skip": c[SKIP],
            "total": len(results), "score": compute_score(results)}


def print_report(results: List[Result], color: bool = True) -> None:
    def paint(status: str) -> str:
        tag = f"[{status}]"
        return f"{COLORS[status]}{tag}{RESET}" if color else tag

    for r in results:
        print(f"{paint(r.status)} {r.check_id:<9}{r.title}")
        if r.status in (FAIL, WARN, SKIP) and r.detail:
            print(f"           ↳ {r.detail}")
        if r.status in (FAIL, WARN) and r.remediation:
            print(f"           ✎ Düzəliş: {r.remediation}")
    s = summary(results)
    print(f"\nNəticə: {s['pass']} PASS, {s['fail']} FAIL, {s['warn']} WARN, {s['skip']} SKIP")
    print(f"Hardening xalı: {s['score']}/100")


def save_json(results: List[Result], path: str) -> None:
    data = {"generated": datetime.now().isoformat(timespec="seconds"),
            "summary": summary(results), "results": [r.to_dict() for r in results]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_html(results: List[Result], path: str) -> None:
    s = summary(results)
    rows = []
    for r in results:
        rows.append(
            f"<tr class='{r.status.lower()}'><td>{html.escape(r.check_id)}</td>"
            f"<td>{r.status}</td><td>{html.escape(r.severity)}</td>"
            f"<td>{html.escape(r.title)}</td><td>{html.escape(r.detail)}</td>"
            f"<td><code>{html.escape(r.remediation)}</code></td></tr>")
    doc = f"""<!DOCTYPE html>
<html lang="az"><head><meta charset="utf-8"><title>Hardening Hesabatı</title>
<style>
body{{font-family:sans-serif;margin:2rem;color:#222}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#f0f0f0}}
tr.pass td:nth-child(2){{color:#1a7f37;font-weight:bold}}
tr.fail td:nth-child(2){{color:#cf222e;font-weight:bold}}
tr.warn td:nth-child(2){{color:#9a6700;font-weight:bold}}
tr.skip td:nth-child(2){{color:#888}}
.score{{font-size:2rem;font-weight:bold}}
</style></head><body>
<h1>Linux Hardening Hesabatı</h1>
<p>Tarix: {datetime.now():%Y-%m-%d %H:%M} &nbsp;|&nbsp;
PASS {s['pass']} · FAIL {s['fail']} · WARN {s['warn']} · SKIP {s['skip']}</p>
<p class="score">Xal: {s['score']}/100</p>
<table><tr><th>ID</th><th>Status</th><th>Ciddilik</th><th>Yoxlama</th><th>Detal</th><th>Düzəliş</th></tr>
{''.join(rows)}
</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
