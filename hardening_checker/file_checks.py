"""Kritik faylların icazələrinin yoxlanması."""
import os
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, yol, icazə verilən maksimum rejim, uğursuzluq statusu, ciddilik)
FILES = [
    ("FILE-001", "/etc/passwd", 0o644, FAIL, "high"),
    ("FILE-002", "/etc/shadow", 0o640, FAIL, "critical"),
    ("FILE-003", "/etc/group", 0o644, FAIL, "medium"),
    ("FILE-004", "/etc/gshadow", 0o640, FAIL, "high"),
    ("FILE-005", "/etc/ssh/sshd_config", 0o600, WARN, "medium"),
]


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []
    for cid, path, max_mode, fail_status, sev in FILES:
        title = f"{path} icazələri ≤ {max_mode:o}"
        try:
            st = os.stat(ctx.path(path))
        except OSError:
            out.append(Result(cid, title, SKIP, sev, "Fayl tapılmadı"))
            continue
        mode = st.st_mode & 0o777
        problems = []
        if mode & ~max_mode:
            problems.append(f"rejim {mode:o}, olmalıdır ≤ {max_mode:o}")
        if ctx.is_real and st.st_uid != 0:
            problems.append(f"sahibi root deyil (uid={st.st_uid})")
        if problems:
            out.append(Result(cid, title, fail_status, sev, "; ".join(problems),
                              f"sudo chmod {max_mode:o} {path} && sudo chown root {path}"))
        else:
            out.append(Result(cid, title, PASS, sev, f"rejim {mode:o}"))
    return out
