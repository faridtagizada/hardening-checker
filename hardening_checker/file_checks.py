"""Permission checks for critical files."""
import os
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, path, maximum allowed mode, status on failure, severity, groups that may read the file)
FILES = [
    ("FILE-001", "/etc/passwd", 0o644, FAIL, "high", None),
    ("FILE-002", "/etc/shadow", 0o640, FAIL, "critical", ("root", "shadow")),
    ("FILE-003", "/etc/group", 0o644, FAIL, "medium", None),
    ("FILE-004", "/etc/gshadow", 0o640, FAIL, "high", ("root", "shadow")),
    ("FILE-005", "/etc/ssh/sshd_config", 0o600, WARN, "medium", None),
]


def _group_name(gid: int) -> str:
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []
    for cid, path, max_mode, fail_status, sev, groups in FILES:
        title = f"{path} permissions ≤ {max_mode:o}"
        try:
            st = os.stat(ctx.path(path))
        except OSError:
            out.append(Result(cid, title, SKIP, sev, "File not found"))
            continue
        mode = st.st_mode & 0o777
        problems = []
        fix = f"sudo chmod {max_mode:o} {path} && sudo chown root {path}"
        if mode & ~max_mode:
            problems.append(f"mode {mode:o}, should be ≤ {max_mode:o}")
        if ctx.is_real and st.st_uid != 0:
            problems.append(f"owner is not root (uid={st.st_uid})")
        # mode 640 is only as good as the group: any member of that group can read the password hashes
        if ctx.is_real and groups and mode & 0o040 and st.st_gid != 0 and _group_name(st.st_gid) not in groups:
            problems.append(f"readable by group '{_group_name(st.st_gid)}', expected root or shadow")
            fix += f" && sudo chgrp shadow {path}"
        if problems:
            out.append(Result(cid, title, fail_status, sev, "; ".join(problems), fix))
        else:
            out.append(Result(cid, title, PASS, sev, f"mode {mode:o}"))
    return out
