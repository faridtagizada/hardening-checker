"""Permission checks for critical files."""
import os
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, path, maximum allowed mode, status on failure, severity)
FILES = [
    ("FILE-001", "/etc/passwd", 0o644, FAIL, "high"),
    ("FILE-002", "/etc/shadow", 0o640, FAIL, "critical"),
    ("FILE-003", "/etc/group", 0o644, FAIL, "medium"),
    ("FILE-004", "/etc/gshadow", 0o640, FAIL, "high"),
    ("FILE-005", "/etc/ssh/sshd_config", 0o600, WARN, "medium"),
]


def _describe_bits(bits: int) -> str:
    """0o004 -> 'others read', 0o022 -> 'group write, others write'"""
    parts = []
    for shift, who in ((6, "owner"), (3, "group"), (0, "others")):
        rights = [name for bit, name in ((4, "read"), (2, "write"), (1, "execute")) if (bits >> shift) & bit]
        if rights:
            parts.append(f"{who} {'+'.join(rights)}")
    return ", ".join(parts)


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []
    for cid, path, max_mode, fail_status, sev in FILES:
        # The check is bitwise, not "smaller number": 604 is below 640 but lets
        # everyone read the file. So the text names the extra permission bits.
        title = f"{path} permissions within {max_mode:03o}"
        try:
            st = os.stat(ctx.path(path))
        except OSError:
            out.append(Result(cid, title, SKIP, sev, "File not found"))
            continue
        mode = st.st_mode & 0o777
        problems = []
        extra = mode & ~max_mode
        if extra:
            problems.append(f"mode {mode:03o} has permission bits that {max_mode:03o} doesn't allow "
                            f"({_describe_bits(extra)})")
        if ctx.is_real and st.st_uid != 0:
            problems.append(f"owner is not root (uid={st.st_uid})")
        if problems:
            out.append(Result(cid, title, fail_status, sev, "; ".join(problems),
                              f"sudo chmod {max_mode:o} {path} && sudo chown root {path}"))
        else:
            out.append(Result(cid, title, PASS, sev, f"mode {mode:o}"))
    return out
