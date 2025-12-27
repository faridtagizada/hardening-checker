"""User accounts and password policy."""
import re
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        out.append(Result("USR-001", "Only root has UID 0", SKIP, "critical", "/etc/passwd is not readable"))
    else:
        extra = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                extra.append(parts[0])
        if extra:
            out.append(Result("USR-001", "Only root has UID 0", FAIL, "critical",
                              "Extra accounts with UID 0: " + ", ".join(extra),
                              "Delete these accounts or change their UID: sudo usermod -u <new> <name>"))
        else:
            out.append(Result("USR-001", "Only root has UID 0", PASS, "critical", "OK"))

    shadow = ctx.read("/etc/shadow")
    if shadow is None:
        out.append(Result("USR-002", "No accounts with empty passwords", SKIP, "critical",
                          "/etc/shadow is not readable (run as root)"))
    else:
        empty = [ln.split(":")[0] for ln in shadow.splitlines()
                 if len(ln.split(":")) > 1 and ln.split(":")[1] == ""]
        if empty:
            out.append(Result("USR-002", "No accounts with empty passwords", FAIL, "critical",
                              "Accounts with empty passwords: " + ", ".join(empty),
                              "sudo passwd -l <name>  (lock it) or set a password"))
        else:
            out.append(Result("USR-002", "No accounts with empty passwords", PASS, "critical", "OK"))

    defs = ctx.read("/etc/login.defs")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", defs or "", re.MULTILINE)
    if not m:
        out.append(Result("USR-003", "Maximum password age ≤ 90 days", SKIP, "medium",
                          "PASS_MAX_DAYS not found in /etc/login.defs"))
    else:
        days = int(m.group(1))
        if days <= 90:
            out.append(Result("USR-003", "Maximum password age ≤ 90 days", PASS, "medium", f"PASS_MAX_DAYS={days}"))
        else:
            out.append(Result("USR-003", "Maximum password age ≤ 90 days", WARN, "medium",
                              f"PASS_MAX_DAYS={days}", "/etc/login.defs: PASS_MAX_DAYS 90"))
    return out
