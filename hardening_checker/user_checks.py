"""User accounts and password policy."""
import re
from typing import List, Optional

from .models import Context, Result, PASS, FAIL, WARN, SKIP


MAX_DAYS = 90


def _passwords_without_expiry(shadow: str) -> List[str]:
    """Accounts with a usable password that does not have to be changed within MAX_DAYS days.

    The 5th field of /etc/shadow is the account's own maximum age. login.defs only sets it for
    accounts created later, so the existing ones have to be checked here.
    """
    names = []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        name, password, max_days = parts[0], parts[1], parts[4]
        if not password or password[0] in "!*":
            continue        # an empty password is USR-002; a locked one ("!", "*") can't be used to log in
        try:
            days: Optional[int] = int(max_days)
        except ValueError:
            days = None     # empty field: the password never expires
        if days is None or days < 0 or days > MAX_DAYS:
            names.append(name)
    return names


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        out.append(Result("USR-001", "Only root has UID 0", SKIP, "critical", "/etc/passwd is not readable"))
    else:
        extra = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) <= 2 or parts[0] == "root":
                continue
            try:
                uid = int(parts[2])         # "00" and "000" are UID 0 for the system as well
            except ValueError:
                continue
            if uid == 0:
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
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(-?\d+)", defs or "", re.MULTILINE)
    if not m:
        out.append(Result("USR-003", "Maximum password age ≤ 90 days", SKIP, "medium",
                          "PASS_MAX_DAYS not found in /etc/login.defs"))
    else:
        days = int(m.group(1))
        if 0 <= days <= MAX_DAYS:
            out.append(Result("USR-003", "Maximum password age ≤ 90 days", PASS, "medium", f"PASS_MAX_DAYS={days}"))
        else:
            detail = f"PASS_MAX_DAYS={days}" + (" (passwords never expire)" if days < 0 else "")
            out.append(Result("USR-003", "Maximum password age ≤ 90 days", WARN, "medium", detail,
                              "/etc/login.defs: PASS_MAX_DAYS 90  (only for accounts created later; "
                              "existing ones: see USR-004)"))

    title = "Existing passwords expire within 90 days"
    if shadow is None:
        out.append(Result("USR-004", title, SKIP, "medium", "/etc/shadow is not readable (run as root)"))
    else:
        names = _passwords_without_expiry(shadow)
        if names:
            out.append(Result("USR-004", title, WARN, "medium",
                              "Maximum password age not set or above 90 days: " + ", ".join(names),
                              "sudo chage -M 90 <name>  (for each account listed)"))
        else:
            out.append(Result("USR-004", title, PASS, "medium", "OK"))
    return out
