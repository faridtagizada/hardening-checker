"""İstifadəçi hesabları və parol siyasəti."""
import re
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        out.append(Result("USR-001", "Yalnız root-un UID-si 0-dır", SKIP, "critical", "/etc/passwd oxunmur"))
    else:
        extra = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                extra.append(parts[0])
        if extra:
            out.append(Result("USR-001", "Yalnız root-un UID-si 0-dır", FAIL, "critical",
                              "UID 0 olan əlavə hesablar: " + ", ".join(extra),
                              "Bu hesabları sil və ya UID-ni dəyiş: sudo usermod -u <yeni> <ad>"))
        else:
            out.append(Result("USR-001", "Yalnız root-un UID-si 0-dır", PASS, "critical", "OK"))

    shadow = ctx.read("/etc/shadow")
    if shadow is None:
        out.append(Result("USR-002", "Boş parollu hesab yoxdur", SKIP, "critical",
                          "/etc/shadow oxunmur (root ilə işlət)"))
    else:
        empty = [ln.split(":")[0] for ln in shadow.splitlines()
                 if len(ln.split(":")) > 1 and ln.split(":")[1] == ""]
        if empty:
            out.append(Result("USR-002", "Boş parollu hesab yoxdur", FAIL, "critical",
                              "Boş parollu hesablar: " + ", ".join(empty),
                              "sudo passwd -l <ad>  (kilidlə) və ya parol təyin et"))
        else:
            out.append(Result("USR-002", "Boş parollu hesab yoxdur", PASS, "critical", "OK"))

    defs = ctx.read("/etc/login.defs")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", defs or "", re.MULTILINE)
    if not m:
        out.append(Result("USR-003", "Parolun maksimum ömrü ≤ 90 gün", SKIP, "medium",
                          "PASS_MAX_DAYS /etc/login.defs-də tapılmadı"))
    else:
        days = int(m.group(1))
        if days <= 90:
            out.append(Result("USR-003", "Parolun maksimum ömrü ≤ 90 gün", PASS, "medium", f"PASS_MAX_DAYS={days}"))
        else:
            out.append(Result("USR-003", "Parolun maksimum ömrü ≤ 90 gün", WARN, "medium",
                              f"PASS_MAX_DAYS={days}", "/etc/login.defs: PASS_MAX_DAYS 90"))
    return out
