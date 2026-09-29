"""SSH server konfiqurasiyasının yoxlanması (/etc/ssh/sshd_config)."""
import glob
import os
import re
from typing import Dict, List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

LINE_RE = re.compile(r"^(\S+?)(?:\s+|\s*=\s*)(.*)$")


def _parse_file(ctx: Context, path: str, cfg: Dict[str, str], depth: int = 0) -> None:
    text = ctx.read(path)
    if text is None or depth > 5:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        if key == "match":
            return                      # Match blokundan sonrakılar şərtlidir
        if key == "include":
            for pattern in value.split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join("/etc/ssh", pattern)
                for fpath in sorted(glob.glob(ctx.path(pattern))):
                    rel = "/" + os.path.relpath(fpath, ctx.root)
                    _parse_file(ctx, rel, cfg, depth + 1)
            continue
        cfg.setdefault(key, value)      # sshd-də ilk təyin olunan dəyər qüvvədədir


def parse_sshd_config(ctx: Context, path: str = "/etc/ssh/sshd_config") -> Dict[str, str]:
    cfg: Dict[str, str] = {}
    _parse_file(ctx, path, cfg)
    return cfg


def run(ctx: Context) -> List[Result]:
    if ctx.read("/etc/ssh/sshd_config") is None:
        return [Result("SSH-000", "SSH konfiqurasiya faylı", SKIP, "low",
                       "/etc/ssh/sshd_config tapılmadı və ya oxuna bilmir")]
    cfg = parse_sshd_config(ctx)
    out: List[Result] = []

    v = cfg.get("permitrootlogin", "").lower()
    if v == "no":
        st, d = PASS, "PermitRootLogin no"
    elif v == "yes":
        st, d = FAIL, "root birbaşa SSH ilə daxil ola bilər"
    else:
        st, d = WARN, f"PermitRootLogin={v or 'təyin olunmayıb (default: prohibit-password)'}; 'no' tövsiyə olunur"
    out.append(Result("SSH-001", "Root SSH girişi qadağandır", st, "high", d, "PermitRootLogin no"))

    v = cfg.get("passwordauthentication", "").lower()
    if v == "no":
        st, d = PASS, "Parol ilə giriş söndürülüb (açar ilə giriş)"
    else:
        st, d = FAIL, "Parol ilə giriş açıqdır" + ("" if v else " (default: yes)")
    out.append(Result("SSH-002", "SSH parol autentifikasiyası söndürülüb", st, "high", d,
                      "PasswordAuthentication no (əvvəl SSH açarı qur!)"))

    v = cfg.get("permitemptypasswords", "").lower()
    st = FAIL if v == "yes" else PASS
    out.append(Result("SSH-003", "Boş parola icazə verilmir", st, "critical",
                      "Boş parollu hesablar daxil ola bilər" if st == FAIL else "OK",
                      "PermitEmptyPasswords no"))

    v = cfg.get("x11forwarding", "").lower()
    st = WARN if v == "yes" else PASS
    out.append(Result("SSH-004", "X11 forwarding söndürülüb", st, "low",
                      "X11Forwarding yes" if st == WARN else "OK", "X11Forwarding no"))

    raw = cfg.get("maxauthtries", "")
    try:
        n = int(raw) if raw else 6
    except ValueError:
        n = 6
    st = PASS if n <= 4 else WARN
    out.append(Result("SSH-005", "MaxAuthTries ≤ 4", st, "medium",
                      f"MaxAuthTries={n}" + ("" if raw else " (default)"), "MaxAuthTries 3"))
    return out
