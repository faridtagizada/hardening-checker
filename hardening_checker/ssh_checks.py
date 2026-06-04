"""Checks of the SSH server configuration (/etc/ssh/sshd_config)."""
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
            return                      # everything after a Match block is conditional
        if key == "include":
            for pattern in value.split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join("/etc/ssh", pattern)
                for fpath in sorted(glob.glob(ctx.path(pattern))):
                    rel = "/" + os.path.relpath(fpath, ctx.root)
                    _parse_file(ctx, rel, cfg, depth + 1)
            continue
        cfg.setdefault(key, value)      # in sshd the first value that is set wins


def parse_sshd_config(ctx: Context, path: str = "/etc/ssh/sshd_config") -> Dict[str, str]:
    cfg: Dict[str, str] = {}
    _parse_file(ctx, path, cfg)
    return cfg


def run(ctx: Context) -> List[Result]:
    if ctx.read("/etc/ssh/sshd_config") is None:
        return [Result("SSH-000", "SSH configuration file", SKIP, "low",
                       "/etc/ssh/sshd_config not found or not readable")]
    cfg = parse_sshd_config(ctx)
    out: List[Result] = []

    v = cfg.get("permitrootlogin", "").lower()
    if v == "no":
        st, d = PASS, "PermitRootLogin no"
    elif v == "yes":
        st, d = FAIL, "root can log in directly over SSH"
    else:
        st, d = WARN, f"PermitRootLogin={v or 'not set (default: prohibit-password)'}; 'no' is recommended"
    out.append(Result("SSH-001", "Root SSH login is disabled", st, "high", d, "PermitRootLogin no"))

    v = cfg.get("passwordauthentication", "").lower()
    if v == "no":
        st, d = PASS, "Password login is disabled (key-based login)"
    else:
        st, d = FAIL, "Password login is enabled" + ("" if v else " (default: yes)")
    out.append(Result("SSH-002", "SSH password authentication is disabled", st, "high", d,
                      "PasswordAuthentication no (set up an SSH key first!)"))

    v = cfg.get("permitemptypasswords", "").lower()
    st = FAIL if v == "yes" else PASS
    out.append(Result("SSH-003", "Empty passwords are not allowed", st, "critical",
                      "Accounts with empty passwords can log in" if st == FAIL else "OK",
                      "PermitEmptyPasswords no"))

    v = cfg.get("x11forwarding", "").lower()
    st = WARN if v == "yes" else PASS
    out.append(Result("SSH-004", "X11 forwarding is disabled", st, "low",
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
