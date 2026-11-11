"""Checks of the SSH server configuration (/etc/ssh/sshd_config)."""
import glob
import os
import re
from typing import Dict, List, Tuple

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# sshd accepts "Key value", "Key=value" and "Key = value"
LINE_RE = re.compile(r"^([^\s=]+)(?:\s*=\s*|\s+)(.*)$")
TOKEN_RE = re.compile(r'"[^"]*"|\S+')


class SshdConfig:
    """What the parser found: global values, Match-block settings and files it could not read."""

    def __init__(self) -> None:
        self.values: Dict[str, str] = {}                 # global section; the first value wins
        self.match: List[Tuple[str, str, str]] = []      # (criteria, key, value) inside Match blocks
        self.unreadable: List[str] = []                  # included files that exist but can't be read


def _clean_value(value: str) -> str:
    """Drops a trailing "# comment" and surrounding double quotes, like sshd does."""
    out: List[str] = []
    for token in TOKEN_RE.findall(value):
        if token.startswith("#"):
            break
        if len(token) >= 2 and token[0] == token[-1] == '"':
            token = token[1:-1]
        out.append(token)
    return " ".join(out)


def _parse_file(ctx: Context, path: str, conf: SshdConfig, depth: int = 0) -> None:
    text = ctx.read(path)
    if text is None:
        if depth > 0:
            conf.unreadable.append(path)    # e.g. a mode-600 drop-in when not running as root
        return
    if depth > 5:
        return
    criteria = None                         # set once this file has entered a Match block
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1).lower(), _clean_value(m.group(2))
        if key == "match":
            criteria = value
            continue
        if criteria is not None:
            # Conditional: it doesn't change the global value, but it can override it for some connections
            if key != "include":
                conf.match.append((criteria, key, value))
            continue
        if key == "include":
            for pattern in value.split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join("/etc/ssh", pattern)
                for fpath in sorted(glob.glob(ctx.path(pattern))):
                    rel = "/" + os.path.relpath(fpath, ctx.root)
                    _parse_file(ctx, rel, conf, depth + 1)
            continue
        conf.values.setdefault(key, value)  # in sshd the first value that is set wins


def parse_sshd(ctx: Context, path: str = "/etc/ssh/sshd_config") -> SshdConfig:
    conf = SshdConfig()
    _parse_file(ctx, path, conf)
    return conf


def parse_sshd_config(ctx: Context, path: str = "/etc/ssh/sshd_config") -> Dict[str, str]:
    """The global (unconditional) settings only."""
    return parse_sshd(ctx, path).values


def _match_override(conf: SshdConfig, key: str, weak: Tuple[str, ...],
                    status: str, detail: str) -> Tuple[str, str]:
    """A PASS on the global value is not the whole story if a Match block sets a weak value."""
    hits = [(crit, val) for crit, k, val in conf.match if k == key and val.lower() in weak]
    if status != PASS or not hits:
        return status, detail
    where = "; ".join(f"Match {crit}: {val}" for crit, val in hits)
    if any(crit.strip().lower() == "all" for crit, _ in hits):
        return FAIL, f"A 'Match all' block overrides the global value ({where})"
    return WARN, f"Fine globally, but a Match block overrides it for some connections ({where})"


def run(ctx: Context) -> List[Result]:
    if ctx.read("/etc/ssh/sshd_config") is None:
        return [Result("SSH-000", "SSH configuration file", SKIP, "low",
                       "/etc/ssh/sshd_config not found or not readable")]
    conf = parse_sshd(ctx)
    cfg = conf.values
    out: List[Result] = []

    v = cfg.get("permitrootlogin", "").lower()
    if v == "no":
        st, d = PASS, "PermitRootLogin no"
    elif v == "yes":
        st, d = FAIL, "root can log in directly over SSH"
    else:
        st, d = WARN, f"PermitRootLogin={v or 'not set (default: prohibit-password)'}; 'no' is recommended"
    st, d = _match_override(conf, "permitrootlogin", ("yes",), st, d)
    out.append(Result("SSH-001", "Root SSH login is disabled", st, "high", d, "PermitRootLogin no"))

    v = cfg.get("passwordauthentication", "").lower()
    kbd = (cfg.get("kbdinteractiveauthentication") or cfg.get("challengeresponseauthentication") or "").lower()
    fix = "PasswordAuthentication no (set up an SSH key first!)"
    if v == "no" and kbd == "yes":
        st, d = WARN, "PasswordAuthentication no, but KbdInteractiveAuthentication yes: with PAM, passwords may still be accepted"
        fix = "KbdInteractiveAuthentication no (unless you need it, e.g. for 2FA)"
    elif v == "no":
        st, d = PASS, "Password login is disabled (key-based login)"
    else:
        st, d = FAIL, "Password login is enabled" + ("" if v else " (default: yes)")
    st, d = _match_override(conf, "passwordauthentication", ("yes",), st, d)
    out.append(Result("SSH-002", "SSH password authentication is disabled", st, "high", d, fix))

    v = cfg.get("permitemptypasswords", "").lower()
    st = FAIL if v == "yes" else PASS
    d = "Accounts with empty passwords can log in" if st == FAIL else "OK"
    st, d = _match_override(conf, "permitemptypasswords", ("yes",), st, d)
    out.append(Result("SSH-003", "Empty passwords are not allowed", st, "critical", d,
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

    if conf.unreadable:
        # A drop-in that is read before the main file's own settings can override them. If it can't be
        # read (typically mode 600 without root), a PASS would be a guess.
        names = ", ".join(conf.unreadable)
        for r in out:
            if r.status == PASS:
                r.status = WARN
                r.detail = f"Not verified: could not read {names} (run as root), and it may override this setting"
                r.remediation = "Run the check again as root: sudo python3 -m hardening_checker"
    return out
