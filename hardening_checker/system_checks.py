"""Kernel parametrləri, təhlükəli servislər və firewall."""
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, /proc/sys altındakı yol, gözlənilən dəyər, başlıq, uğursuzluq statusu, ciddilik, sysctl)
SYSCTLS = [
    ("SYS-001", "net/ipv4/ip_forward", "0", "IP forwarding söndürülüb", WARN, "medium", "net.ipv4.ip_forward=0"),
    ("SYS-002", "net/ipv4/tcp_syncookies", "1", "SYN cookies aktivdir", FAIL, "medium", "net.ipv4.tcp_syncookies=1"),
    ("SYS-003", "net/ipv4/conf/all/accept_redirects", "0", "ICMP redirect qəbul edilmir", FAIL, "medium",
     "net.ipv4.conf.all.accept_redirects=0"),
    ("SYS-004", "net/ipv4/icmp_echo_ignore_broadcasts", "1", "Broadcast ping-lərə cavab verilmir", FAIL, "low",
     "net.ipv4.icmp_echo_ignore_broadcasts=1"),
    ("SYS-005", "kernel/randomize_va_space", "2", "ASLR tam aktivdir", FAIL, "high", "kernel.randomize_va_space=2"),
]

INSECURE_SERVICES = ["telnet.socket", "telnetd", "inetd", "xinetd", "rsh.socket",
                     "rlogin.socket", "vsftpd", "tftpd-hpa", "ypserv"]
FIREWALL_SERVICES = ["ufw", "firewalld", "nftables"]


def _systemd_available(ctx: Context) -> bool:
    res = ctx.run(["systemctl", "is-system-running"])
    return res is not None and res[1].strip() not in ("", "offline")


def _is_active(ctx: Context, service: str) -> bool:
    res = ctx.run(["systemctl", "is-active", service])
    return res is not None and res[0] == 0


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    for cid, rel, expected, title, fail_status, sev, fix in SYSCTLS:
        text = ctx.read("/proc/sys/" + rel)
        if text is None:
            out.append(Result(cid, title, SKIP, sev, "Parametr oxunmur"))
        elif text.strip() == expected:
            out.append(Result(cid, title, PASS, sev, f"{rel.replace('/', '.')}={expected}"))
        else:
            out.append(Result(cid, title, fail_status, sev,
                              f"{rel.replace('/', '.')}={text.strip()}, olmalıdır {expected}",
                              f"sudo sysctl -w {fix}  (daimi: /etc/sysctl.d/99-hardening.conf)"))

    if not _systemd_available(ctx):
        out.append(Result("SVC-001", "Təhlükəli servislər işləmir", SKIP, "high", "systemd mövcud deyil"))
        out.append(Result("FW-001", "Firewall aktivdir", SKIP, "high", "systemd mövcud deyil"))
        return out

    active = [s for s in INSECURE_SERVICES if _is_active(ctx, s)]
    if active:
        out.append(Result("SVC-001", "Təhlükəli servislər işləmir", FAIL, "high",
                          "Aktiv: " + ", ".join(active),
                          "sudo systemctl disable --now " + " ".join(active)))
    else:
        out.append(Result("SVC-001", "Təhlükəli servislər işləmir", PASS, "high",
                          "telnet, rsh, vsftpd və s. aktiv deyil"))

    fw = [s for s in FIREWALL_SERVICES if _is_active(ctx, s)]
    if fw:
        out.append(Result("FW-001", "Firewall aktivdir", PASS, "high", "Aktiv: " + ", ".join(fw)))
    else:
        out.append(Result("FW-001", "Firewall aktivdir", WARN, "high",
                          "ufw/firewalld/nftables aktiv deyil",
                          "sudo ufw allow ssh && sudo ufw enable"))
    return out
