"""Kernel parameters, insecure services and the firewall."""
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, path under /proc/sys, expected value, title, status on failure, severity, sysctl)
SYSCTLS = [
    ("SYS-001", "net/ipv4/ip_forward", "0", "IP forwarding is disabled", WARN, "medium", "net.ipv4.ip_forward=0"),
    ("SYS-002", "net/ipv4/tcp_syncookies", "1", "SYN cookies are enabled", FAIL, "medium", "net.ipv4.tcp_syncookies=1"),
    ("SYS-003", "net/ipv4/conf/all/accept_redirects", "0", "ICMP redirects are not accepted", FAIL, "medium",
     "net.ipv4.conf.all.accept_redirects=0"),
    ("SYS-004", "net/ipv4/icmp_echo_ignore_broadcasts", "1", "Broadcast pings are ignored", FAIL, "low",
     "net.ipv4.icmp_echo_ignore_broadcasts=1"),
    ("SYS-005", "kernel/randomize_va_space", "2", "ASLR is fully enabled", FAIL, "high", "kernel.randomize_va_space=2"),
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
            out.append(Result(cid, title, SKIP, sev, "Parameter is not readable"))
        elif text.strip() == expected:
            out.append(Result(cid, title, PASS, sev, f"{rel.replace('/', '.')}={expected}"))
        else:
            out.append(Result(cid, title, fail_status, sev,
                              f"{rel.replace('/', '.')}={text.strip()}, should be {expected}",
                              f"sudo sysctl -w {fix}  (persistent: /etc/sysctl.d/99-hardening.conf)"))

    if not _systemd_available(ctx):
        out.append(Result("SVC-001", "Insecure services are not running", SKIP, "high", "systemd is not available"))
        out.append(Result("FW-001", "Firewall is active", SKIP, "high", "systemd is not available"))
        return out

    active = [s for s in INSECURE_SERVICES if _is_active(ctx, s)]
    if active:
        out.append(Result("SVC-001", "Insecure services are not running", FAIL, "high",
                          "Active: " + ", ".join(active),
                          "sudo systemctl disable --now " + " ".join(active)))
    else:
        out.append(Result("SVC-001", "Insecure services are not running", PASS, "high",
                          "telnet, rsh, vsftpd etc. are not active"))

    fw = [s for s in FIREWALL_SERVICES if _is_active(ctx, s)]
    if fw:
        out.append(Result("FW-001", "Firewall is active", PASS, "high", "Active: " + ", ".join(fw)))
    else:
        out.append(Result("FW-001", "Firewall is active", WARN, "high",
                          "ufw/firewalld/nftables is not active",
                          "sudo ufw allow ssh && sudo ufw enable"))
    return out
