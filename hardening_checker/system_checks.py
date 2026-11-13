"""Kernel parameters, insecure services and the firewall."""
import re
from typing import List

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, paths under /proc/sys, expected value, title, status on failure, severity, sysctl fix)
# Every path must have the expected value.
SYSCTLS = [
    ("SYS-001", ["net/ipv4/ip_forward"], "0", "IP forwarding is disabled", WARN, "medium",
     ["net.ipv4.ip_forward=0"]),
    ("SYS-002", ["net/ipv4/tcp_syncookies"], "1", "SYN cookies are enabled", FAIL, "medium",
     ["net.ipv4.tcp_syncookies=1"]),
    # "all" alone is not enough: on a host (no forwarding) redirects are accepted on an
    # interface if "all" OR the interface value is 1, and new interfaces start from "default"
    ("SYS-003", ["net/ipv4/conf/all/accept_redirects", "net/ipv4/conf/default/accept_redirects"], "0",
     "ICMP redirects are not accepted", FAIL, "medium",
     ["net.ipv4.conf.all.accept_redirects=0", "net.ipv4.conf.default.accept_redirects=0"]),
    ("SYS-004", ["net/ipv4/icmp_echo_ignore_broadcasts"], "1", "Broadcast pings are ignored", FAIL, "low",
     ["net.ipv4.icmp_echo_ignore_broadcasts=1"]),
    ("SYS-005", ["kernel/randomize_va_space"], "2", "ASLR is fully enabled", FAIL, "high",
     ["kernel.randomize_va_space=2"]),
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


def _ufw_enabled(ctx: Context) -> bool:
    # ufw.service is a oneshot unit: it is "active (exited)" on a fresh Ubuntu even
    # when the firewall is off ("ufw status" says inactive). ENABLED=yes in ufw.conf
    # is what "ufw enable" sets.
    text = ctx.read("/etc/ufw/ufw.conf")
    m = re.search(r'^\s*ENABLED\s*=\s*"?(\w+)"?', text or "", re.MULTILINE)
    return bool(m) and m.group(1).lower() == "yes"


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    for cid, rels, expected, title, fail_status, sev, fixes in SYSCTLS:
        values = {rel: ctx.read("/proc/sys/" + rel) for rel in rels}
        missing = [rel.replace("/", ".") for rel, text in values.items() if text is None]
        if missing:
            out.append(Result(cid, title, SKIP, sev, "Parameter is not readable: " + ", ".join(missing)))
            continue
        wrong = {rel: text.strip() for rel, text in values.items() if text.strip() != expected}
        if not wrong:
            out.append(Result(cid, title, PASS, sev, ", ".join(f"{rel.replace('/', '.')}={expected}" for rel in rels)))
        else:
            detail = ", ".join(f"{rel.replace('/', '.')}={value}" for rel, value in wrong.items())
            out.append(Result(cid, title, fail_status, sev, f"{detail}, should be {expected}",
                              f"sudo sysctl -w {' '.join(fixes)}  (persistent: /etc/sysctl.d/99-hardening.conf)"))

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

    fw = []
    ufw_off = False
    for service in FIREWALL_SERVICES:
        if not _is_active(ctx, service):
            continue
        if service == "ufw" and not _ufw_enabled(ctx):
            ufw_off = True
            continue
        fw.append(service)
    if fw:
        out.append(Result("FW-001", "Firewall is active", PASS, "high", "Active: " + ", ".join(fw)))
    else:
        detail = "ufw/firewalld/nftables is not active"
        if ufw_off:
            detail = "ufw.service is running, but ufw itself is disabled (ENABLED=no in /etc/ufw/ufw.conf)"
        out.append(Result("FW-001", "Firewall is active", WARN, "high", detail,
                          "sudo ufw allow ssh && sudo ufw enable"))
    return out
