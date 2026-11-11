"""Kernel parameters, insecure services and the firewall."""
import glob
import os
import re
from typing import Dict, List, Optional

from .models import Context, Result, PASS, FAIL, WARN, SKIP

# (id, path under /proc/sys, accepted values, title, status on failure, severity, sysctl)
SYSCTLS = [
    ("SYS-001", "net/ipv4/ip_forward", ("0",), "IP forwarding is disabled", WARN, "medium", "net.ipv4.ip_forward=0"),
    # 2 = SYN cookies are sent unconditionally, which is "on" as well
    ("SYS-002", "net/ipv4/tcp_syncookies", ("1", "2"), "SYN cookies are enabled", FAIL, "medium",
     "net.ipv4.tcp_syncookies=1"),
    ("SYS-004", "net/ipv4/icmp_echo_ignore_broadcasts", ("1",), "Broadcast pings are ignored", FAIL, "low",
     "net.ipv4.icmp_echo_ignore_broadcasts=1"),
    ("SYS-005", "kernel/randomize_va_space", ("2",), "ASLR is fully enabled", FAIL, "high", "kernel.randomize_va_space=2"),
]

INSECURE_SERVICES = ["telnet.socket", "telnetd", "inetd", "xinetd", "rsh.socket",
                     "rlogin.socket", "vsftpd", "tftpd-hpa", "ypserv"]
FIREWALL_SERVICES = ["ufw", "firewalld", "nftables", "netfilter-persistent", "iptables"]


def _systemd_available(ctx: Context) -> bool:
    res = ctx.run(["systemctl", "is-system-running"])
    return res is not None and res[1].strip() not in ("", "offline")


def _is_active(ctx: Context, service: str) -> bool:
    res = ctx.run(["systemctl", "is-active", service])
    return res is not None and res[0] == 0


def _ufw_enabled(ctx: Context) -> Optional[bool]:
    """ufw.service is a oneshot unit that stays "active (exited)" even while the firewall is switched
    off (`ufw status: inactive`), so the service state alone proves nothing. Returns None if unknown."""
    text = ctx.read("/etc/ufw/ufw.conf")
    if text is None:
        return None
    m = re.search(r"^\s*ENABLED\s*=\s*(\w+)", text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).lower() == "yes" if m else None


def _redirect_settings(ctx: Context) -> Dict[str, str]:
    """accept_redirects for every interface plus the IPv6 defaults.

    With forwarding off, the kernel accepts a redirect on an interface when conf/all OR conf/<interface>
    is 1, so conf/all = 0 alone is not enough. The loopback interface is left out.
    """
    found: Dict[str, str] = {}
    for path in sorted(glob.glob(ctx.path("/proc/sys/net/ipv4/conf/*/accept_redirects"))):
        name = os.path.basename(os.path.dirname(path))
        if name == "lo":
            continue
        text = ctx.read("/proc/sys/net/ipv4/conf/" + name + "/accept_redirects")
        if text is not None:
            found[name] = text.strip()
    for name in ("all", "default"):
        text = ctx.read("/proc/sys/net/ipv6/conf/" + name + "/accept_redirects")
        if text is not None:
            found["ipv6." + name] = text.strip()
    return found


def _check_redirects(ctx: Context) -> Result:
    cid, title, sev = "SYS-003", "ICMP redirects are not accepted", "medium"
    found = _redirect_settings(ctx)
    if "all" not in found:
        return Result(cid, title, SKIP, sev, "Parameter is not readable")
    bad = [name for name, value in found.items() if value != "0"]
    if bad:
        return Result(cid, title, FAIL, sev,
                      "accept_redirects is not 0 for: " + ", ".join(bad),
                      "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0"
                      "  (also each interface listed; persistent: /etc/sysctl.d/99-hardening.conf)")
    return Result(cid, title, PASS, sev, f"accept_redirects=0 ({len(found)} entries checked)")


def run(ctx: Context) -> List[Result]:
    out: List[Result] = []

    for cid, rel, accepted, title, fail_status, sev, fix in SYSCTLS:
        text = ctx.read("/proc/sys/" + rel)
        if text is None:
            out.append(Result(cid, title, SKIP, sev, "Parameter is not readable"))
        elif text.strip() in accepted:
            out.append(Result(cid, title, PASS, sev, f"{rel.replace('/', '.')}={text.strip()}"))
        else:
            out.append(Result(cid, title, fail_status, sev,
                              f"{rel.replace('/', '.')}={text.strip()}, should be {accepted[0]}",
                              f"sudo sysctl -w {fix}  (persistent: /etc/sysctl.d/99-hardening.conf)"))
    out.append(_check_redirects(ctx))
    out.sort(key=lambda r: r.check_id)

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

    fw: List[str] = []
    note = ""
    for service in FIREWALL_SERVICES:
        if not _is_active(ctx, service):
            continue
        if service == "ufw" and _ufw_enabled(ctx) is False:
            note = "ufw.service is active, but ufw itself is switched off (ENABLED=no in /etc/ufw/ufw.conf)"
            continue
        fw.append(service)
    if fw:
        out.append(Result("FW-001", "Firewall is active", PASS, "high", "Active: " + ", ".join(fw)))
    else:
        out.append(Result("FW-001", "Firewall is active", WARN, "high",
                          note or "ufw/firewalld/nftables/iptables is not active",
                          "sudo ufw allow ssh && sudo ufw enable"))
    return out
