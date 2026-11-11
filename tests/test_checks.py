import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from make_demo_root import make_root                                  # noqa: E402
from hardening_checker.cli import main                                 # noqa: E402
from hardening_checker.models import Context, Result, compute_score   # noqa: E402
from hardening_checker.runner import run_all                          # noqa: E402
from hardening_checker.ssh_checks import parse_sshd_config            # noqa: E402


def fake_runner(active=()):
    def run(cmd):
        if cmd[:2] == ["systemctl", "is-system-running"]:
            return 0, "running"
        if cmd[:2] == ["systemctl", "is-active"]:
            return (0, "active") if cmd[2] in active else (3, "inactive")
        return None
    return run


@pytest.fixture
def insecure(tmp_path):
    return make_root(str(tmp_path / "bad"), secure=False)


@pytest.fixture
def secure(tmp_path):
    return make_root(str(tmp_path / "good"), secure=True)


def by_id(results):
    return {r.check_id: r for r in results}


def ssh_root(path, main_conf, dropins=None):
    """A fake root that only has an SSH configuration."""
    p = path / "etc" / "ssh"
    (p / "sshd_config.d").mkdir(parents=True)
    (p / "sshd_config").write_text(main_conf)
    for name, text in (dropins or {}).items():
        (p / "sshd_config.d" / name).write_text(text)
    return str(path)


def ssh_results(ctx):
    return by_id(run_all(ctx, only=["SSH"]))


def test_ssh_first_value_wins_and_include(insecure):
    cfg = parse_sshd_config(Context(insecure))
    assert cfg["passwordauthentication"] == "yes"    # the drop-in comes before the main file's own setting
    assert cfg["permitrootlogin"] == "yes"


def test_ssh_match_block_ignored(tmp_path):
    p = tmp_path / "etc" / "ssh"
    p.mkdir(parents=True)
    (p / "sshd_config").write_text("PermitRootLogin no\nMatch User bob\nPermitRootLogin yes\n")
    assert parse_sshd_config(Context(str(tmp_path)))["permitrootlogin"] == "no"


def test_ssh_equals_sign_comment_and_quotes(tmp_path):
    root = ssh_root(tmp_path, 'PermitEmptyPasswords = yes\nPermitRootLogin = yes\n'
                              'PasswordAuthentication=no # keys only\nX11Forwarding "no"\n')
    cfg = parse_sshd_config(Context(root))
    assert cfg["permitemptypasswords"] == "yes"
    assert cfg["passwordauthentication"] == "no"
    assert cfg["x11forwarding"] == "no"
    r = ssh_results(Context(root))
    assert r["SSH-001"].status == "FAIL"
    assert r["SSH-002"].status == "PASS"
    assert r["SSH-003"].status == "FAIL"


def test_ssh_match_block_can_override(tmp_path):
    base = "PermitRootLogin no\nPasswordAuthentication no\n"
    r = ssh_results(Context(ssh_root(tmp_path / "a", base + "Match User bob\n  PasswordAuthentication yes\n")))
    assert r["SSH-001"].status == "PASS"
    assert r["SSH-002"].status == "WARN" and "Match User bob" in r["SSH-002"].detail
    r = ssh_results(Context(ssh_root(tmp_path / "b", base + "Match all\n  PermitRootLogin yes\n")))
    assert r["SSH-001"].status == "FAIL"


def test_ssh_unreadable_include_is_not_a_pass(tmp_path):
    root = ssh_root(tmp_path,
                    "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin no\n",
                    {"50-cloud-init.conf": "PasswordAuthentication yes\n"})

    class NoRoot(Context):      # what a normal user sees: the mode-600 drop-in can't be opened
        def read(self, p):
            return None if p.endswith("50-cloud-init.conf") else super().read(p)

    r = ssh_results(NoRoot(root))
    assert r["SSH-002"].status == "WARN" and "50-cloud-init.conf" in r["SSH-002"].detail
    assert ssh_results(Context(root))["SSH-002"].status == "FAIL"    # root sees the real value


def test_ssh_keyboard_interactive_keeps_passwords_possible(tmp_path):
    root = ssh_root(tmp_path, "PasswordAuthentication no\nKbdInteractiveAuthentication yes\n")
    assert ssh_results(Context(root))["SSH-002"].status == "WARN"


def test_insecure_findings(insecure):
    r = by_id(run_all(Context(insecure, fake_runner(active={"telnetd"}))))
    for cid in ["SSH-001", "SSH-002", "SSH-003", "FILE-001", "FILE-002", "FILE-004",
                "USR-001", "USR-002", "SYS-002", "SYS-003", "SYS-005", "SVC-001"]:
        assert r[cid].status == "FAIL", cid
    for cid in ["SSH-004", "SSH-005", "USR-003", "SYS-001", "FILE-005", "FW-001"]:
        assert r[cid].status == "WARN", cid


def test_secure_has_no_problems(secure):
    results = run_all(Context(secure, fake_runner(active={"ufw"})))
    assert {r.status for r in results} == {"PASS"}
    assert compute_score(results) == 100


def test_insecure_score_low(insecure):
    assert compute_score(run_all(Context(insecure, fake_runner()))) < 40


def test_ufw_service_active_but_firewall_disabled(secure):
    conf = os.path.join(secure, "etc", "ufw", "ufw.conf")
    os.makedirs(os.path.dirname(conf))
    with open(conf, "w") as f:
        f.write("# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n")
    r = by_id(run_all(Context(secure, fake_runner(active={"ufw"}))))
    assert r["FW-001"].status == "WARN" and "switched off" in r["FW-001"].detail
    with open(conf, "w") as f:
        f.write("ENABLED=yes\n")
    assert by_id(run_all(Context(secure, fake_runner(active={"ufw"}))))["FW-001"].status == "PASS"


def test_accept_redirects_checks_every_interface(secure):
    def set_iface(name, value):
        path = os.path.join(secure, "proc", "sys", "net", "ipv4", "conf", name, "accept_redirects")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(value + "\n")

    set_iface("lo", "1")            # loopback doesn't count
    set_iface("default", "0")
    assert by_id(run_all(Context(secure), only=["SYS"]))["SYS-003"].status == "PASS"
    set_iface("eth0", "1")          # conf/all = 0 is not enough when the interface itself says 1
    r = by_id(run_all(Context(secure), only=["SYS"]))["SYS-003"]
    assert r.status == "FAIL" and "eth0" in r.detail


def test_syncookies_2_is_enabled_too(secure):
    with open(os.path.join(secure, "proc", "sys", "net", "ipv4", "tcp_syncookies"), "w") as f:
        f.write("2\n")
    assert by_id(run_all(Context(secure), only=["SYS"]))["SYS-002"].status == "PASS"


def test_uid_zero_written_as_00(secure):
    with open(os.path.join(secure, "etc", "passwd"), "a") as f:
        f.write("backdoor:x:00:0::/root:/bin/sh\n")
    r = by_id(run_all(Context(secure), only=["USR"]))["USR-001"]
    assert r.status == "FAIL" and "backdoor" in r.detail


def test_password_that_never_expires(secure):
    with open(os.path.join(secure, "etc", "login.defs"), "w") as f:
        f.write("PASS_MAX_DAYS\t-1\n")
    assert by_id(run_all(Context(secure), only=["USR"]))["USR-003"].status == "WARN"


def test_skip_when_files_missing(tmp_path):
    results = by_id(run_all(Context(str(tmp_path))))
    assert results["SSH-000"].status == "SKIP"
    assert results["FILE-001"].status == "SKIP"
    assert results["SVC-001"].status == "SKIP"      # services aren't checked in a fake root


def test_only_filter(secure):
    results = run_all(Context(secure), only=["SSH"])
    assert results and all(r.check_id.startswith("SSH") for r in results)


def test_only_filter_ignores_empty_prefixes(secure, capsys):
    assert {r.check_id[:3] for r in run_all(Context(secure), only=["SSH", ""])} == {"SSH"}
    assert main(["--root", secure, "--only", ","]) == 1
    capsys.readouterr()
    assert main(["--root", secure, "--only", "SSH,"]) == 0
    out = capsys.readouterr().out
    assert "SSH-001" in out and "FILE-001" not in out


def test_score_is_not_zero_when_everything_is_skipped(tmp_path, capsys):
    assert compute_score([Result("X-1", "t", "SKIP", "low")]) is None
    report = tmp_path / "r.json"
    assert main(["--root", str(tmp_path), "--only", "SVC,FW", "--json", str(report)]) == 0
    assert "Hardening score: n/a" in capsys.readouterr().out
    assert json.loads(report.read_text())["summary"]["score"] is None


def test_cli_reports_and_exit_codes(insecure, secure, tmp_path):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    assert main(["--root", insecure, "--json", str(j), "--html", str(h), "--fail-on", "high"]) == 2
    data = json.loads(j.read_text())
    assert data["summary"]["fail"] > 0
    assert "<table>" in h.read_text()
    assert main(["--root", secure, "--fail-on", "low"]) == 0


def test_report_directory_is_created_and_write_errors_are_reported(secure, tmp_path, capsys):
    target = tmp_path / "reports" / "r.json"
    assert main(["--root", secure, "--json", str(target)]) == 0
    assert target.exists()
    blocker = tmp_path / "file.txt"
    blocker.write_text("x")
    assert main(["--root", secure, "--json", str(blocker / "r.json")]) == 1
    assert "could not write" in capsys.readouterr().err


def test_cli_bad_root():
    assert main(["--root", "/no/such/directory"]) == 1


def test_double_slash_root_is_the_real_system():
    assert Context("//").is_real
