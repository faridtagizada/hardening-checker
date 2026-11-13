import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from make_demo_root import make_root                          # noqa: E402
from hardening_checker.cli import main                         # noqa: E402
from hardening_checker.models import Context, compute_score   # noqa: E402
from hardening_checker.runner import run_all                  # noqa: E402
from hardening_checker.ssh_checks import parse_sshd_config    # noqa: E402


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


def test_ssh_first_value_wins_and_include(insecure):
    cfg = parse_sshd_config(Context(insecure))
    assert cfg["passwordauthentication"] == "yes"    # the drop-in comes before the main file's own setting
    assert cfg["permitrootlogin"] == "yes"


def test_ssh_match_block_ignored(tmp_path):
    p = tmp_path / "etc" / "ssh"
    p.mkdir(parents=True)
    (p / "sshd_config").write_text("PermitRootLogin no\nMatch User bob\nPermitRootLogin yes\n")
    assert parse_sshd_config(Context(str(tmp_path)))["permitrootlogin"] == "no"


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


def test_skip_when_files_missing(tmp_path):
    results = by_id(run_all(Context(str(tmp_path))))
    assert results["SSH-000"].status == "SKIP"
    assert results["FILE-001"].status == "SKIP"
    assert results["SVC-001"].status == "SKIP"      # services aren't checked in a fake root


def test_only_filter(secure):
    results = run_all(Context(secure), only=["SSH"])
    assert results and all(r.check_id.startswith("SSH") for r in results)


def test_cli_reports_and_exit_codes(insecure, secure, tmp_path):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    assert main(["--root", insecure, "--json", str(j), "--html", str(h), "--fail-on", "high"]) == 2
    data = json.loads(j.read_text())
    assert data["summary"]["fail"] > 0
    assert "<table>" in h.read_text()
    assert main(["--root", secure, "--fail-on", "low"]) == 0


def test_cli_bad_root():
    assert main(["--root", "/no/such/directory"]) == 1


def test_ufw_service_running_but_ufw_disabled(insecure, secure):
    # ufw.service is "active (exited)" even when "ufw status" says inactive
    r = by_id(run_all(Context(insecure, fake_runner(active={"ufw"}))))
    assert r["FW-001"].status == "WARN"
    assert "ENABLED=no" in r["FW-001"].detail
    assert by_id(run_all(Context(secure, fake_runner(active={"ufw"}))))["FW-001"].status == "PASS"


def test_firewalld_does_not_need_ufw_conf(insecure):
    assert by_id(run_all(Context(insecure, fake_runner(active={"firewalld"}))))["FW-001"].status == "PASS"


def test_accept_redirects_default_is_checked(secure):
    with open(os.path.join(secure, "proc/sys/net/ipv4/conf/default/accept_redirects"), "w") as f:
        f.write("1\n")
    r = by_id(run_all(Context(secure, fake_runner(active={"ufw"}))))["SYS-003"]
    assert r.status == "FAIL"
    assert "default.accept_redirects=1" in r.detail


def write_sshd(tmp_path, text):
    p = tmp_path / "etc" / "ssh"
    p.mkdir(parents=True)
    (p / "sshd_config").write_text(text)
    return by_id(run_all(Context(str(tmp_path)), only=["SSH"]))


def test_passwords_through_pam_keyboard_interactive(tmp_path):
    r = write_sshd(tmp_path, "PasswordAuthentication no\nUsePAM yes\n")   # KbdInteractive defaults to yes
    assert r["SSH-002"].status == "FAIL"
    assert r["SSH-002"].remediation == "KbdInteractiveAuthentication no"


@pytest.mark.parametrize("extra", ["KbdInteractiveAuthentication no\n", "ChallengeResponseAuthentication no\n",
                                   "AuthenticationMethods publickey\n", ""])
def test_keyboard_interactive_off_is_fine(tmp_path, extra):
    use_pam = "UsePAM yes\n" if extra else "UsePAM no\n"
    r = write_sshd(tmp_path, "PasswordAuthentication no\n" + use_pam + extra)
    assert r["SSH-002"].status == "PASS"


def test_permission_message_names_the_extra_bits(tmp_path):
    # 604 is a smaller number than 640, but "others read" is not allowed
    (tmp_path / "etc").mkdir()
    shadow = tmp_path / "etc" / "shadow"
    shadow.write_text("root:*:19000:0:99999:7:::\n")
    os.chmod(shadow, 0o604)
    r = by_id(run_all(Context(str(tmp_path)), only=["FILE-002"]))["FILE-002"]
    assert r.status == "FAIL"
    assert "others read" in r.detail and "≤" not in r.detail
