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
