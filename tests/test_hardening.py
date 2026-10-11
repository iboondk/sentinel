"""Tests for hardening/harden.sh, run against fixture trees.

Fixtures live in tests/fixtures/hardening/{good,bad}. Git does not keep file
modes (and some external volumes are exFAT, which has no Unix modes), so each test
copies a fixture into tmp_path and sets the modes with os.chmod. The script runs
with SENTINEL_ROOT=tmp_path, so it only reads and writes inside tmp_path.

The script is run with /bin/bash when it exists (macOS: bash 3.2).
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "hardening" / "harden.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "hardening"
BASH = "/bin/bash" if os.path.exists("/bin/bash") else "bash"

CHECK_PREFIXES = ("PASS ", "FAIL ", "FIXED ")
CHECK_COUNT = 11

MODES = {
    "good": {"etc/shadow": 0o640, "etc/passwd": 0o644},
    "bad": {"etc/shadow": 0o644, "etc/passwd": 0o666},
}


def make_tree(kind, dest):
    shutil.copytree(FIXTURES / kind, dest, dirs_exist_ok=True)
    for rel, mode in MODES[kind].items():
        os.chmod(dest / rel, mode)
    return dest


def run(root, *args):
    env = {**os.environ, "SENTINEL_ROOT": str(root)}
    return subprocess.run(
        [BASH, str(SCRIPT), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def check_lines(result):
    return [line for line in result.stdout.splitlines() if line.startswith(CHECK_PREFIXES)]


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def good(tmp_path):
    return make_tree("good", tmp_path)


@pytest.fixture
def bad(tmp_path):
    return make_tree("bad", tmp_path)


def test_script_exists_and_has_valid_bash_syntax():
    assert SCRIPT.is_file()
    result = subprocess.run([BASH, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_good_check_exits_zero_with_all_pass(good):
    result = run(good, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    lines = check_lines(result)
    assert len(lines) == CHECK_COUNT
    assert all(line.startswith("PASS ") for line in lines)
    assert "SUMMARY" in result.stdout


def test_bad_check_exits_one_and_lists_ssh01(bad):
    result = run(bad, "--check")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL SSH-01" in result.stdout
    assert not any(line.startswith("FIXED ") for line in check_lines(result))


def test_check_mode_does_not_change_files(bad):
    before = (bad / "etc/ssh/sshd_config").read_text()
    run(bad, "--check")
    assert (bad / "etc/ssh/sshd_config").read_text() == before
    assert not (bad / "etc/sysctl.d/99-sentinel.conf").exists()
    assert not (bad / "etc/ssh/sshd_config.sentinel.bak").exists()


def test_bad_apply_fixes_and_following_check_passes(bad):
    result = run(bad, "--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(line.startswith("FIXED ") for line in check_lines(result))
    assert "PermitRootLogin no" in (bad / "etc/ssh/sshd_config").read_text()
    assert run(bad, "--check").returncode == 0


def test_second_apply_reports_only_pass(bad):
    assert run(bad, "--apply").returncode == 0
    result = run(bad, "--apply")
    assert result.returncode == 0, result.stdout + result.stderr
    lines = check_lines(result)
    assert len(lines) == CHECK_COUNT
    assert not any(line.startswith("FIXED ") for line in lines)


def test_apply_creates_backup_with_original_content(bad):
    original = (bad / "etc/ssh/sshd_config").read_text()
    assert run(bad, "--apply").returncode == 0
    backup = bad / "etc/ssh/sshd_config.sentinel.bak"
    assert backup.exists()
    assert backup.read_text() == original


def test_backup_is_made_only_once(bad):
    original = (bad / "etc/ssh/sshd_config").read_text()
    assert run(bad, "--apply").returncode == 0
    # Break the file again, then apply again: the backup must keep the first original.
    (bad / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    assert run(bad, "--apply").returncode == 0
    assert (bad / "etc/ssh/sshd_config.sentinel.bak").read_text() == original


def test_apply_creates_sysctl_drop_in(bad):
    sysctl = bad / "etc/sysctl.d/99-sentinel.conf"
    assert not sysctl.exists()
    assert run(bad, "--apply").returncode == 0
    text = sysctl.read_text()
    assert "net.ipv4.ip_forward = 0" in text
    assert "kernel.randomize_va_space = 2" in text
    assert "net.ipv4.tcp_syncookies = 1" in text


def test_apply_keeps_shadow_and_passwd_modes(bad):
    assert run(bad, "--apply").returncode == 0
    assert mode_of(bad / "etc/shadow") == 0o640
    assert mode_of(bad / "etc/passwd") == 0o644


def test_apply_sets_login_defs_max_days(bad):
    assert run(bad, "--apply").returncode == 0
    assert "PASS_MAX_DAYS 90" in (bad / "etc/login.defs").read_text()
    assert "PASS_MAX_DAYS 99999" not in (bad / "etc/login.defs").read_text()


def test_only_prints_exactly_one_check_line(bad):
    result = run(bad, "--check", "--only", "SSH-01")
    assert result.returncode == 1, result.stdout + result.stderr
    lines = check_lines(result)
    assert len(lines) == 1
    assert lines[0].startswith("FAIL SSH-01 ")


def test_only_passes_on_good_tree(good):
    result = run(good, "--check", "--only", "SSH-01")
    assert result.returncode == 0
    lines = check_lines(result)
    assert len(lines) == 1
    assert lines[0].startswith("PASS SSH-01 ")


@pytest.mark.parametrize(
    "args",
    [
        ["--bogus"],
        ["--check", "--apply"],
        ["--only", "NOPE-99"],
        ["--only"],
    ],
)
def test_usage_errors_exit_two(bad, args):
    result = run(bad, *args)
    assert result.returncode == 2, result.stdout + result.stderr


def test_apply_without_root_and_without_fixture_root_exits_two(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root; the non-root refusal cannot be tested")
    env = {k: v for k, v in os.environ.items() if k != "SENTINEL_ROOT"}
    env["SENTINEL_ROOT"] = ""
    result = subprocess.run(
        [BASH, str(SCRIPT), "--apply"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 2
    assert "root" in result.stderr
