"""setup.sh installs mitmproxy as root, so the default path must hash-verify
every wheel against native-proxy/requirements-lock.txt. Runs the real install
block with pip and sudo stubbed out."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SETUP_SH = REPO_ROOT / "native-proxy/setup.sh"
LOCK = REPO_ROOT / "native-proxy/requirements-lock.txt"


def _install_block() -> str:
    text = SETUP_SH.read_text(encoding="utf-8")
    start = text.index('MITMPROXY_VERSION="${INPUT_MITMPROXY_VERSION:-')
    end = text.index('echo "::endgroup::"', start)
    return text[start:end]


def _locked_version() -> str:
    m = re.search(r"^mitmproxy==([^\s;\\]+)", LOCK.read_text(encoding="utf-8"), re.M)
    assert m
    return m.group(1)


def _run(
    tmp_path: Path, with_lock: bool = True, **env: str
) -> tuple[subprocess.CompletedProcess, list[str]]:
    runtime = tmp_path / "opt"
    (runtime / "native-proxy").mkdir(parents=True)
    if with_lock:
        shutil.copy(LOCK, runtime / "native-proxy/requirements-lock.txt")

    stubs = tmp_path / "bin"
    stubs.mkdir()
    pip_log = tmp_path / "pip.log"
    (stubs / "pip").write_text(
        f'#!/bin/bash\nprintf "%s\\n" "PIP_CACHE_DIR=${{PIP_CACHE_DIR:-}}" "$@" "--" >> "{pip_log}"\n'
    )
    (stubs / "sudo").write_text(
        '#!/bin/bash\nwhile [[ "$1" == *=* ]]; do export "$1"; shift; done\nexec "$@"\n'
    )
    for stub in ("pip", "sudo"):
        (stubs / stub).chmod(0o755)

    script = (
        "set -euo pipefail\n"
        f'RUNTIME_ROOT="{runtime}"\n'
        'ENABLE_TLS_INTERCEPT="${ENABLE_TLS_INTERCEPT:-true}"\n'
        'ENABLE_TRANSPARENT="${ENABLE_TRANSPARENT:-true}"\n' + _install_block()
    )
    proc = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{stubs}:/usr/bin:/bin", **env},
        capture_output=True,
        text=True,
        check=False,
    )
    args = pip_log.read_text().splitlines() if pip_log.exists() else []
    return proc, args


@pytest.fixture(autouse=True)
def _no_preinstalled_mitmdump():
    if os.path.exists("/usr/local/bin/mitmdump"):
        pytest.skip("transparent branch skips install when mitmdump is preinstalled")


def test_default_version_installs_from_hash_pinned_lock(tmp_path):
    proc, args = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "--require-hashes" in args
    lock_arg = args[args.index("-r") + 1]
    assert lock_arg == str(tmp_path / "opt/native-proxy/requirements-lock.txt")
    assert "--break-system-packages" in args and "--ignore-installed" in args
    assert not any(a.startswith("mitmproxy==") for a in args)
    assert "::warning::" not in proc.stdout


def test_explicit_locked_version_still_hash_verifies(tmp_path):
    proc, args = _run(tmp_path, INPUT_MITMPROXY_VERSION=_locked_version())
    assert proc.returncode == 0, proc.stderr
    assert "--require-hashes" in args


def test_overridden_version_falls_back_unhashed_with_warning(tmp_path):
    proc, args = _run(tmp_path, INPUT_MITMPROXY_VERSION="99.0.0")
    assert proc.returncode == 0, proc.stderr
    assert "--require-hashes" not in args
    assert "mitmproxy==99.0.0" in args and "typing_extensions" in args
    assert "::warning::" in proc.stdout and "hash verification" in proc.stdout


def test_pip_cache_dir_is_forwarded_through_sudo(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    proc, args = _run(tmp_path, PIP_CACHE_DIR=str(cache))
    assert proc.returncode == 0, proc.stderr
    assert f"PIP_CACHE_DIR={cache}" in args
    assert "--require-hashes" in args


def test_explicit_proxy_mode_also_uses_lock(tmp_path):
    proc, args = _run(tmp_path, ENABLE_TRANSPARENT="false")
    assert proc.returncode == 0, proc.stderr
    assert "--require-hashes" in args
    assert "--break-system-packages" not in args


def test_missing_lock_fails_closed(tmp_path):
    proc, args = _run(tmp_path, with_lock=False)
    assert proc.returncode != 0
    assert args == []
