"""Teardown's boundary integrity check, run against stubbed sudo (no root).

The relevant teardown.sh sections are cut out of the script and executed, so
what is tested is the shipped shell rather than a reimplementation.
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEARDOWN_SH = os.path.join(REPO_ROOT, "native-proxy", "teardown.sh")

with open(TEARDOWN_SH, encoding="utf-8") as _fh:
    _SOURCE = _fh.read()


def _between(start: str, end: str | None) -> str:
    i = _SOURCE.index(start)
    j = _SOURCE.index(end, i) if end else len(_SOURCE)
    return _SOURCE[i:j]


CHECK_SECTION = _between('TLS_INTERCEPT="${NFW_TLS_INTERCEPT', "# 0.5. Stop fail-fast")
EXIT_SECTION = _between("# 8. Exit code", None)
HEALTH_PY = _between("import json\nimport os\n\nproxy_leg", "\nPYEOF")

FAKE_SUDO = """#!/bin/bash
echo "$*" >> "${FAKE_SUDO_CALLS}"
if [ -s "${FAKE_MISSING}" ]; then
    while IFS= read -r needle; do
        case "$*" in *"${needle}"*) exit 1 ;; esac
    done < "${FAKE_MISSING}"
fi
exit 0
"""


def _run_check(tmp_path, *, missing=(), proxy_alive="yes", dns_alive="yes", **env):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sudo = bindir / "sudo"
    sudo.write_text(FAKE_SUDO)
    sudo.chmod(0o755)
    (tmp_path / "missing").write_text("".join(m + "\n" for m in missing))
    script = (
        "set -euo pipefail\n" + CHECK_SECTION
        + '\nprintf "INTACT=%s\\n" "${BOUNDARY_INTACT}"\n'
        + 'printf "%s" "${BOUNDARY_MISSING}" > "${OUT_MISSING}"\n'
    )
    full_env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_SUDO_CALLS": str(tmp_path / "calls"),
        "FAKE_MISSING": str(tmp_path / "missing"),
        "OUT_MISSING": str(tmp_path / "out_missing"),
        "TRANSPARENT": "true",
        "MODE": "enforce",
        "DNS_ENABLED": "true",
        "FORWARD_LOG": "true",
        "IP6TABLES": "true",
        "PROXY_PORT": "8080",
        "PROXY_ALIVE_AT_TEARDOWN": proxy_alive,
        "DNS_ALIVE_AT_TEARDOWN": dns_alive,
    }
    full_env.update(env)
    res = subprocess.run(["bash", "-c", script], env=full_env,
                         capture_output=True, text=True, check=True)
    intact = res.stdout.strip().splitlines()[-1].removeprefix("INTACT=")
    missing_out = (tmp_path / "out_missing").read_text().splitlines()
    calls_file = tmp_path / "calls"
    calls = calls_file.read_text().splitlines() if calls_file.exists() else []
    return intact, missing_out, calls


class TestBoundaryCheck:
    def test_all_rules_present_is_intact(self, tmp_path):
        intact, missing, calls = _run_check(tmp_path)
        assert intact == "true"
        assert missing == []
        assert all(" -C " in c for c in calls)
        assert any("--dport 53" in c for c in calls)
        assert any(c.startswith("ip6tables") for c in calls)

    def test_deleted_redirect_is_reported(self, tmp_path):
        intact, missing, _ = _run_check(tmp_path, missing=["--dport 443 -j REDIRECT"])
        assert intact == "false"
        assert len(missing) == 1
        assert "--dport 443 -j REDIRECT --to-port 8080" in missing[0]

    def test_dead_proxy_breaks_boundary(self, tmp_path):
        intact, missing, _ = _run_check(tmp_path, proxy_alive="no")
        assert intact == "false"
        assert any("mitmdump" in m for m in missing)

    def test_dead_dns_server_breaks_boundary(self, tmp_path):
        intact, missing, _ = _run_check(tmp_path, dns_alive="no")
        assert intact == "false"
        assert any("dns_server.py" in m for m in missing)

    def test_monitor_does_not_check_enforce_only_rules(self, tmp_path):
        intact, _, calls = _run_check(tmp_path, MODE="monitor",
                                      missing=["-j REJECT"])
        assert intact == "true"
        assert not any("REJECT" in c for c in calls)

    def test_uninstalled_optional_rules_are_not_checked(self, tmp_path):
        _, _, calls = _run_check(tmp_path, FORWARD_LOG="false", IP6TABLES="false",
                                 DNS_ENABLED="false", dns_alive="disabled")
        assert not any("FORWARD" in c for c in calls)
        assert not any(c.startswith("ip6tables") for c in calls)
        assert not any("--dport 53" in c for c in calls)

    def test_intercept_off_enforce_checks_dns_rejects(self, tmp_path):
        intact, missing, calls = _run_check(
            tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false", CONN_LOGGING="true",
            proxy_alive="no", missing=["--dport 853 -m owner ! --uid-owner 0 -j REJECT --reject-with tcp-reset"])
        assert intact == "false"
        assert len(missing) == 1
        assert not any("REDIRECT" in c for c in calls)
        assert sum("--uid-owner 0" in c for c in calls) == 6

    @pytest.mark.parametrize("mode", ["enforce", "monitor"])
    def test_intercept_off_checks_conn_log_rules(self, tmp_path, mode):
        intact, missing, calls = _run_check(
            tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false", CONN_LOGGING="true",
            MODE=mode, proxy_alive="no", missing=["NFW-CONN6"])
        assert intact == "false"
        assert len(missing) == 1 and "ip6tables" in missing[0]
        assert sum("-j LOG" in c for c in calls) == 2
        assert not any("FORWARD" in c for c in calls)

    def test_intercept_off_skips_conn_log_rule_setup_could_not_add(self, tmp_path):
        intact, missing, calls = _run_check(
            tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false", CONN_LOGGING="true",
            NFW_CONN_LOG4="false", proxy_alive="no", missing=["NFW-CONN: "])
        assert intact == "true"
        assert missing == []
        assert not any("NFW-CONN: " in c for c in calls)

    def test_intercept_off_monitor_skips_dns_rejects(self, tmp_path):
        intact, _, calls = _run_check(tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false",
                                      CONN_LOGGING="true", MODE="monitor", proxy_alive="no")
        assert intact == "true"
        assert not any("REJECT" in c for c in calls)

    def test_intercept_off_no_ip6tables_skips_ip6_rules(self, tmp_path):
        _, _, calls = _run_check(tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false",
                                 CONN_LOGGING="true", IP6TABLES="false", proxy_alive="no")
        assert not any(c.startswith("ip6tables") for c in calls)

    def test_intercept_off_without_installed_rules_is_unchecked(self, tmp_path):
        intact, _, calls = _run_check(tmp_path, TRANSPARENT="false", NFW_TLS_INTERCEPT="false",
                                      CONN_LOGGING="false", MODE="monitor")
        assert intact == "unchecked"
        assert calls == []

    def test_explicit_proxy_mode_is_unchecked(self, tmp_path):
        intact, _, calls = _run_check(tmp_path, TRANSPARENT="false")
        assert intact == "unchecked"
        assert calls == []


def _run_exit(mode, fail_on_block, intact, missing="iptables -C OUTPUT x\n"):
    script = (
        f'MODE="{mode}"\nFAIL_ON_BLOCK="{fail_on_block}"\nBOUNDARY_INTACT="{intact}"\n'
        f"BOUNDARY_MISSING='{missing}'\n"
        'REPORT_OK="true"\nMALFORMED_LINES=0\nBLOCKED_COUNT=0\n' + EXIT_SECTION
    )
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script],
                          capture_output=True, text=True)


class TestBoundaryExit:
    def test_enforce_fails_closed(self):
        res = _run_exit("enforce", "true", "false")
        assert res.returncode == 1
        assert "::error title=PipeWarden boundary::" in res.stdout
        assert "iptables -C OUTPUT x" in res.stdout

    def test_enforce_fail_on_block_false_warns(self):
        res = _run_exit("enforce", "false", "false")
        assert res.returncode == 0
        assert "::warning title=PipeWarden boundary::" in res.stdout

    def test_monitor_never_blocks(self):
        res = _run_exit("monitor", "true", "false")
        assert res.returncode == 0
        assert "::warning title=PipeWarden boundary::" in res.stdout

    @pytest.mark.parametrize("intact", ["true", "unchecked"])
    def test_intact_or_unchecked_is_silent(self, intact):
        res = _run_exit("enforce", "true", intact)
        assert res.returncode == 0
        assert "boundary" not in res.stdout


def _run_health(tmp_path, intact, missing=""):
    conn = tmp_path / "connections.jsonl"
    conn.write_text("")
    env = dict(os.environ, PW_CONN_LOG=str(conn), PW_REPORT_DIR=str(tmp_path),
               PW_TRANSPARENT="true", PW_PROXY_ALIVE="yes", PW_DNS_ALIVE="yes",
               PW_BOUNDARY_INTACT=intact, PW_BOUNDARY_MISSING=missing)
    res = subprocess.run([sys.executable, "-c", HEALTH_PY], env=env,
                         capture_output=True, text=True, check=True)
    health = json.loads((tmp_path / "health.json").read_text())
    return health, (tmp_path / "summary.md").read_text(), res.stdout


class TestBoundaryHealth:
    def test_broken_boundary_recorded(self, tmp_path):
        health, summary, stdout = _run_health(
            tmp_path, "false", "iptables -C OUTPUT a\nprocess: mitmdump (proxy)\n")
        assert health["boundary_intact"] is False
        assert health["boundary_missing"] == ["iptables -C OUTPUT a", "process: mitmdump (proxy)"]
        assert "Boundary intact at teardown (rules + processes) | **no**" in summary
        assert "boundary was NOT intact" in summary
        # Annotated by the exit step with mode-appropriate severity, not here.
        assert "boundary" not in stdout

    def test_intact_boundary_recorded(self, tmp_path):
        health, summary, _ = _run_health(tmp_path, "true")
        assert health["boundary_intact"] is True
        assert health["boundary_missing"] == []
        assert "| yes |" in summary

    def test_unchecked_is_null(self, tmp_path):
        health, summary, _ = _run_health(tmp_path, "unchecked")
        assert health["boundary_intact"] is None
        assert "not checked" in summary
