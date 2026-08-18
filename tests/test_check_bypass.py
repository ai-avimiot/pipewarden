"""Tests for the bypass-suite checker (scripts/check_bypass.py).

The checker decides whether a claim about coverage holds, so its own failure
modes matter more than usual: a checker that passes on an empty report would
manufacture exactly the false confidence the suite exists to remove.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_bypass import evaluate, matches, render  # noqa: E402


def _conn(**kw) -> dict:
    base = {
        "timestamp": "2026-08-10T00:00:00+00:00",
        "protocol": "https",
        "host": "example.com",
        "port": 443,
        "status": "allowed",
    }
    base.update(kw)
    return base


class TestMatches:
    def test_matches_on_host_substring(self):
        assert matches(_conn(host="api.example.com"), {"host": "example.com"})

    def test_host_also_checks_sni_and_server_ip(self):
        """A direct-to-IP request has the IP as host and the name only in SNI,
        or no name at all."""
        assert matches(_conn(host="93.184.216.34", tls_sni="example.com"),
                       {"host": "example.com"})
        assert matches(_conn(host="1.2.3.4", server_ip="93.184.216.34"),
                       {"host": "93.184"})

    def test_matches_on_port_alone(self):
        assert matches(_conn(port=853, host="1.1.1.1"), {"port": 853})

    def test_matches_on_protocol(self):
        assert matches(_conn(protocol="dns", port=53), {"protocol": "dns"})

    def test_all_specified_fields_must_agree(self):
        conn = _conn(port=443, protocol="tcp")
        assert not matches(conn, {"port": 443, "protocol": "udp"})

    def test_empty_case_matches_anything(self):
        assert matches(_conn(), {})


class TestEvaluate:
    def test_observed_case_passes_when_seen(self):
        results = evaluate(
            [_conn(host="example.com")],
            [{"name": "control", "host": "example.com", "expect": "observed"}],
        )
        assert results[0]["ok"] is True
        assert results[0]["verdict"] == "caught"

    def test_observed_case_fails_when_missing(self):
        """A regression: the intercept stopped seeing something it used to."""
        results = evaluate(
            [_conn(host="other.test")],
            [{"name": "control", "host": "example.com", "expect": "observed"}],
        )
        assert results[0]["ok"] is False
        assert results[0]["verdict"] == "MISSED"

    def test_gap_case_passes_when_absent(self):
        results = evaluate(
            [_conn(host="example.com")],
            [{"name": "docker", "host": "docker-blindspot", "expect": "gap"}],
        )
        assert results[0]["ok"] is True
        assert results[0]["verdict"] == "known gap"

    def test_gap_case_fails_when_it_starts_being_caught(self):
        """Good news, but the docs telling users about the gap are now wrong."""
        results = evaluate(
            [_conn(host="docker-blindspot.example")],
            [{"name": "docker", "host": "docker-blindspot", "expect": "gap"}],
        )
        assert results[0]["ok"] is False
        assert results[0]["verdict"] == "GAP CLOSED"

    def test_rejects_unknown_expectation(self):
        with pytest.raises(ValueError, match="'expect' must be one of"):
            evaluate([_conn()], [{"name": "x", "expect": "maybe"}])


class TestRender:
    def test_names_regressions_explicitly(self):
        out = render(
            evaluate([], [{"name": "control", "host": "x", "expect": "observed"}])
        )
        assert "Regression" in out
        assert "control" in out

    def test_calls_out_a_closed_gap_as_stale_docs(self):
        out = render(
            evaluate(
                [_conn(host="docker-blindspot.example")],
                [{"name": "docker", "host": "docker-blindspot", "expect": "gap"}],
            )
        )
        assert "documented gap appears to be closed" in out


class TestCli:
    def _write(self, tmp_path, connections, cases):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"connections": connections}), encoding="utf-8")
        spec = tmp_path / "cases.json"
        spec.write_text(json.dumps(cases), encoding="utf-8")
        return report, spec

    def _run(self, report, spec):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/check_bypass.py"),
             str(report), str(spec)],
            capture_output=True, text=True,
        )

    def test_passes_when_every_case_matches(self, tmp_path):
        report, spec = self._write(
            tmp_path,
            [_conn(host="example.com")],
            [{"name": "control", "host": "example.com", "expect": "observed"}],
        )
        result = self._run(report, spec)
        assert result.returncode == 0
        assert "All 1 bypass cases matched" in result.stdout

    def test_fails_on_empty_report(self, tmp_path):
        """Passing here would report 'no bypasses found' from an empty set —
        the exact false-green this suite exists to prevent."""
        report, spec = self._write(
            tmp_path, [], [{"name": "c", "host": "x", "expect": "gap"}]
        )
        result = self._run(report, spec)
        assert result.returncode == 1
        assert "recorded nothing" in result.stdout

    def test_fails_on_missing_report(self, tmp_path):
        _, spec = self._write(tmp_path, [], [])
        result = self._run(tmp_path / "nope.json", spec)
        assert result.returncode == 1
        assert "cannot read report" in result.stdout

    def test_writes_step_summary_when_available(self, tmp_path, monkeypatch):
        import os

        report, spec = self._write(
            tmp_path,
            [_conn(host="example.com")],
            [{"name": "control", "host": "example.com", "expect": "observed"}],
        )
        summary = tmp_path / "summary.md"
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/check_bypass.py"),
             str(report), str(spec)],
            capture_output=True, text=True,
            env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)},
        )
        assert result.returncode == 0
        assert "PipeWarden bypass suite" in summary.read_text()

    def test_usage_error_on_wrong_arity(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/check_bypass.py")],
            capture_output=True, text=True,
        )
        assert result.returncode == 2


class TestShippedCaseFile:
    """The committed spec must stay loadable and internally sane."""

    def test_cases_file_is_valid(self):
        cases = json.loads(
            (REPO_ROOT / ".github/bypass-cases.json").read_text(encoding="utf-8")
        )
        assert cases, "no cases defined"
        for case in cases:
            assert case.get("name"), f"case without a name: {case}"
            assert case.get("expect") in ("observed", "gap"), case["name"]
            assert case.get("note"), f"{case['name']}: every case needs its rationale"

    def test_gaps_are_documented_as_such(self):
        cases = json.loads(
            (REPO_ROOT / ".github/bypass-cases.json").read_text(encoding="utf-8")
        )
        for case in cases:
            if case["expect"] == "gap":
                assert "KNOWN GAP" in case["note"], (
                    f"{case['name']}: a gap's note must say so plainly — it is "
                    f"what users read to learn the boundary"
                )

    def test_has_a_control_case(self):
        """Without one, a totally dead intercept still passes every gap case."""
        cases = json.loads(
            (REPO_ROOT / ".github/bypass-cases.json").read_text(encoding="utf-8")
        )
        assert any(c["expect"] == "observed" for c in cases)


class TestHostIsIp:
    """Discriminates the direct-to-IP case from the hostname control case.

    Matching on port+protocol alone let the control satisfy the case, so the
    suite stayed green even if direct-to-IP interception broke — the opposite
    of what a regression suite is for."""

    def test_matches_only_ip_hosts(self):
        case = {"port": 443, "protocol": "https", "host_is_ip": True}
        assert matches(_conn(host="140.82.121.6"), case)
        assert not matches(_conn(host="api.github.com"), case)

    def test_control_case_cannot_satisfy_it(self):
        results = evaluate(
            [_conn(host="api.github.com")],
            [{"name": "direct-ip", "port": 443, "protocol": "https",
              "host_is_ip": True, "expect": "observed"}],
        )
        assert results[0]["ok"] is False
        assert results[0]["verdict"] == "MISSED"

    def test_ipv6_hosts_count_as_ips(self):
        assert matches(_conn(host="2606:50c0:8000::153"), {"host_is_ip": True})


class TestCliErrorAnnotations:
    """CI surfaces ::error:: annotations; a raw traceback surfaces nothing."""

    def test_malformed_cases_file_emits_error_annotation(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"connections": [_conn()]}), encoding="utf-8")
        spec = tmp_path / "cases.json"
        spec.write_text("not json", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/check_bypass.py"),
             str(report), str(spec)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "::error::cannot read cases file" in result.stdout
        assert "Traceback" not in result.stderr

    def test_invalid_expect_emits_error_annotation(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"connections": [_conn()]}), encoding="utf-8")
        spec = tmp_path / "cases.json"
        spec.write_text(json.dumps([{"name": "x", "expect": "maybe"}]), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/check_bypass.py"),
             str(report), str(spec)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "::error::invalid bypass case" in result.stdout
        assert "Traceback" not in result.stderr
