"""Tests for the watched-secret handover (scripts/write_watch_secrets.py).

The proxy runs under sudo with a stripped environment, so this file is the only
route by which the job's secrets reach the detector. If it silently produces
nothing, env-secrets watches nothing and every report comes back clean — the
same shape of failure as #102, where a dead addon looked like a quiet network.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from write_watch_secrets import collect  # noqa: E402

V2_WATCHING = """
version: "2"
mode: enforce
exfiltration:
  mode: block
  detectors: [env-secrets, patterns]
  watch_env: [MY_TOKEN, ABSENT_TOKEN]
rules: []
"""


def _policy(tmp_path: Path, content: str) -> str:
    path = tmp_path / "policy.yml"
    path.write_text(content, encoding="utf-8")
    return str(path)


class TestCollect:
    def test_returns_watched_values_present_in_env(self, tmp_path):
        got = collect(_policy(tmp_path, V2_WATCHING), {"MY_TOKEN": "s" * 20})
        assert got == {"MY_TOKEN": "s" * 20}

    def test_skips_absent_names(self, tmp_path):
        """A job not granted a watched secret is normal, not an error."""
        got = collect(_policy(tmp_path, V2_WATCHING), {})
        assert got == {}

    def test_empty_when_scanning_disabled(self, tmp_path):
        content = V2_WATCHING.replace("mode: block", "mode: off")
        got = collect(_policy(tmp_path, content), {"MY_TOKEN": "s" * 20})
        assert got == {}

    def test_empty_when_env_secrets_detector_not_selected(self, tmp_path):
        content = V2_WATCHING.replace(
            "detectors: [env-secrets, patterns]", "detectors: [patterns]"
        )
        got = collect(_policy(tmp_path, content), {"MY_TOKEN": "s" * 20})
        assert got == {}, "no reason to materialise values nothing will read"

    def test_empty_for_v1_policy(self, tmp_path):
        content = 'version: "1"\nmode: enforce\nrules: []\n'
        got = collect(_policy(tmp_path, content), {"MY_TOKEN": "s" * 20})
        assert got == {}

    def test_no_policy_file_yields_nothing(self):
        assert collect("", {"MY_TOKEN": "s" * 20}) == {}


class TestCli:
    def _run(self, policy: str, out: Path, env: dict):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/write_watch_secrets.py"),
             policy, str(out)],
            capture_output=True, text=True,
            env={**os.environ, **env, "PYTHONPATH": str(REPO_ROOT)},
        )

    def test_writes_values_with_owner_only_permissions(self, tmp_path):
        out = tmp_path / "secrets.json"
        result = self._run(
            _policy(tmp_path, V2_WATCHING), out, {"MY_TOKEN": "s" * 20}
        )

        assert result.returncode == 0
        assert json.loads(out.read_text()) == {"MY_TOKEN": "s" * 20}
        mode = stat.S_IMODE(out.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_never_prints_the_values(self, tmp_path):
        """The output goes to the build log, which is far easier to read than
        the traffic the detector exists to catch."""
        out = tmp_path / "secrets.json"
        secret = "supersecretvalue123456"
        result = self._run(_policy(tmp_path, V2_WATCHING), out, {"MY_TOKEN": secret})

        assert secret not in result.stdout
        assert secret not in result.stderr
        assert "1 watched value" in result.stdout

    def test_unreadable_policy_still_writes_empty_file(self, tmp_path):
        """Losing the detector is bad; failing setup — and so losing egress
        control — because a detector could not be configured is worse."""
        out = tmp_path / "secrets.json"
        result = self._run(str(tmp_path / "nope.yml"), out, {})

        assert result.returncode == 0
        assert json.loads(out.read_text()) == {}

    def test_malformed_policy_still_writes_empty_file(self, tmp_path):
        out = tmp_path / "secrets.json"
        bad = _policy(tmp_path, 'version: "2"\nmode: enforce\nexfiltration: 5\n')
        result = self._run(bad, out, {})

        assert result.returncode == 0
        assert json.loads(out.read_text()) == {}

    @pytest.mark.parametrize("args", [[], ["only-one"]])
    def test_usage_error_on_wrong_arity(self, args):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/write_watch_secrets.py"), *args],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        )
        assert result.returncode == 2


class TestLoadWatchValues:
    def test_round_trips_with_the_writer(self, tmp_path):
        from policy.exfil import build_watchlist, load_watch_values

        out = tmp_path / "secrets.json"
        out.write_text(json.dumps({"MY_TOKEN": "s" * 20}), encoding="utf-8")

        values = load_watch_values(str(out))
        assert [w.label for w in build_watchlist(values, ["MY_TOKEN"])] == ["MY_TOKEN"]

    @pytest.mark.parametrize(
        "content", ["not json", '["a","b"]', '{"k": 5}'],
    )
    def test_malformed_file_degrades_to_empty(self, tmp_path, content):
        from policy.exfil import load_watch_values

        out = tmp_path / "secrets.json"
        out.write_text(content, encoding="utf-8")
        assert load_watch_values(str(out)) == {}

    def test_missing_file_degrades_to_empty(self, tmp_path):
        from policy.exfil import load_watch_values

        assert load_watch_values(str(tmp_path / "nope.json")) == {}


class TestFreshFileOnly:
    """The path must be fresh. A stale leftover from a cancelled job is owned
    by the proxy user; writing through it either fails or, worse, leaves the
    previous job's secrets to be chowned and trusted."""

    def test_refuses_an_existing_file(self, tmp_path):
        out = tmp_path / "secrets.json"
        out.write_text('{"OLD_JOB": "stale-secret-value"}', encoding="utf-8")

        import subprocess as sp
        result = sp.run(
            [sys.executable, str(REPO_ROOT / "scripts/write_watch_secrets.py"),
             "", str(out)],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        )

        assert result.returncode == 1
        assert "refusing to write" in result.stderr
        # And the stale contents were not silently blessed as current.
        assert json.loads(out.read_text()) == {"OLD_JOB": "stale-secret-value"}

    def test_refuses_a_symlink(self, tmp_path):
        target = tmp_path / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        link = tmp_path / "secrets.json"
        link.symlink_to(target)

        import subprocess as sp
        result = sp.run(
            [sys.executable, str(REPO_ROOT / "scripts/write_watch_secrets.py"),
             "", str(link)],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        )
        assert result.returncode == 1
