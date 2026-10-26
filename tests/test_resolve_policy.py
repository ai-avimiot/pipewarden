"""Tests for policy auto-resolution and merging."""

import sys

import pytest
import yaml

from policy.parser import parse_policy, parse_policy_string
from scripts.resolve_policy import (
    main,
    merge_policies,
    pipeline_policy_name,
    resolve,
    workflow_stem,
)


def _write(path, rules, mode="monitor"):
    path.write_text(yaml.safe_dump({"version": "1", "mode": mode, "rules": rules}))
    return str(path)


COMMON_RULE = {
    "name": "GitHub",
    "allow": {"domains": ["*.github.com"], "ports": [443], "protocols": ["https"]},
}
PIPELINE_RULE = {
    "name": "npm registry",
    "allow": {"domains": ["registry.npmjs.org"], "ports": [443], "protocols": ["https"]},
}


class TestWorkflowStem:
    def test_from_workflow_ref(self):
        ref = "ai-avimiot/pipewarden/.github/workflows/ci.yml@refs/heads/main"
        assert workflow_stem(ref) == "ci"

    def test_yaml_extension(self):
        ref = "o/r/.github/workflows/release.yaml@refs/tags/v1"
        assert workflow_stem(ref) == "release"

    def test_empty(self):
        assert workflow_stem("") == ""

    def test_pipeline_filename(self):
        assert pipeline_policy_name("ci") == "ci.network-policy.yml"


class TestMerge:
    def test_union_of_rules(self, tmp_path):
        common = _write(tmp_path / "common.yml", [COMMON_RULE])
        pipeline = _write(tmp_path / "ci.yml", [PIPELINE_RULE])
        merged = merge_policies([common, pipeline], "enforce")
        names = [r["name"] for r in merged["rules"]]
        assert names == ["GitHub", "npm registry"]
        assert merged["mode"] == "enforce"
        # Round-trips through the parser.
        m, rules = parse_policy_string(yaml.safe_dump(merged))
        assert m == "enforce"
        assert {r.name for r in rules} == {"GitHub", "npm registry"}

    def test_pipeline_overrides_same_name(self, tmp_path):
        base = {"name": "shared", "allow": {"domains": ["a.com"], "ports": [443], "protocols": ["https"]}}
        override = {"name": "shared", "allow": {"domains": ["b.com"], "ports": [443], "protocols": ["https"]}}
        common = _write(tmp_path / "common.yml", [base])
        pipeline = _write(tmp_path / "ci.yml", [override])
        merged = merge_policies([common, pipeline], "monitor")
        assert len(merged["rules"]) == 1
        assert merged["rules"][0]["allow"]["domains"] == ["b.com"]

    def test_preserves_appears(self, tmp_path):
        rule = {"name": "cache", "appears": "sometimes",
                "allow": {"domains": ["*.pythonhosted.org"], "ports": [443], "protocols": ["https"]}}
        p = _write(tmp_path / "ci.yml", [rule])
        merged = merge_policies([p], "monitor")
        assert merged["rules"][0]["appears"] == "sometimes"


def _write_v2(path, rules, exfiltration=None):
    doc = {"version": "2", "mode": "monitor"}
    if exfiltration is not None:
        doc["exfiltration"] = exfiltration
    doc["rules"] = rules
    path.write_text(yaml.safe_dump(doc))
    return str(path)


class TestMergeV2:
    def test_keeps_exfiltration_and_allow_request_body(self, tmp_path):
        rule = dict(COMMON_RULE, allow_request_body=True)
        p = _write_v2(tmp_path / "common.yml", [rule],
                      {"mode": "block", "watch_env": ["DEPLOY_TOKEN"]})
        merged = merge_policies([p], "enforce")
        assert merged["version"] == "2"
        assert merged["rules"][0]["allow_request_body"] is True
        policy = parse_policy(yaml.safe_dump(merged))
        assert policy.exfil.mode == "block"
        assert policy.exfil.watch_env == ["DEPLOY_TOKEN"]
        assert policy.rules[0].allow_request_body is True

    def test_exfiltration_inherited_when_pipeline_declares_none(self, tmp_path):
        common = _write_v2(tmp_path / "common.yml", [COMMON_RULE], {"mode": "block"})
        pipeline = _write_v2(tmp_path / "ci.yml", [PIPELINE_RULE])
        merged = merge_policies([common, pipeline], "enforce")
        assert parse_policy(yaml.safe_dump(merged)).exfil.mode == "block"

    def test_last_exfiltration_block_wins_whole(self, tmp_path):
        common = _write_v2(tmp_path / "common.yml", [COMMON_RULE],
                           {"mode": "block", "scan_headers": True})
        pipeline = _write_v2(tmp_path / "ci.yml", [PIPELINE_RULE], {"mode": "warn"})
        exfil = parse_policy(yaml.safe_dump(
            merge_policies([common, pipeline], "enforce"))).exfil
        assert exfil.mode == "warn"
        assert exfil.scan_headers is False

    def test_off_mode_round_trips(self, tmp_path):
        p = _write_v2(tmp_path / "ci.yml", [COMMON_RULE], {"mode": "off"})
        merged = merge_policies([p], "enforce")
        assert parse_policy(yaml.safe_dump(merged)).exfil.mode == "off"

    def test_no_exfiltration_block_when_none_declared(self, tmp_path):
        p = _write_v2(tmp_path / "ci.yml", [COMMON_RULE])
        assert "exfiltration" not in merge_policies([p], "enforce")

    def test_v2_rules_stay_guarded(self, tmp_path):
        common = _write_v2(tmp_path / "common.yml", [COMMON_RULE])
        pipeline = _write_v2(tmp_path / "ci.yml", [PIPELINE_RULE])
        _, rules = parse_policy_string(yaml.safe_dump(
            merge_policies([common, pipeline], "enforce")))
        assert all(r.internal_ip_guard for r in rules)

    def test_v1_rules_stay_unguarded(self, tmp_path):
        common = _write(tmp_path / "common.yml", [COMMON_RULE])
        pipeline = _write(tmp_path / "ci.yml", [PIPELINE_RULE])
        merged = merge_policies([common, pipeline], "enforce")
        assert merged["version"] == "1"
        _, rules = parse_policy_string(yaml.safe_dump(merged))
        assert not any(r.internal_ip_guard for r in rules)

    def test_mixed_versions_refused(self, tmp_path):
        common = _write(tmp_path / "common.yml", [COMMON_RULE])
        pipeline = _write_v2(tmp_path / "ci.yml", [PIPELINE_RULE])
        with pytest.raises(ValueError, match="different versions") as exc:
            merge_policies([common, pipeline], "enforce")
        assert common in str(exc.value) and pipeline in str(exc.value)

    def test_resolve_cli_reports_mixed_versions(self, tmp_path, monkeypatch, capsys):
        pw = tmp_path / ".github" / "pipewarden"
        pw.mkdir(parents=True)
        _write(pw / "common.network-policy.yml", [COMMON_RULE])
        _write_v2(pw / "ci.network-policy.yml", [PIPELINE_RULE])
        out = tmp_path / "eff.yml"
        monkeypatch.setattr(sys, "argv", [
            "resolve_policy.py", "--pipewarden-dir", str(pw),
            "--workflow-ref", "o/r/.github/workflows/ci.yml@refs/heads/main",
            "--root-policy", str(tmp_path / "network-policy.yml"), "--out", str(out),
        ])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        assert "different versions" in capsys.readouterr().err
        assert not out.exists()


class TestResolve:
    def _ref(self):
        return "o/r/.github/workflows/ci.yml@refs/heads/main"

    def test_explicit_wins(self, tmp_path):
        explicit = _write(tmp_path / "custom.yml", [COMMON_RULE])
        out = str(tmp_path / "eff.yml")
        assert resolve(explicit, self._ref(), str(tmp_path), "network-policy.yml", "monitor", out) == explicit

    def test_explicit_missing_is_discovery(self, tmp_path):
        out = str(tmp_path / "eff.yml")
        assert resolve(str(tmp_path / "nope.yml"), self._ref(), str(tmp_path),
                       "network-policy.yml", "monitor", out) == ""

    def test_merges_common_and_pipeline(self, tmp_path):
        pw = tmp_path / ".github" / "pipewarden"
        pw.mkdir(parents=True)
        _write(pw / "common.network-policy.yml", [COMMON_RULE])
        _write(pw / "ci.network-policy.yml", [PIPELINE_RULE])
        out = str(tmp_path / "eff.yml")
        result = resolve("", self._ref(), str(pw), "network-policy.yml", "enforce", out)
        assert result == out
        m, rules = parse_policy_string(open(out).read())
        assert {r.name for r in rules} == {"GitHub", "npm registry"}

    def test_common_only(self, tmp_path):
        pw = tmp_path / "pw"
        pw.mkdir()
        _write(pw / "common.network-policy.yml", [COMMON_RULE])
        out = str(tmp_path / "eff.yml")
        result = resolve("", self._ref(), str(pw), "network-policy.yml", "monitor", out)
        assert result == out
        _, rules = parse_policy_string(open(out).read())
        assert {r.name for r in rules} == {"GitHub"}

    def test_root_fallback(self, tmp_path):
        pw = tmp_path / "pw"
        pw.mkdir()
        root = _write(tmp_path / "network-policy.yml", [COMMON_RULE])
        out = str(tmp_path / "eff.yml")
        result = resolve("", self._ref(), str(pw), root, "monitor", out)
        assert result == root

    def test_discovery_when_nothing(self, tmp_path):
        pw = tmp_path / "pw"
        pw.mkdir()
        out = str(tmp_path / "eff.yml")
        result = resolve("", self._ref(), str(pw), str(tmp_path / "network-policy.yml"), "monitor", out)
        assert result == ""
