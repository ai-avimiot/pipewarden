"""Tests for policy auto-resolution and merging."""

import yaml

from policy.parser import parse_policy_string
from scripts.resolve_policy import (
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
