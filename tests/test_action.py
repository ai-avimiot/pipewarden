"""Tests verifying action.yml structure and network-policy.yml validity."""

from pathlib import Path

import yaml

from policy.parser import parse_policy_file

ROOT = Path(__file__).resolve().parent.parent


class TestActionYml:
    """Verify the GitHub Action definition has the correct structure."""

    def setup_method(self):
        action_path = ROOT / "container" / "action.yml"
        assert action_path.exists(), "container/action.yml must exist"
        with open(action_path) as f:
            self.action = yaml.safe_load(f)

    def test_has_name_and_description(self):
        assert "name" in self.action
        assert "description" in self.action
        assert isinstance(self.action["name"], str)
        assert isinstance(self.action["description"], str)

    def test_required_inputs_exist(self):
        inputs = self.action.get("inputs", {})
        assert "policy-file" in inputs
        assert "mode" in inputs

    def test_workflow_file_is_optional(self):
        inp = self.action["inputs"]["workflow-file"]
        assert inp.get("required") is False

    def test_pipeline_command_is_optional(self):
        inp = self.action["inputs"]["pipeline-command"]
        assert inp.get("required") is False

    def test_optional_inputs_have_defaults(self):
        policy = self.action["inputs"]["policy-file"]
        assert policy.get("required") is False
        assert policy.get("default") == "network-policy.yml"

        mode = self.action["inputs"]["mode"]
        assert mode.get("required") is False
        assert mode.get("default") == "enforce"

    def test_outputs_exist(self):
        outputs = self.action.get("outputs", {})
        assert "report-path" in outputs
        assert "blocked-count" in outputs
        assert "status" in outputs

    def test_outputs_have_descriptions(self):
        for name, output in self.action["outputs"].items():
            assert "description" in output, f"Output '{name}' missing description"

    def test_runs_using_composite(self):
        runs = self.action.get("runs", {})
        assert runs.get("using") == "composite"

    def test_runs_has_steps(self):
        runs = self.action.get("runs", {})
        steps = runs.get("steps", [])
        assert len(steps) > 0, "Composite action must have at least one step"


class TestExampleNetworkPolicy:
    """Verify the example network-policy.yml is valid and parseable."""

    def test_policy_file_exists(self):
        policy_path = ROOT / "examples" / "network-policy.yml"
        assert policy_path.exists(), "examples/network-policy.yml must exist"

    def test_policy_parses_successfully(self):
        policy_path = ROOT / "examples" / "network-policy.yml"
        mode, rules = parse_policy_file(str(policy_path))
        assert mode in ("monitor", "enforce")
        assert len(rules) > 0

    def test_policy_rules_have_names(self):
        policy_path = ROOT / "examples" / "network-policy.yml"
        _, rules = parse_policy_file(str(policy_path))
        for rule in rules:
            assert rule.name, "Each rule must have a name"

    def test_policy_contains_expected_rules(self):
        policy_path = ROOT / "examples" / "network-policy.yml"
        _, rules = parse_policy_file(str(policy_path))
        rule_names = [r.name for r in rules]
        assert "npm registry" in rule_names
        assert "GitHub" in rule_names
        assert "DNS" in rule_names
