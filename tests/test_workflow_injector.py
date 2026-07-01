"""Tests for the workflow injector."""

import textwrap
from pathlib import Path

import pytest
import yaml

from scripts.workflow_injector import NFW_INIT_STEP, inject_init_step


@pytest.fixture
def tmp_workflow(tmp_path):
    """Helper to write a workflow YAML and return its path."""
    def _write(content: str) -> str:
        p = tmp_path / "workflow.yml"
        p.write_text(content)
        return str(p)
    return _write


class TestInjectInitStep:
    def test_injects_after_checkout(self, tmp_workflow, tmp_path):
        wf = tmp_workflow(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - run: echo hello
        """))
        out = str(tmp_path / "out.yml")
        job = inject_init_step(wf, out)
        assert job == "build"

        with open(out) as f:
            result = yaml.safe_load(f)
        steps = result["jobs"]["build"]["steps"]
        assert steps[0]["uses"] == "actions/checkout@v4"
        assert steps[1]["name"] == "NFW: Setup monitoring"
        assert "ip route" in steps[1]["run"]
        assert steps[2]["run"] == "echo hello"

    def test_injects_at_beginning_without_checkout(self, tmp_workflow, tmp_path):
        wf = tmp_workflow(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """))
        out = str(tmp_path / "out.yml")
        inject_init_step(wf, out)

        with open(out) as f:
            result = yaml.safe_load(f)
        steps = result["jobs"]["test"]["steps"]
        assert steps[0]["name"] == "NFW: Setup monitoring"
        assert steps[1]["run"] == "echo hello"

    def test_preserves_on_key(self, tmp_workflow, tmp_path):
        wf = tmp_workflow(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """))
        out = str(tmp_path / "out.yml")
        inject_init_step(wf, out)

        text = Path(out).read_text()
        assert "\non:" in text or text.startswith("on:")
        assert "true:" not in text

    def test_preserves_uses_actions(self, tmp_workflow, tmp_path):
        wf = tmp_workflow(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-node@v4
                    with:
                      node-version: '20'
                  - run: npm test
        """))
        out = str(tmp_path / "out.yml")
        inject_init_step(wf, out)

        with open(out) as f:
            result = yaml.safe_load(f)
        steps = result["jobs"]["build"]["steps"]
        # checkout, NFW init, setup-node, npm test
        assert len(steps) == 4
        assert steps[2]["uses"] == "actions/setup-node@v4"

    def test_init_step_has_ca_trust(self):
        assert "ca.pem" in NFW_INIT_STEP["run"]
        assert "update-ca-certificates" in NFW_INIT_STEP["run"]

    def test_init_step_has_route_switching(self):
        assert "ip route del default" in NFW_INIT_STEP["run"]
        assert "ip route add default" in NFW_INIT_STEP["run"]
        assert "PROXY_GATEWAY" in NFW_INIT_STEP["run"]

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            inject_init_step("/nonexistent/workflow.yml", "/tmp/out.yml")

    def test_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text(": invalid: yaml: {{")
        with pytest.raises(ValueError, match="Invalid YAML"):
            inject_init_step(str(p), str(tmp_path / "out.yml"))

    def test_missing_jobs_raises(self, tmp_workflow, tmp_path):
        wf = tmp_workflow("name: CI\non: push\n")
        with pytest.raises(ValueError, match="missing 'jobs'"):
            inject_init_step(wf, str(tmp_path / "out.yml"))

    def test_uses_first_job(self, tmp_workflow, tmp_path):
        wf = tmp_workflow(textwrap.dedent("""\
            name: CI
            on: push
            jobs:
              lint:
                runs-on: ubuntu-latest
                steps:
                  - run: echo lint
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo build
        """))
        out = str(tmp_path / "out.yml")
        job = inject_init_step(wf, out)
        assert job == "lint"

        with open(out) as f:
            result = yaml.safe_load(f)
        # Only first job gets the init step
        lint_steps = result["jobs"]["lint"]["steps"]
        build_steps = result["jobs"]["build"]["steps"]
        assert lint_steps[0]["name"] == "NFW: Setup monitoring"
        assert build_steps[0]["run"] == "echo build"
