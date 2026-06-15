"""Inject NFW initialization step into a GitHub Actions workflow.

Reads a workflow YAML, prepends an NFW init step to the first job's steps
(after checkout if present), and writes the modified workflow for act to
execute.

The init step:
  1. Installs iproute2 if missing (skipped on the NFW runner image)
  2. Trusts the monitoring CA certificate
  3. Switches the default route to the proxy gateway

This is the only modification NFW makes — all other steps (including
uses: actions) are executed natively by act.

Usage:
    python scripts/workflow_injector.py input.yml --output /tmp/nfw-workflow.yml
"""

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml


# Custom YAML handling to preserve 'on' key (PyYAML treats it as boolean True)
class _Loader(yaml.SafeLoader):
    pass

# Override boolean resolution so 'on' stays as string 'on'
_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    # Only match true/false/yes/no — NOT 'on'/'off'
    __import__("re").compile(
        r"^(?:true|True|TRUE|false|False|FALSE|yes|Yes|YES|no|No|NO)$"
    ),
    list("tTfFyYnN"),
)


class _Dumper(yaml.SafeDumper):
    pass

# Prevent PyYAML from converting True back to 'true' for our 'on' key
def _str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)

_Dumper.add_representer(str, _str_representer)

# The NFW init step — prepended to the first job's steps.
# Installs minimal deps, trusts the CA, and switches the route.
NFW_INIT_STEP = {
    "name": "NFW: Setup monitoring",
    "run": (
        "SUDO=\"\"\n"
        "if [ \"$(id -u)\" != \"0\" ] && command -v sudo &>/dev/null; then\n"
        "  SUDO=sudo\n"
        "fi\n"
        "if ! command -v ip &>/dev/null; then\n"
        "  $SUDO apt-get update -qq > /dev/null 2>&1\n"
        "  $SUDO apt-get install -y -qq iproute2 > /dev/null 2>&1\n"
        "fi\n"
        "if [ -f /ca/ca.pem ]; then\n"
        "  $SUDO cp /ca/ca.pem /usr/local/share/ca-certificates/cicd-monitor.crt\n"
        "  $SUDO update-ca-certificates > /dev/null 2>&1 || true\n"
        "fi\n"
        "if [ -n \"${PROXY_GATEWAY:-}\" ]; then\n"
        "  $SUDO ip route del default 2>/dev/null || true\n"
        "  $SUDO ip route add default via \"${PROXY_GATEWAY}\"\n"
        "fi\n"
        "git config --global --add safe.directory '*' 2>/dev/null || true\n"
    ),
}


def inject_init_step(workflow_path: str, output_path: str) -> str:
    """Read a workflow YAML, inject NFW init step, write to output.

    Parameters
    ----------
    workflow_path:
        Path to the original GitHub Actions workflow YAML.
    output_path:
        Path to write the modified workflow YAML.

    Returns
    -------
    str
        The job name that was modified.
    """
    path = Path(workflow_path)
    if not path.exists():
        raise FileNotFoundError(f"Workflow file not found: {workflow_path}")

    with open(path) as fh:
        try:
            wf = yaml.load(fh, Loader=_Loader)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(wf, dict) or "jobs" not in wf:
        raise ValueError("Invalid workflow file: missing 'jobs' key")

    jobs = wf["jobs"]
    job_name = next(iter(jobs))
    job = jobs[job_name]

    steps = job.get("steps", [])

    # Prepend the NFW init step (after checkout if present)
    checkout_idx = -1
    for i, step in enumerate(steps):
        uses = step.get("uses", "")
        if uses.startswith("actions/checkout"):
            checkout_idx = i
            break

    init_step = copy.deepcopy(NFW_INIT_STEP)
    if checkout_idx >= 0:
        # Insert after checkout
        steps.insert(checkout_idx + 1, init_step)
    else:
        # Insert at the beginning
        steps.insert(0, init_step)

    job["steps"] = steps

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Dump to string, then fix PyYAML's 'on' → 'true' boolean conversion
    text = yaml.dump(wf, Dumper=_Dumper, default_flow_style=False, sort_keys=False)
    # PyYAML converts the 'on:' key to 'true:' — fix it back
    text = re.sub(r'^true:', 'on:', text, count=1)
    if not text.startswith('on:'):
        text = re.sub(r'\ntrue:', '\non:', text, count=1)

    out.write_text(text)

    return job_name


def main():
    parser = argparse.ArgumentParser(
        description="Inject NFW init step into a GitHub Actions workflow"
    )
    parser.add_argument("workflow", help="Path to workflow YAML file")
    parser.add_argument("--output", required=True, help="Output path for modified workflow")
    args = parser.parse_args()

    try:
        job_name = inject_init_step(args.workflow, args.output)
        print(f"Injected NFW init step into job '{job_name}' → {args.output}")
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
