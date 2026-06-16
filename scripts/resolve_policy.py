#!/usr/bin/env python3
"""Resolve and merge the effective network policy for a run.

Auto-resolution (used when no explicit policy-file is given):

  1. .github/pipewarden/common.network-policy.yml      (shared baseline)
  2. .github/pipewarden/<workflow>.network-policy.yml   (pipeline-specific)

All that exist are merged (union of rules; same-name rules from the
pipeline file override the common one) into a single effective policy file.
Fallbacks: repo-root network-policy.yml, then discovery mode (no policy).

The action's ``mode`` governs enforce/monitor; the merged file's ``mode`` is
set from ``--mode``. The resolved policy path is printed to stdout (an empty
line means discovery mode); human-readable details go to stderr.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.parser import parse_policy_file  # noqa: E402

PIPEWARDEN_DIR = ".github/pipewarden"
COMMON_NAME = "common.network-policy.yml"


def workflow_stem(workflow_ref: str) -> str:
    """Extract the workflow file stem from GITHUB_WORKFLOW_REF.

    ``owner/repo/.github/workflows/ci.yml@refs/heads/main`` -> ``ci``
    Returns "" when no usable stem can be derived.
    """
    if not workflow_ref:
        return ""
    path = workflow_ref.split("@", 1)[0]
    marker = "/.github/workflows/"
    if marker in path:
        path = path.split(marker, 1)[1]
    base = os.path.basename(path)
    for ext in (".yml", ".yaml"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def pipeline_policy_name(stem: str) -> str:
    """The per-pipeline policy filename for a workflow stem."""
    return f"{stem}.network-policy.yml"


def _rule_to_yaml(rule) -> dict:
    """Serialize a PolicyRule back to the YAML rule shape."""
    allow: dict = {}
    if rule.domains:
        allow["domains"] = list(rule.domains)
    if rule.ports:
        allow["ports"] = list(rule.ports)
    if rule.protocols:
        allow["protocols"] = list(rule.protocols)
    if rule.paths:
        allow["paths"] = list(rule.paths)
    out: dict = {"name": rule.name}
    if getattr(rule, "appears", "always") != "always":
        out["appears"] = rule.appears
    out["allow"] = allow
    return out


def merge_policies(paths: list[str], mode: str) -> dict:
    """Parse and union rules from ``paths`` (later files override same-name)."""
    merged: dict[str, object] = {}
    order: list[str] = []
    for p in paths:
        _, rules = parse_policy_file(p)
        for r in rules:
            if r.name not in merged:
                order.append(r.name)
            merged[r.name] = r
    return {
        "version": "1",
        "mode": mode,
        "rules": [_rule_to_yaml(merged[n]) for n in order],
    }


def resolve(explicit: str, workflow_ref: str, pipewarden_dir: str,
            root_policy: str, mode: str, out: str) -> str:
    """Return the effective policy path ("" = discovery mode)."""
    # An explicit policy-file always wins.
    if explicit:
        if os.path.isfile(explicit):
            print(f"Using explicit policy-file: {explicit}", file=sys.stderr)
            return explicit
        print(f"policy-file '{explicit}' not found — discovery mode", file=sys.stderr)
        return ""

    stem = workflow_stem(workflow_ref)
    common = os.path.join(pipewarden_dir, COMMON_NAME)
    pipeline = (
        os.path.join(pipewarden_dir, pipeline_policy_name(stem)) if stem else ""
    )

    candidates: list[str] = []
    if os.path.isfile(common):
        candidates.append(common)
    if pipeline and os.path.isfile(pipeline):
        candidates.append(pipeline)

    if candidates:
        import yaml
        merged = merge_policies(candidates, mode)
        with open(out, "w") as f:
            yaml.safe_dump(merged, f, sort_keys=False)
        print(f"Merged policy from {', '.join(candidates)} -> {out}", file=sys.stderr)
        return out

    if os.path.isfile(root_policy):
        print(f"Using repo-root policy: {root_policy}", file=sys.stderr)
        return root_policy

    looked = [common] + ([pipeline] if pipeline else []) + [root_policy]
    print(
        "No policy found (looked for: " + ", ".join(looked) + ") — discovery mode",
        file=sys.stderr,
    )
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--explicit", default="", help="Explicit policy-file path (overrides auto-resolve)")
    ap.add_argument("--workflow-ref", default=os.environ.get("GITHUB_WORKFLOW_REF", ""))
    ap.add_argument("--pipewarden-dir", default=PIPEWARDEN_DIR)
    ap.add_argument("--root-policy", default="network-policy.yml")
    ap.add_argument("--mode", default="monitor")
    ap.add_argument("--out", default="/tmp/pipewarden-effective-policy.yml")
    args = ap.parse_args()
    resolved = resolve(
        args.explicit, args.workflow_ref, args.pipewarden_dir,
        args.root_policy, args.mode, args.out,
    )
    print(resolved)


if __name__ == "__main__":
    main()
