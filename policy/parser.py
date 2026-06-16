"""YAML policy file parser for PipeWarden."""

from pathlib import Path

import yaml

from policy.models import PolicyRule

VALID_MODES = ("monitor", "enforce")
VALID_PROTOCOLS = ("http", "https", "tcp", "udp", "dns")


def parse_policy_string(content: str) -> tuple[str, list[PolicyRule]]:
    """Parse a YAML policy string and return (mode, rules).

    Args:
        content: YAML string containing the policy configuration.

    Returns:
        A tuple of (mode, list[PolicyRule]).

    Raises:
        ValueError: If the policy content is invalid.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Policy must be a YAML mapping at the top level")

    # Validate version
    version = data.get("version")
    if version is None:
        raise ValueError("Missing required field: 'version'")
    if str(version) != "1":
        raise ValueError(f"Unsupported policy version: '{version}' (expected '1')")

    # Validate mode
    mode = data.get("mode")
    if mode is None:
        raise ValueError("Missing required field: 'mode'")
    if mode not in VALID_MODES:
        raise ValueError(
            f"Invalid mode: '{mode}' (expected one of {VALID_MODES})"
        )

    # Validate rules
    raw_rules = data.get("rules")
    if raw_rules is None:
        raise ValueError("Missing required field: 'rules'")
    if not isinstance(raw_rules, list):
        raise ValueError("'rules' must be a list")

    rules: list[PolicyRule] = []
    for i, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Rule {i}: must be a mapping")

        name = raw_rule.get("name")
        if not name:
            raise ValueError(f"Rule {i}: missing required field 'name'")

        appears = raw_rule.get("appears", "always")
        if appears not in ("always", "sometimes"):
            raise ValueError(
                f"Rule {i} ('{name}'): 'appears' must be 'always' or 'sometimes', "
                f"got {appears!r}"
            )

        allow = raw_rule.get("allow", {})
        if not isinstance(allow, dict):
            raise ValueError(f"Rule {i} ('{name}'): 'allow' must be a mapping")

        domains = allow.get("domains", [])
        if not isinstance(domains, list):
            raise ValueError(f"Rule {i} ('{name}'): 'domains' must be a list")

        ports = allow.get("ports", [])
        if not isinstance(ports, list):
            raise ValueError(f"Rule {i} ('{name}'): 'ports' must be a list")
        for p in ports:
            if not isinstance(p, int) or p < 1 or p > 65535:
                raise ValueError(
                    f"Rule {i} ('{name}'): invalid port {p!r} (must be integer 1-65535)"
                )

        protocols = allow.get("protocols", [])
        if not isinstance(protocols, list):
            raise ValueError(f"Rule {i} ('{name}'): 'protocols' must be a list")
        for proto in protocols:
            if proto not in VALID_PROTOCOLS:
                raise ValueError(
                    f"Rule {i} ('{name}'): invalid protocol '{proto}' "
                    f"(expected one of {VALID_PROTOCOLS})"
                )

        paths = allow.get("paths", [])
        if not isinstance(paths, list):
            raise ValueError(f"Rule {i} ('{name}'): 'paths' must be a list")
        for path in paths:
            if not isinstance(path, str):
                raise ValueError(
                    f"Rule {i} ('{name}'): path patterns must be strings"
                )

        rules.append(
            PolicyRule(
                name=name,
                domains=domains,
                ports=ports,
                protocols=protocols,
                paths=paths,
                appears=appears,
            )
        )

    return mode, rules


def parse_policy_file(path: str) -> tuple[str, list[PolicyRule]]:
    """Parse a YAML policy file and return (mode, rules).

    Args:
        path: Path to the YAML policy file.

    Returns:
        A tuple of (mode, list[PolicyRule]).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the policy content is invalid.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    content = policy_path.read_text(encoding="utf-8")
    return parse_policy_string(content)
