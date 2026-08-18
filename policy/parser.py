"""YAML policy file parser for PipeWarden."""

from pathlib import Path

import yaml

from policy.exfil import (
    DEFAULT_MAX_SCAN_BYTES,
    MIN_SECRET_LENGTH,
    VALID_DETECTORS,
    ExfilConfig,
)
from policy.exfil import VALID_MODES as VALID_EXFIL_MODES
from policy.models import Policy, PolicyRule

VALID_MODES = ("monitor", "enforce")
VALID_PROTOCOLS = ("http", "https", "tcp", "udp", "dns")

# v1 policies stay valid forever: they are committed in users' repositories and
# a major release is not a licence to break files that still express exactly
# what their author meant. v2 adds the `exfiltration:` block and per-rule
# `allow_request_body`; a v1 policy simply parses with payload scanning off.
SUPPORTED_VERSIONS = ("1", "2")


def _parse_exfil(data: dict) -> ExfilConfig:
    """Parse the optional top-level ``exfiltration:`` block."""
    raw = data.get("exfiltration")
    if raw is None:
        return ExfilConfig()
    if not isinstance(raw, dict):
        raise ValueError("'exfiltration' must be a mapping")

    mode = raw.get("mode", "off")
    # YAML 1.1 resolves bare `off` (and on/yes/no) to a boolean, so a policy
    # written exactly as documented — `mode: off` — arrives here as False and
    # would be rejected with a baffling "Invalid exfiltration mode: 'False'".
    # Map it back to the word the author typed before validating.
    if isinstance(mode, bool):
        mode = "on" if mode else "off"
    if mode not in VALID_EXFIL_MODES:
        raise ValueError(
            f"Invalid exfiltration mode: '{mode}' "
            f"(expected one of {VALID_EXFIL_MODES})"
        )

    detectors = raw.get("detectors", ["env-secrets", "patterns"])
    if not isinstance(detectors, list):
        raise ValueError("'exfiltration.detectors' must be a list")
    for det in detectors:
        if det not in VALID_DETECTORS:
            raise ValueError(
                f"Invalid exfiltration detector: '{det}' "
                f"(expected one of {VALID_DETECTORS})"
            )

    max_scan_bytes = raw.get("max_scan_bytes", DEFAULT_MAX_SCAN_BYTES)
    # Strictly positive: 0 meant "unlimited" to the payload assembler and
    # "scan nothing" to the scanner, so the full cost of reading the body was
    # paid while zero bytes were inspected — under a policy claiming to block.
    if not isinstance(max_scan_bytes, int) or max_scan_bytes <= 0:
        raise ValueError(
            f"'exfiltration.max_scan_bytes' must be a positive integer, "
            f"got {max_scan_bytes!r}"
        )

    scan_headers = raw.get("scan_headers", False)
    if not isinstance(scan_headers, bool):
        raise ValueError(
            f"'exfiltration.scan_headers' must be a boolean, got {scan_headers!r}"
        )

    watch_env = raw.get("watch_env", [])
    if not isinstance(watch_env, list):
        raise ValueError("'exfiltration.watch_env' must be a list")
    for name in watch_env:
        if not isinstance(name, str) or not name:
            raise ValueError(
                f"'exfiltration.watch_env' entries must be non-empty environment "
                f"variable names, got {name!r}"
            )

    min_secret_length = raw.get("min_secret_length", MIN_SECRET_LENGTH)
    if not isinstance(min_secret_length, int) or min_secret_length < 1:
        raise ValueError(
            f"'exfiltration.min_secret_length' must be a positive integer, "
            f"got {min_secret_length!r}"
        )

    return ExfilConfig(
        mode=mode,
        detectors=detectors,
        max_scan_bytes=max_scan_bytes,
        watch_env=watch_env,
        min_secret_length=min_secret_length,
        scan_headers=scan_headers,
    )


def parse_policy(content: str) -> Policy:
    """Parse a YAML policy string into a full :class:`Policy`.

    Use this when the ``exfiltration:`` settings matter. ``parse_policy_string``
    remains the right call for the (mode, rules) pair alone.

    Raises:
        ValueError: If the policy content is invalid.
    """
    mode, rules = parse_policy_string(content)
    # parse_policy_string has already validated the exfiltration block (and
    # refused it under v1); re-loading here is cheap next to the proxy's
    # per-request work, and it keeps the tuple-returning function the single
    # place all validation lives.
    data = yaml.safe_load(content)
    return Policy(mode=mode, rules=rules, exfil=_parse_exfil(data))


def parse_policy_file_full(path: str) -> Policy:
    """Read *path* and parse it into a full :class:`Policy`."""
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    return parse_policy(policy_path.read_text(encoding="utf-8"))


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
    if str(version) not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported policy version: '{version}' "
            f"(expected one of {SUPPORTED_VERSIONS})"
        )

    # Refused here — not in parse_policy — because THIS is the function the
    # addon, the DNS server and the report generator gate on. When the check
    # lived only in parse_policy, a v1 file carrying an exfiltration block
    # sailed through this path and the job ran green with scanning silently
    # off, the exact outcome the refusal exists to prevent: an author who
    # wrote the block believes they have a control they do not have.
    if "exfiltration" in data and str(version) == "1":
        raise ValueError(
            "'exfiltration' requires policy version 2 (found version 1)"
        )

    # Malformed exfiltration must also fail loudly on the gating path, not
    # just when the full Policy is requested: the proxy fails closed on a
    # ValueError from here, which is the correct response to a policy whose
    # scanning intent cannot be read.
    if str(version) == "2":
        _parse_exfil(data)

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
    seen_names: set[str] = set()
    for i, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Rule {i}: must be a mapping")

        name = raw_rule.get("name")
        if not name:
            raise ValueError(f"Rule {i}: missing required field 'name'")
        if not isinstance(name, str):
            raise ValueError(f"Rule {i}: 'name' must be a string, got {name!r}")
        if name in seen_names:
            raise ValueError(f"Rule {i}: duplicate rule name {name!r}")
        seen_names.add(name)

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
        for domain in domains:
            if not isinstance(domain, str) or not domain:
                raise ValueError(
                    f"Rule {i} ('{name}'): domain patterns must be non-empty "
                    f"strings, got {domain!r}"
                )

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

        allow_request_body = raw_rule.get("allow_request_body", False)
        if not isinstance(allow_request_body, bool):
            raise ValueError(
                f"Rule {i} ('{name}'): 'allow_request_body' must be a boolean, "
                f"got {allow_request_body!r}"
            )
        if allow_request_body and str(version) == "1":
            raise ValueError(
                f"Rule {i} ('{name}'): 'allow_request_body' requires policy "
                f"version 2"
            )

        rules.append(
            PolicyRule(
                name=name,
                domains=domains,
                ports=ports,
                protocols=protocols,
                paths=paths,
                appears=appears,
                allow_request_body=allow_request_body,
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
