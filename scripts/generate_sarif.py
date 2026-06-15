#!/usr/bin/env python3
"""Generate SARIF 2.1.0 output from NFW report for GitHub Security tab.

Converts blocked/would-block connections and TLS certificate warnings
into SARIF code scanning alerts that appear under Security > Code scanning.
"""

import json
import os

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "pipewarden"
TOOL_URL = "https://github.com/ai-avimiot/pipewarden"

# Rule definitions
RULES = [
    {
        "id": "NFW-001",
        "shortDescription": {"text": "Blocked outbound connection"},
        "fullDescription": {
            "text": "A CI/CD build step made an outbound connection to a "
                    "destination not in the network policy allowlist. In enforce "
                    "mode this connection was blocked; in monitor mode it was "
                    "flagged as would_block."
        },
        "help": {
            "text": "Add the destination to your network-policy.yml if it is "
                    "expected, or investigate the source of the connection.",
            "markdown": "Add the destination to your `network-policy.yml` if "
                        "it is expected, or investigate the source of the "
                        "connection."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "security-severity": "8.0",
            "tags": ["security", "supply-chain", "network"],
        },
    },
    {
        "id": "NFW-002",
        "shortDescription": {"text": "Untrusted TLS certificate"},
        "fullDescription": {
            "text": "An HTTPS connection used a TLS certificate that is not "
                    "trusted by the system trust store (self-signed or issued "
                    "by an unknown CA). This may indicate a man-in-the-middle "
                    "attack or misconfigured server."
        },
        "help": {
            "text": "Verify the server's TLS certificate. Self-signed "
                    "certificates in CI/CD traffic are suspicious.",
            "markdown": "Verify the server's TLS certificate. Self-signed "
                        "certificates in CI/CD traffic are suspicious."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "security-severity": "6.0",
            "tags": ["security", "tls", "network"],
        },
    },
]

RULE_INDEX = {r["id"]: i for i, r in enumerate(RULES)}


def generate_sarif(report: dict, policy_file: str = "network-policy.yml") -> dict:
    """Convert an NFW report dict to a SARIF 2.1.0 document.

    Args:
        report: Report dict from generate_report.build_report().
        policy_file: Path to the network policy file (used as the
            artifact location for findings).

    Returns:
        A SARIF 2.1.0 dict ready to be serialized to JSON.
    """
    results = []

    # Blocked / would-block connections (grouped by destination)
    destinations = report.get("access_summary", {}).get("destinations", [])
    for dest in destinations:
        statuses = dest.get("statuses", {})
        blocked = statuses.get("blocked", 0) + statuses.get("would_block", 0)
        if blocked == 0:
            continue

        host = dest.get("host", "unknown")
        port = dest.get("port", 0)
        proto = dest.get("protocol", "tcp")
        count = blocked
        ip_info = dest.get("ip_info", {})
        owner = ip_info.get("owner", "")

        owner_str = f" ({owner})" if owner else ""
        status_word = "blocked" if "blocked" in statuses else "would be blocked"

        results.append({
            "ruleId": "NFW-001",
            "ruleIndex": RULE_INDEX["NFW-001"],
            "level": "error",
            "message": {
                "text": f"[{proto}] {host}:{port} — {count}x {status_word}{owner_str}",
            },
            "locations": [_make_location(policy_file)],
            "partialFingerprints": {
                "primaryLocationLineHash": f"nfw-blocked-{host}-{port}",
            },
        })

    # DNS blocked queries
    dns_queries = report.get("dns_summary", {}).get("queries", [])
    for q in dns_queries:
        status = q.get("status", "allowed")
        if status not in ("blocked", "would_block"):
            continue

        host = q.get("host", "unknown")
        count = q.get("count", 1)
        status_word = "blocked" if status == "blocked" else "would be blocked"

        results.append({
            "ruleId": "NFW-001",
            "ruleIndex": RULE_INDEX["NFW-001"],
            "level": "error",
            "message": {
                "text": f"[dns] {host}:53 — {count}x {status_word}",
            },
            "locations": [_make_location(policy_file)],
            "partialFingerprints": {
                "primaryLocationLineHash": f"nfw-blocked-dns-{host}",
            },
        })

    # TLS certificate warnings
    cert_warnings = report.get("access_summary", {}).get("tls_cert_warnings", [])
    for w in cert_warnings:
        host = w.get("host", "unknown")
        port = w.get("port", 443)
        error = w.get("tls_cert_error", "untrusted certificate")

        results.append({
            "ruleId": "NFW-002",
            "ruleIndex": RULE_INDEX["NFW-002"],
            "level": "warning",
            "message": {
                "text": f"{host}:{port} — {error}",
            },
            "locations": [_make_location(policy_file)],
            "partialFingerprints": {
                "primaryLocationLineHash": f"nfw-cert-{host}-{port}",
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URL,
                        "rules": RULES,
                    },
                },
                "results": results,
            },
        ],
    }


def _make_location(policy_file: str) -> dict:
    """Build a SARIF physicalLocation pointing at the policy file."""
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": policy_file},
            "region": {"startLine": 1, "startColumn": 1},
        },
    }


def write_sarif(report: dict, output_path: str,
                policy_file: str = "network-policy.yml") -> str:
    """Generate SARIF from a report and write it to a file.

    Args:
        report: Report dict from build_report().
        output_path: Path to write the SARIF JSON file.
        policy_file: Path to the network policy file.

    Returns:
        The output path.
    """
    sarif = generate_sarif(report, policy_file)
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return output_path
