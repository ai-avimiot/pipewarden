#!/usr/bin/env python3
"""Iptables rule generation for the native transparent proxy mode.

Generates iptables command argument lists for NAT OUTPUT redirect rules,
OUTPUT LOG rules, and flush/cleanup commands. Pure functions with no
side effects — returns lists of string arguments for subprocess calls.
"""

_REDIRECT_PORTS = [443, 80]


def generate_nat_rules(proxy_port: int, username: str) -> list[list[str]]:
    """Generate iptables NAT OUTPUT redirect rules.

    Args:
        proxy_port: The proxy listening port (1–65535).
        username: System user running the proxy, excluded from redirect.

    Returns:
        List of iptables command argument lists — one rule per
        destination port (443, 80) redirecting to proxy_port,
        excluding traffic from username.

    Raises:
        ValueError: If proxy_port is outside 1–65535 or username is empty.
    """
    if not isinstance(proxy_port, int) or not (1 <= proxy_port <= 65535):
        raise ValueError(f"proxy_port must be between 1 and 65535, got {proxy_port}")
    if not username or not username.strip():
        raise ValueError("username must be a non-empty string")

    rules: list[list[str]] = []
    for dport in _REDIRECT_PORTS:
        rules.append([
            "iptables", "-t", "nat", "-A", "OUTPUT",
            "-p", "tcp",
            "-m", "owner", "!", "--uid-owner", username,
            "--dport", str(dport),
            "-j", "REDIRECT", "--to-port", str(proxy_port),
        ])
    return rules


def generate_log_rules() -> list[list[str]]:
    """Generate iptables OUTPUT LOG rules for connection visibility.

    Returns:
        List containing a single iptables command argument list that
        logs all new outbound connections with the ``NFW-CONN: ``
        prefix and ``--log-uid`` flag.
    """
    return [
        [
            "iptables", "-A", "OUTPUT",
            "-m", "conntrack", "--ctstate", "NEW",
            "-j", "LOG",
            "--log-prefix", "NFW-CONN: ", "--log-uid",
        ],
    ]


def generate_flush_commands(proxy_port: int, username: str) -> list[list[str]]:
    """Generate iptables commands to clean up all NFW rules.

    Deletes only the specific rules added by NFW, leaving any other
    rules in the chain untouched.

    Args:
        proxy_port: The proxy listening port used when the rules were added.
        username: System user running the proxy that was excluded from redirect.

    Returns:
        List of iptables command argument lists to:
        1. Delete each NAT OUTPUT redirect rule added by NFW (one per port).
        2. Delete the LOG rule from the OUTPUT chain.

    Raises:
        ValueError: If proxy_port is outside 1–65535 or username is empty.
    """
    if not isinstance(proxy_port, int) or not (1 <= proxy_port <= 65535):
        raise ValueError(f"proxy_port must be between 1 and 65535, got {proxy_port}")
    if not username or not username.strip():
        raise ValueError("username must be a non-empty string")

    cmds: list[list[str]] = []
    for dport in _REDIRECT_PORTS:
        cmds.append([
            "iptables", "-t", "nat", "-D", "OUTPUT",
            "-p", "tcp",
            "-m", "owner", "!", "--uid-owner", username,
            "--dport", str(dport),
            "-j", "REDIRECT", "--to-port", str(proxy_port),
        ])
    cmds.append([
        "iptables", "-D", "OUTPUT",
        "-m", "conntrack", "--ctstate", "NEW",
        "-j", "LOG",
        "--log-prefix", "NFW-CONN: ", "--log-uid",
    ])
    return cmds
