#!/usr/bin/env python3
"""Report generator for PipeWarden.

Reads a JSONL connection log and produces:
- report.json  - machine-readable full report
- summary.txt  - human-readable summary for CI logs
- summary.md   - GitHub Job Summary (Markdown)

When --policy is provided, also runs dry-run analysis:
compares actual traffic against allowlist rules, finds unused rules,
and generates copy-paste YAML for blocked destinations.
"""

import argparse
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def read_jsonl(input_path: str) -> list[dict]:
    """Read a JSONL file and return a list of connection dicts."""
    connections: list[dict] = []
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                connections.append(json.loads(line))
    return connections


def build_report(connections: list[dict]) -> dict:
    """Build a report dict from a list of connection dicts."""
    # Separate DNS queries from other connections for counting
    non_dns = [c for c in connections if c.get("protocol") != "dns"]
    dns_queries = [c for c in connections if c.get("protocol") == "dns"]

    return {
        "total_connections": len(non_dns),
        "allowed_connections": sum(
            1 for c in non_dns if c.get("status") == "allowed"
        ),
        "blocked_connections": sum(
            1 for c in non_dns
            if c.get("status") in ("blocked", "would_block")
        ),
        "dns_queries": len(dns_queries),
        "access_summary": _build_access_summary(non_dns),
        "dns_summary": _build_dns_summary(dns_queries),
        "connections": connections,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _format_bytes(n: int) -> str:
    """Format byte count as a human-readable string."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def _build_access_summary(connections: list[dict]) -> dict:
    """Build a per-domain access summary with TLS certificate info and data amounts."""
    domains: dict[str, dict] = {}
    total_bytes = 0
    for c in connections:
        host = c.get("host", "unknown")
        port = c.get("port", 0)
        key = f"{host}:{port}"
        if key not in domains:
            domains[key] = {
                "host": host, "port": port,
                "protocol": c.get("protocol", ""),
                "count": 0, "bytes_transferred": 0, "statuses": {},
            }
        entry = domains[key]
        entry["count"] += 1
        b = c.get("bytes_transferred", 0)
        entry["bytes_transferred"] += b
        total_bytes += b
        status = c.get("status", "unknown")
        entry["statuses"][status] = entry["statuses"].get(status, 0) + 1
        sni = c.get("tls_sni", "")
        if sni and "tls_sni" not in entry:
            entry["tls_sni"] = sni
        issuer = c.get("tls_cert_issuer", "")
        if issuer and "tls_cert_issuer" not in entry:
            entry["tls_cert_issuer"] = issuer
        if c.get("tls_cert_valid") is False:
            entry["tls_cert_valid"] = False
            entry["tls_cert_error"] = c.get("tls_cert_error", "")
        sip = c.get("server_ip", "")
        if sip and "server_ip" not in entry:
            entry["server_ip"] = sip
    cert_warnings = [
        e for e in domains.values() if e.get("tls_cert_valid") is False
    ]
    return {
        "unique_destinations": len(domains),
        "total_bytes": total_bytes,
        "destinations": list(domains.values()),
        "tls_cert_warnings": cert_warnings,
    }


def _is_ip(host: str) -> bool:
    """Check if a host string looks like an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _build_dns_summary(dns_queries: list[dict]) -> dict:
    """Build a summary of DNS queries with resolved IPs."""
    domains: dict[str, dict] = {}
    for q in dns_queries:
        host = q.get("host", "")
        if not host:
            continue
        if host not in domains:
            domains[host] = {
                "host": host,
                "query_type": q.get("method", "A"),
                "count": 0,
                "status": q.get("status", "allowed"),
                "resolved_ips": [],
            }
        domains[host]["count"] += 1
        for ip in q.get("dns_resolved_ips", []):
            if ip not in domains[host]["resolved_ips"]:
                domains[host]["resolved_ips"].append(ip)
        # Track worst status
        s = q.get("status", "allowed")
        if s in ("blocked", "would_block"):
            domains[host]["status"] = s

    return {
        "total_queries": len(dns_queries),
        "unique_domains": len(domains),
        "queries": list(domains.values()),
    }


def _enrich_destinations(report: dict) -> None:
    """Enrich access summary destinations with IP ownership info."""
    try:
        from scripts.ip_enrichment import enrich_ips
    except ImportError:
        try:
            from ip_enrichment import enrich_ips
        except ImportError:
            logger.debug("ip_enrichment module not available, skipping")
            return
    access = report.get("access_summary", {})
    destinations = access.get("destinations", [])

    # Build IP→domain map from DNS query logs (most reliable source)
    dns_ip_to_domain: dict[str, str] = {}
    for c in report.get("connections", []):
        if c.get("protocol") == "dns":
            domain = c.get("host", "")
            for ip in c.get("dns_resolved_ips", []):
                if ip and domain:
                    dns_ip_to_domain[ip] = domain

    host_to_ip: dict[str, str] = {}
    for c in report.get("connections", []):
        host = c.get("host", "")
        ip = c.get("server_ip", "")
        if host and ip and host not in host_to_ip:
            host_to_ip[host] = ip
    ips_to_lookup: set[str] = set()
    for dest in destinations:
        ip = dest.get("server_ip", "") or host_to_ip.get(dest.get("host", ""), "")
        if ip:
            ips_to_lookup.add(ip)
        host = dest.get("host", "")
        if _is_ip(host):
            ips_to_lookup.add(host)
    for c in report.get("connections", []):
        ip = c.get("server_ip", "")
        if ip:
            ips_to_lookup.add(ip)
    import socket
    for dest in destinations:
        host = dest.get("host", "")
        if host and not _is_ip(host) and host not in host_to_ip:
            try:
                resolved_ip = socket.gethostbyname(host)
                host_to_ip[host] = resolved_ip
                ips_to_lookup.add(resolved_ip)
            except (socket.gaierror, socket.herror, OSError):
                pass
    if not ips_to_lookup:
        return
    ip_info = enrich_ips(list(ips_to_lookup))
    for dest in destinations:
        host = dest.get("host", "")
        ip = dest.get("server_ip", "") or host_to_ip.get(host, "")
        if _is_ip(host):
            ip = host
        if ip and ip in ip_info:
            dest["ip_info"] = ip_info[ip]
            if not dest.get("server_ip"):
                dest["server_ip"] = ip
            # When the host is a raw IP, resolve a friendly name.
            # Prefer DNS query log (exact forward lookup) over reverse DNS.
            if _is_ip(host):
                dns_domain = dns_ip_to_domain.get(host, "")
                rdns = ip_info[ip].get("reverse_dns", "")
                dest["reverse_dns"] = dns_domain or rdns


def _run_policy_analysis(policy_path, connections, report):
    """Run policy analysis and return the result dict."""
    import sys

    # Ensure the project root is on sys.path so that `policy.*` and
    # `scripts.*` packages can be imported regardless of how this script
    # was invoked (e.g. `python3 scripts/generate_report.py`).
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    try:
        from policy.parser import parse_policy_file
    except ImportError as e:
        print(f"[policy-analysis] policy.parser not available: {e}", file=sys.stderr)
        return {}
    try:
        from scripts.policy_analysis import analyze_policy
    except ImportError:
        try:
            from policy_analysis import analyze_policy
        except ImportError as e:
            print(f"[policy-analysis] policy_analysis not available: {e}", file=sys.stderr)
            return {}
    try:
        _mode, rules = parse_policy_file(policy_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"[policy-analysis] Could not parse policy file '{policy_path}': {e}", file=sys.stderr)
        return {}
    destinations = list(report.get("access_summary", {}).get("destinations", []))

    # Merge blocked DNS queries into destinations so they appear in the
    # "Needed allowlist" alongside regular traffic.  DNS is treated the
    # same as HTTP/TCP — one unified list.
    dns_queries = report.get("dns_summary", {}).get("queries", [])
    # Collect domains already present in destinations to avoid duplicates
    existing_hosts = {d["host"] for d in destinations}
    for q in dns_queries:
        host = q.get("host", "")
        status = q.get("status", "allowed")
        if not host or status == "allowed":
            continue
        # Strip DNS-SD prefixes for dedup (e.g. _http._tcp.example.com)
        clean = host
        while clean.startswith("_"):
            dot = clean.find(".")
            if dot < 0:
                break
            clean = clean[dot + 1:]
        if clean in existing_hosts:
            continue
        destinations.append({
            "host": clean,
            "port": 53,
            "protocol": "dns",
            "count": q.get("count", 1),
            "statuses": {status: q.get("count", 1)},
        })
        existing_hosts.add(clean)

    return analyze_policy(rules, connections, destinations)


def _time_range(connections: list[dict]) -> str:
    """Return a short time range string from a list of connections."""
    timestamps = [c.get("timestamp", "") for c in connections if c.get("timestamp")]
    if not timestamps:
        return "\u2014"
    timestamps.sort()
    first = timestamps[0]
    last = timestamps[-1]
    first_short = first[11:19] if len(first) >= 19 else first
    last_short = last[11:19] if len(last) >= 19 else last
    if first_short == last_short:
        return first_short
    return f"{first_short}\u2013{last_short}"


def _group_blocked(connections: list[dict]) -> dict[str, dict]:
    """Group blocked connections by host:port with count and time range."""
    groups: dict[str, dict] = {}
    for c in connections:
        host = c.get("host", "?")
        port = c.get("port", "?")
        key = f"{host}:{port}"
        if key not in groups:
            groups[key] = {"protocol": c.get("protocol", "?"), "count": 0, "timestamps": []}
        groups[key]["count"] += 1
        ts = c.get("timestamp", "")
        if ts:
            groups[key]["timestamps"].append(ts)
    for info in groups.values():
        info["time_range"] = _time_range([{"timestamp": t} for t in info["timestamps"]])
        del info["timestamps"]
    return groups


def _dest_display_name(dest: dict) -> str:
    """Return a friendly display name for a destination.

    For IP-only hosts, uses reverse DNS when available
    (e.g. 185.125.190.81 → archive.ubuntu.com).
    """
    host = dest.get("host", "unknown")
    rdns = dest.get("reverse_dns", "")
    if rdns and _is_ip(host):
        return f"{rdns} ({host})"
    return host


def format_summary(report: dict) -> str:
    """Format a human-readable summary from a report dict."""
    run_mode = report.get("run_mode", "monitor")
    blocked = report.get("blocked_connections", 0)
    if run_mode == "enforce":
        banner = "Mode: ENFORCE \u2014 connections outside the policy are blocked; the workflow fails on violations."
    else:
        extra = f" ({blocked} would-be-blocked)" if blocked else ""
        banner = f"Mode: MONITOR \u2014 observing only, nothing was blocked{extra}."
    lines = [
        "PipeWarden \u2014 Connection Report",
        "=" * 44,
        f"Generated at: {report['generated_at']}",
        banner,
        "",
        f"Total connections:   {report['total_connections']}",
        f"Allowed connections: {report['allowed_connections']}",
        f"Blocked connections: {report['blocked_connections']}",
        f"DNS queries:         {report.get('dns_queries', 0)}",
        "",
    ]
    if report.get("discovery"):
        cp = report.get("commit_path") or "network-policy.yml"
        lines += [
            "TIP: PipeWarden generated a network policy from this run. Download the",
            "     'network-report' artifact, review its network-policy.yml, and commit it to",
            f"     {cp} \u2014 then set mode: enforce.",
            "",
        ]

    access = report.get("access_summary", {})
    destinations = access.get("destinations", [])
    total_bytes = access.get("total_bytes", 0)
    if destinations:
        lines.append(f"Unique destinations: {access.get('unique_destinations', 0)}")
        lines.append(f"Total data transferred: {_format_bytes(total_bytes)}")
        lines.append("-" * 60)
        for dest in sorted(destinations, key=lambda d: d["count"], reverse=True):
            display = _dest_display_name(dest)
            host_port = f"{display}:{dest['port']}"
            proto = dest.get("protocol", "?")
            statuses = dest.get("statuses", {})
            status_parts = []
            for s, n in sorted(statuses.items()):
                icon = "\u2705" if s == "allowed" else "\U0001f6ab" if s in ("blocked", "would_block") else ""
                status_parts.append(f"{icon}{s}={n}")
            status_str = ", ".join(status_parts)
            dest_bytes = dest.get("bytes_transferred", 0)
            line = f"  [{proto}] {host_port} ({dest['count']}x, {_format_bytes(dest_bytes)}) \u2014 {status_str}"
            issuer = dest.get("tls_cert_issuer", "")
            if issuer:
                line += f"  [CA: {issuer}]"
            ip_info = dest.get("ip_info", {})
            owner = ip_info.get("owner", "")
            if owner:
                country = ip_info.get("country", "")
                tag = f"{owner} ({country})" if country else owner
                line += f"  [{tag}]"
            if dest.get("tls_cert_valid") is False:
                line += f"  \u26a0 UNTRUSTED: {dest.get('tls_cert_error', '')}"
            lines.append(line)
        lines.append("")

    cert_warnings = access.get("tls_cert_warnings", [])
    if cert_warnings:
        lines.append("\u26a0 TLS Certificate Warnings:")
        lines.append("-" * 40)
        for w in cert_warnings:
            lines.append(f"  {w['host']}:{w['port']} \u2014 {w.get('tls_cert_error', 'untrusted')}")
        lines.append("")

    blocked = [c for c in report["connections"] if c.get("status") in ("blocked", "would_block")]
    if blocked:
        lines.append(f"Blocked connections ({len(blocked)}, {_time_range(blocked)}):")
        lines.append("-" * 40)
        grouped = _group_blocked(blocked)
        for key, info in sorted(grouped.items(), key=lambda x: x[1]["count"], reverse=True):
            lines.append(f"  [{info['protocol']}] {key} \u2014 {info['count']}x ({info['time_range']})")
        lines.append("")

    analysis = report.get("policy_analysis", {})
    if analysis:
        _format_policy_analysis_text(lines, analysis)

    dns_summary = report.get("dns_summary", {})
    dns_queries = dns_summary.get("queries", [])
    if dns_queries:
        lines.append(f"DNS queries ({dns_summary.get('total_queries', 0)} total, {dns_summary.get('unique_domains', 0)} unique domains):")
        lines.append("-" * 40)
        for q in sorted(dns_queries, key=lambda d: d["count"], reverse=True):
            icon = "\u2705" if q["status"] == "allowed" else "\U0001f6ab"
            ips = ", ".join(q["resolved_ips"][:3])
            if len(q["resolved_ips"]) > 3:
                ips += f" (+{len(q['resolved_ips']) - 3})"
            ip_str = f" \u2192 {ips}" if ips else ""
            lines.append(f"  {icon} {q['host']} ({q['count']}x, {q['query_type']}){ip_str}")
        lines.append("")

    return "\n".join(lines) + "\n"


def _format_policy_analysis_text(lines: list[str], analysis: dict) -> None:
    """Append policy analysis sections to text summary lines."""
    rule_usage = analysis.get("rule_usage", [])
    suggested_yaml = analysis.get("suggested_yaml", "")

    if rule_usage:
        used = sum(1 for r in rule_usage if r["match_count"] > 0)
        total = len(rule_usage)
        lines.append(f"Policy rules ({used}/{total} used):")
        lines.append("-" * 40)
        for ru in rule_usage:
            if ru["match_count"] > 0:
                icon, note = "\u2705", ""
            elif ru.get("appears", "always") == "sometimes":
                icon, note = "\u26aa", "  (appears sometimes; not seen this run)"
            else:
                icon, note = "\u26aa", "  (unused; candidate for removal)"
            doms = ", ".join(ru.get("domains", [])[:4])
            if len(ru.get("domains", [])) > 4:
                doms += f" (+{len(ru['domains']) - 4})"
            hosts = ", ".join(ru["matched_hosts"][:5])
            if len(ru["matched_hosts"]) > 5:
                hosts += f" (+{len(ru['matched_hosts']) - 5} more)"
            detail = f" \u2192 {hosts}" if hosts else ""
            lines.append(f"  {icon} {ru['name']} [{doms}]: {ru['match_count']} matches{detail}{note}")
        lines.append("")

    if suggested_yaml:
        lines.append("\U0001f4cb Needed allowlist for blocked destinations (copy-paste into policy YAML):")
        lines.append("")
        lines.append(suggested_yaml)
        lines.append("")


def format_markdown_summary(report: dict) -> str:
    """Format a Markdown summary suitable for GitHub Job Summary."""
    total = report["total_connections"]
    allowed = report["allowed_connections"]
    blocked = report["blocked_connections"]
    access = report.get("access_summary", {})
    total_bytes = access.get("total_bytes", 0)
    destinations = access.get("destinations", [])
    cert_warnings = access.get("tls_cert_warnings", [])

    run_mode = report.get("run_mode", "monitor")
    if run_mode == "enforce":
        banner = "> 🔴 **Enforce mode** — connections outside the policy are blocked; the workflow fails on violations."
    else:
        extra = f" ({blocked} would-be-blocked)" if blocked else ""
        banner = f"> 🟡 **Monitor mode** — observing only, nothing was blocked{extra}."
    lines = [
        "## \U0001f512 PipeWarden Report",
        "",
        f"> Generated at `{report['generated_at']}`",
        "",
        banner,
        "",
    ]
    if report.get("discovery"):
        cp = report.get("commit_path") or "network-policy.yml"
        lines.append(
            "> 💾 **Get your settings:** PipeWarden generated a network policy from this run. "
            "Download the `network-report` artifact, review its `network-policy.yml`, and commit it to "
            f"`{cp}` — then set `mode: enforce`."
        )
        lines.append("")
    lines += [
        "| Metric | Count |",
        "|--------|------:|",
        f"| Total connections | {total} |",
        f"| \u2705 Allowed | {allowed} |",
        f"| \U0001f6ab Blocked / would-block | {blocked} |",
        f"| Unique destinations | {access.get('unique_destinations', 0)} |",
        f"| Data transferred | {_format_bytes(total_bytes)} |",
        f"| DNS queries | {report.get('dns_queries', 0)} |",
        "",
    ]

    if cert_warnings:
        lines.append("### \u26a0\ufe0f TLS Certificate Warnings")
        lines.append("")
        lines.append("| Host | Error |")
        lines.append("|------|-------|")
        for w in cert_warnings:
            lines.append(f"| `{w['host']}:{w['port']}` | {w.get('tls_cert_error', 'untrusted')} |")
        lines.append("")

    if destinations:
        lines.append("<details>")
        lines.append(f"<summary>\U0001f4e1 Destinations ({len(destinations)})</summary>")
        lines.append("")
        lines.append("| Destination | Proto | Requests | Data | Status | Owner | CA |")
        lines.append("|-------------|-------|----------|------|--------|-------|----|")
        for dest in sorted(destinations, key=lambda d: d["count"], reverse=True):
            display = _dest_display_name(dest)
            host_port = f"`{display}:{dest['port']}`"
            proto = dest.get("protocol", "?")
            count = dest["count"]
            data = _format_bytes(dest.get("bytes_transferred", 0))
            statuses = dest.get("statuses", {})
            status_parts = []
            for s, n in sorted(statuses.items()):
                icon = "\u2705" if s == "allowed" else "\U0001f6ab" if s in ("blocked", "would_block") else ""
                status_parts.append(f"{icon}{s}={n}")
            status_str = ", ".join(status_parts)
            issuer = dest.get("tls_cert_issuer", "\u2014")
            cert_flag = " \u26a0\ufe0f" if dest.get("tls_cert_valid") is False else ""
            ip_info = dest.get("ip_info", {})
            owner = ip_info.get("owner", "\u2014")
            country = ip_info.get("country", "")
            if country and owner != "\u2014":
                owner = f"{owner} ({country})"
            lines.append(f"| {host_port} | {proto} | {count} | {data} | {status_str} | {owner} | {issuer}{cert_flag} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    blocked_conns = [c for c in report["connections"] if c.get("status") in ("blocked", "would_block")]
    if blocked_conns:
        time_range = _time_range(blocked_conns)
        lines.append("<details>")
        lines.append(f"<summary>\U0001f6ab Blocked connections ({len(blocked_conns)}, {time_range})</summary>")
        lines.append("")
        lines.append("| Destination | Proto | Count | Time range |")
        lines.append("|-------------|-------|------:|------------|")
        grouped = _group_blocked(blocked_conns)
        for key, info in sorted(grouped.items(), key=lambda x: x[1]["count"], reverse=True):
            lines.append(f"| `{key}` | {info['protocol']} | {info['count']} | {info['time_range']} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    analysis = report.get("policy_analysis", {})
    if analysis:
        _format_policy_analysis_md(lines, analysis)

    dns_summary = report.get("dns_summary", {})
    dns_queries = dns_summary.get("queries", [])
    if dns_queries:
        lines.append("<details>")
        lines.append(f"<summary>\U0001f310 DNS queries ({dns_summary.get('total_queries', 0)} total, {dns_summary.get('unique_domains', 0)} unique)</summary>")
        lines.append("")
        lines.append("| | Domain | Queries | Type | Resolved IPs |")
        lines.append("|--|--------|--------:|------|-------------|")
        for q in sorted(dns_queries, key=lambda d: d["count"], reverse=True):
            icon = "\u2705" if q["status"] == "allowed" else "\U0001f6ab"
            ips = ", ".join(f"`{ip}`" for ip in q["resolved_ips"][:3])
            if len(q["resolved_ips"]) > 3:
                ips += f" (+{len(q['resolved_ips']) - 3})"
            if not ips:
                ips = "\u2014"
            lines.append(f"| {icon} | `{q['host']}` | {q['count']} | {q['query_type']} | {ips} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines) + "\n"


def _format_policy_analysis_md(lines: list[str], analysis: dict) -> None:
    """Append policy analysis sections to markdown summary lines."""
    rule_usage = analysis.get("rule_usage", [])
    suggested_yaml = analysis.get("suggested_yaml", "")

    if rule_usage:
        used = sum(1 for r in rule_usage if r["match_count"] > 0)
        total = len(rule_usage)
        lines.append("<details open>")
        lines.append(f"<summary>\U0001f4ca Policy rules ({used}/{total} used)</summary>")
        lines.append("")
        lines.append("| | Rule | Domains | Matches | Actual hosts |")
        lines.append("|--|------|---------|--------:|-------------|")
        for ru in rule_usage:
            icon = "\u2705" if ru["match_count"] > 0 else "\u26aa"
            # Show domain patterns from the rule
            doms = ", ".join(f"`{d}`" for d in ru.get("domains", [])[:4])
            if len(ru.get("domains", [])) > 4:
                doms += f" (+{len(ru['domains']) - 4})"
            if not doms:
                doms = "\u2014"
            # Show actual matched hosts; for zero-match rules, explain why.
            hosts = ", ".join(f"`{h}`" for h in ru["matched_hosts"][:5])
            if len(ru["matched_hosts"]) > 5:
                hosts += f" (+{len(ru['matched_hosts']) - 5} more)"
            if not hosts:
                if ru["match_count"] == 0 and ru.get("appears", "always") == "sometimes":
                    hosts = "_appears sometimes; not seen this run_"
                elif ru["match_count"] == 0:
                    hosts = "_unused; candidate for removal_"
                else:
                    hosts = "\u2014"
            lines.append(f"| {icon} | {ru['name']} | {doms} | {ru['match_count']} | {hosts} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if suggested_yaml:
        lines.append("<details open>")
        lines.append("<summary>\U0001f4cb Needed allowlist for blocked destinations</summary>")
        lines.append("")
        lines.append("Copy-paste into your `network-policy.yml`")
        lines.append("")
        lines.append("```yaml")
        lines.append(suggested_yaml)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")


def generate_complete_policy_yaml(report: dict) -> str:
    """Generate a complete, valid network-policy.yml from observed traffic.

    Produces a ready-to-commit policy file that allows all connections
    seen during a discovery run. One rule is emitted per unique
    host:port:protocol triplet observed, sorted alphabetically.

    Args:
        report: A report dict produced by build_report().

    Returns:
        A YAML string (valid network-policy.yml content).
    """
    from datetime import date
    today = date.today().isoformat()

    destinations = report.get("access_summary", {}).get("destinations", [])

    lines = [
        f"# Auto-generated by PipeWarden — discovery run ({today})",
        "# Review this file, then commit it to your repository.",
        "# Change 'mode' to 'enforce' once you have verified all rules.",
        "",
        'version: "1"',
        "mode: monitor",
        "",
        "rules:",
    ]

    for dest in sorted(destinations, key=lambda d: (d.get("host", ""), d.get("port", 0))):
        host = dest.get("host", "")
        port = dest.get("port", 443)
        proto = dest.get("protocol", "https")
        if not host or proto == "dns":
            continue

        # Build a short, valid rule name from the host
        rule_name = host.lstrip("*.")
        if len(rule_name) > 60:
            rule_name = rule_name[:60]

        ip_info = dest.get("ip_info", {})
        owner = ip_info.get("owner", "")
        comment = f"  # {owner}" if owner else ""

        lines.append(f'  - name: "{rule_name}"{comment}')
        lines.append("    allow:")
        lines.append(f'      domains: ["{host}"]')
        lines.append(f"      ports: [{port}]")
        lines.append(f"      protocols: [{proto}]")
        lines.append("")

    return "\n".join(lines) + "\n"


def generate_report(input_path: str, output_dir: str,
                    policy_path: str | None = None,
                    mode: str | None = None,
                    commit_path: str | None = None) -> dict:
    """Read JSONL log, produce report.json, summary.txt, summary.md.

    If policy_path is provided, also runs policy analysis (dry-run mode).
    ``mode`` ("monitor"/"enforce") drives the report banner; ``commit_path`` is
    the suggested location to commit the generated policy (discovery mode).
    Returns the report dict.
    """
    connections = read_jsonl(input_path)
    report = build_report(connections)
    _enrich_destinations(report)
    report["run_mode"] = mode or "monitor"
    report["discovery"] = policy_path is None
    report["commit_path"] = commit_path or "network-policy.yml"

    if policy_path:
        report["policy_analysis"] = _run_policy_analysis(
            policy_path, connections, report
        )

    os.makedirs(output_dir, exist_ok=True)

    report_path = os.path.join(output_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    summary_path = os.path.join(output_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(format_summary(report))

    md_path = os.path.join(output_dir, "summary.md")
    with open(md_path, "w") as f:
        f.write(format_markdown_summary(report))

    # In discovery mode (no policy file), generate a ready-to-commit policy.
    if not policy_path:
        policy_yaml = generate_complete_policy_yaml(report)
        policy_out = os.path.join(output_dir, "network-policy.yml")
        with open(policy_out, "w") as f:
            f.write(policy_yaml)

    # Generate SARIF for GitHub Security tab integration
    try:
        from scripts.generate_sarif import write_sarif
    except ImportError:
        try:
            from generate_sarif import write_sarif
        except ImportError:
            write_sarif = None
    if write_sarif:
        sarif_path = os.path.join(output_dir, "pipewarden.sarif")
        policy_rel = os.path.basename(policy_path) if policy_path else "network-policy.yml"
        write_sarif(report, sarif_path, policy_file=policy_rel)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Generate network connection report from JSONL log."
    )
    parser.add_argument("--input", required=True, help="Path to connections.jsonl")
    parser.add_argument("--output", required=True, help="Output directory for report files")
    parser.add_argument("--policy", default=None, help="Path to network-policy.yml for dry-run analysis")
    parser.add_argument("--mode", default=None, help="Run mode: monitor or enforce (for the report banner)")
    parser.add_argument("--commit-path", default=None, help="Suggested path to commit the generated policy")
    args = parser.parse_args()

    report = generate_report(
        args.input, args.output, policy_path=args.policy,
        mode=args.mode, commit_path=args.commit_path,
    )
    print(format_summary(report))


if __name__ == "__main__":
    main()
