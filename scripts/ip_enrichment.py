"""IP address enrichment via Team Cymru DNS and reverse DNS.

Resolves IP addresses to their owning organization (ASN) and reverse
hostname using public DNS services. No API keys required.

Team Cymru IP-to-ASN mapping:
  - Query: TXT record for <reversed-ip>.origin.asn.cymru.com
  - Returns: "ASN | prefix | CC | registry | date"
  - Then: TXT record for AS<asn>.asn.cymru.com
  - Returns: "ASN | CC | registry | date | description"
"""

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNS queries (1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


def _dns_txt(name: str, timeout: float = 3.0) -> str:
    """Resolve a DNS TXT record. Returns the first TXT value or ''."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        for rdata in answers:
            for txt in rdata.strings:
                return txt.decode("utf-8", errors="replace")
    except ImportError:
        # dnspython not installed — fall back to dig via subprocess
        import subprocess
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", name],
                capture_output=True, text=True, timeout=timeout,
            )
            line = result.stdout.strip().strip('"')
            if line:
                return line
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    except Exception:
        pass
    return ""


def lookup_asn(ip: str, timeout: float = 3.0) -> dict:
    """Look up ASN info for an IP address via Team Cymru DNS.

    Returns a dict with keys: asn, prefix, country, owner.
    All values default to '' on failure.
    """
    result = {"asn": "", "prefix": "", "country": "", "owner": ""}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return result

    # Only support IPv4 for now (Cymru also supports IPv6 but format differs)
    if addr.version != 4:
        return result

    # Skip private/reserved IPs
    if addr.is_private or addr.is_reserved or addr.is_loopback:
        result["owner"] = "private"
        return result

    # Step 1: Get ASN + prefix from origin query
    origin_name = f"{_reverse_ip(ip)}.origin.asn.cymru.com"
    origin_txt = _dns_txt(origin_name, timeout)
    if not origin_txt:
        return result

    # Parse: "ASN | prefix | CC | registry | date"
    parts = [p.strip() for p in origin_txt.split("|")]
    if len(parts) >= 3:
        result["asn"] = parts[0]
        result["prefix"] = parts[1]
        result["country"] = parts[2]

    # Step 2: Get org name from ASN query
    if result["asn"]:
        asn_name = f"AS{result['asn']}.asn.cymru.com"
        asn_txt = _dns_txt(asn_name, timeout)
        if asn_txt:
            # Parse: "ASN | CC | registry | date | description"
            asn_parts = [p.strip() for p in asn_txt.split("|")]
            if len(asn_parts) >= 5:
                result["owner"] = asn_parts[4]

    return result


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """Reverse DNS lookup for an IP address. Returns hostname or ''."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def enrich_ips(ips: list[str], timeout: float = 3.0,
               max_workers: int = 8) -> dict[str, dict]:
    """Enrich a list of IP addresses with ASN and reverse DNS info.

    Returns a dict mapping IP -> enrichment data:
        {
            "asn": "16509",
            "prefix": "52.44.0.0/14",
            "country": "US",
            "owner": "AMAZON-02 - Amazon.com, Inc.",
            "reverse_dns": "ec2-52-44-38-1.compute-1.amazonaws.com",
        }

    Lookups are parallelized for speed.
    """
    results: dict[str, dict] = {}
    unique_ips = list(set(ips))

    def _lookup(ip: str) -> tuple[str, dict]:
        info = lookup_asn(ip, timeout)
        info["reverse_dns"] = reverse_dns(ip, timeout)
        return ip, info

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unique_ips) or 1)) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            try:
                ip, info = future.result(timeout=timeout + 2)
                results[ip] = info
            except Exception as e:
                ip = futures[future]
                logger.debug(f"IP enrichment failed for {ip}: {e}")
                results[ip] = {
                    "asn": "", "prefix": "", "country": "",
                    "owner": "", "reverse_dns": "",
                }

    return results
