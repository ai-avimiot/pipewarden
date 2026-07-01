"""Lightweight DNS proxy for PipeWarden.

Intercepts all DNS queries from the pipeline container, logs them,
resolves via upstream DNS, and maintains an IP→domain mapping that
the mitmproxy addon can use to enrich connection logs.

Architecture:
  - Listens on UDP port 53
  - Forwards queries to upstream DNS (default: 8.8.8.8, 1.1.1.1)
  - Logs every query + resolved IPs to a shared JSONL file
  - Maintains a live ip→domain map file for the mitmproxy addon
"""

import fcntl
import json
import logging
import os
import socket
import struct
import sys
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

UPSTREAM_DNS = os.environ.get("UPSTREAM_DNS", "8.8.8.8,1.1.1.1").split(",")
LISTEN_ADDR = os.environ.get("DNS_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("DNS_LISTEN_PORT", "53"))
LOG_PATH = os.environ.get("DNS_LOG_PATH", "/var/log/dns_queries.jsonl")
IP_MAP_PATH = os.environ.get("DNS_IP_MAP_PATH", "/var/log/dns_ip_map.json")
CONN_LOG_PATH = os.environ.get("LOG_PATH", "/var/log/connections.jsonl")

# Shared ip→domain map (thread-safe via GIL for simple dict ops)
ip_to_domain: dict[str, str] = {}


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from a packet, handling compression pointers."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def parse_dns_query(data: bytes) -> tuple[int, str, int]:
    """Parse a DNS query packet. Returns (txn_id, qname, qtype)."""
    if len(data) < 12:
        return 0, "", 0
    txn_id = struct.unpack("!H", data[0:2])[0]
    # Skip header (12 bytes), parse question
    qname, offset = parse_dns_name(data, 12)
    qtype = struct.unpack("!H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0
    return txn_id, qname, qtype


def parse_dns_response(data: bytes) -> list[str]:
    """Extract A record IPs from a DNS response."""
    if len(data) < 12:
        return []
    # Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    ancount = struct.unpack("!H", data[6:8])[0]
    qdcount = struct.unpack("!H", data[4:6])[0]

    # Skip questions
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4  # QTYPE(2) + QCLASS(2)

    ips = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = struct.unpack("!H", data[offset:offset + 2])[0]
        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            # A record
            ip = socket.inet_ntoa(data[offset:offset + 4])
            ips.append(ip)
        offset += rdlength

    return ips


def forward_query(data: bytes, timeout: float = 3.0) -> bytes | None:
    """Forward a DNS query to upstream resolvers and return the response."""
    for upstream in UPSTREAM_DNS:
        upstream = upstream.strip()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(data, (upstream, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
        except (socket.timeout, OSError):
            try:
                sock.close()
            except Exception:
                pass
            continue
    return None


def log_dns_query(qname: str, qtype: int, resolved_ips: list[str],
                  status: str) -> None:
    """Write a DNS query log entry to the connections JSONL."""
    qtype_name = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
                  2: "NS", 6: "SOA", 33: "SRV", 65: "HTTPS"}.get(qtype, str(qtype))
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "dns",
        "host": qname,
        "port": 53,
        "method": qtype_name,
        "status": status,
        "dns_resolved_ips": resolved_ips,
    }
    try:
        log_dir = os.path.dirname(CONN_LOG_PATH)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(CONN_LOG_PATH, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(entry) + "\n")
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logger.debug(f"Failed to write DNS log: {e}")


def update_ip_map() -> None:
    """Write the current ip→domain map to a JSON file for the addon."""
    try:
        tmp = IP_MAP_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(ip_to_domain, f)
        os.replace(tmp, IP_MAP_PATH)
    except Exception as e:
        logger.debug(f"Failed to write IP map: {e}")


def handle_query(data: bytes, addr: tuple, sock: socket.socket,
                 policy_engine=None) -> None:
    """Handle a single DNS query: log, evaluate policy, forward, respond.

    In enforce mode, blocked queries get NXDOMAIN (no forwarding).
    In monitor mode, would_block queries are still forwarded but logged.
    This prevents DNS exfiltration in enforce mode while still providing
    full visibility in monitor mode.
    """
    _, qname, qtype = parse_dns_query(data)
    if not qname:
        return

    # Evaluate against policy
    status = "allowed"
    if policy_engine:
        from policy.models import ConnectionEntry
        entry = ConnectionEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            protocol="dns",
            host=qname,
            port=53,
        )
        status = policy_engine.evaluate(entry)

    if status == "blocked":
        # Enforce mode: return NXDOMAIN, do NOT forward
        log_dns_query(qname, qtype, [], "blocked")
        response = _make_nxdomain(data)
        sock.sendto(response, addr)
        return

    # Forward to upstream (allowed or would_block in monitor mode)
    response = forward_query(data)
    if response is None:
        log_dns_query(qname, qtype, [], status)
        return

    # Parse resolved IPs and update the map
    resolved_ips = parse_dns_response(response)
    for ip in resolved_ips:
        ip_to_domain[ip] = qname

    if resolved_ips:
        update_ip_map()

    log_dns_query(qname, qtype, resolved_ips, status)
    sock.sendto(response, addr)


def _make_nxdomain(query: bytes) -> bytes:
    """Build an NXDOMAIN response from a query packet."""
    if len(query) < 12:
        return query
    # Copy the query, set QR=1 (response), RCODE=3 (NXDOMAIN)
    response = bytearray(query)
    response[2] = 0x81  # QR=1, RD=1
    response[3] = 0x83  # RA=1, RCODE=3 (NXDOMAIN)
    # Zero out answer/authority/additional counts
    response[6:12] = b'\x00\x00\x00\x00\x00\x00'
    return bytes(response)


def run_dns_server(policy_engine=None) -> None:
    """Start the DNS server on UDP port 53. Blocks forever."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    print(f"[dns] Listening on {LISTEN_ADDR}:{LISTEN_PORT}", flush=True)
    print(f"[dns] Upstream resolvers: {UPSTREAM_DNS}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            # Handle each query in a thread to avoid blocking
            t = threading.Thread(
                target=handle_query,
                args=(data, addr, sock, policy_engine),
                daemon=True,
            )
            t.start()
        except Exception as e:
            logger.debug(f"DNS server error: {e}")


def start_dns_server_thread(policy_engine=None) -> threading.Thread:
    """Start the DNS server in a background daemon thread."""
    t = threading.Thread(
        target=run_dns_server,
        args=(policy_engine,),
        daemon=True,
    )
    t.start()
    return t


# ---------------------------------------------------------------------------
# Standalone mode: run as main script
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Optionally load policy for DNS filtering
    engine = None
    policy_file = os.environ.get("POLICY_FILE", "")
    if policy_file and os.path.exists(policy_file):
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from policy.matcher import PolicyEngine
            from policy.parser import parse_policy_file
            _, rules = parse_policy_file(policy_file)
            mode = os.environ.get("MODE", "monitor")
            engine = PolicyEngine(rules, mode=mode)
            print(f"[dns] Policy loaded: {len(rules)} rules, mode={mode}")
        except Exception as e:
            print(f"[dns] Could not load policy: {e}")

    run_dns_server(engine)
