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
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

UPSTREAM_DNS = os.environ.get("UPSTREAM_DNS", "8.8.8.8,1.1.1.1").split(",")
LISTEN_ADDR = os.environ.get("DNS_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("DNS_LISTEN_PORT", "53"))
LOG_PATH = os.environ.get("DNS_LOG_PATH", "/var/log/dns_queries.jsonl")
IP_MAP_PATH = os.environ.get("DNS_IP_MAP_PATH", "/var/log/dns_ip_map.json")
CONN_LOG_PATH = os.environ.get("LOG_PATH", "/var/log/connections.jsonl")
# Cap the ip→domain map so a long-running job with lots of unique resolutions
# can't grow it without bound.
MAX_IP_MAP_ENTRIES = int(os.environ.get("DNS_IP_MAP_MAX", "4096"))
# Cap concurrent query handlers so a flood of queries can't exhaust threads.
MAX_WORKERS = int(os.environ.get("DNS_MAX_WORKERS", "32"))
# Minimum seconds between ip→domain map writes (see _map_flusher).
MAP_FLUSH_INTERVAL = float(os.environ.get("DNS_MAP_FLUSH_INTERVAL", "0.5"))

# Shared ip→domain map (thread-safe via GIL for simple dict ops)
ip_to_domain: dict[str, str] = {}

# Set when the map has unwritten changes; a single flusher thread persists
# it. Handler threads must not write the file directly: concurrent writers
# raced on the shared .tmp path, and a dict mutated mid-json.dump raises
# "dictionary changed size during iteration".
_map_dirty = threading.Event()


def _same_txn_id(query: bytes, response: bytes) -> bool:
    """Return True if a response's transaction ID matches the query's."""
    if len(query) < 2 or len(response) < 2:
        return False
    return query[:2] == response[:2]


def _remember_ip(ip: str, qname: str) -> None:
    """Record an ip→domain mapping, most-recent last, bounded in size.

    Uses the insertion-ordered dict as an LRU-ish cache: a refreshed IP moves
    to the end, and the oldest entries are evicted once the cap is exceeded.
    """
    if ip in ip_to_domain:
        del ip_to_domain[ip]
    ip_to_domain[ip] = qname
    while len(ip_to_domain) > MAX_IP_MAP_ENTRIES:
        del ip_to_domain[next(iter(ip_to_domain))]


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
    """Forward a DNS query to upstream resolvers and return the response.

    Hardened against off-path spoofing: the socket is ``connect()``-ed to the
    chosen resolver so the kernel only delivers datagrams from that peer, and
    the response's transaction ID must match the query's (stray/mismatched
    datagrams are ignored until a matching one arrives or the deadline passes).
    """
    for upstream in UPSTREAM_DNS:
        upstream = upstream.strip()
        if not upstream:
            continue
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # connect() restricts recv() to datagrams from this resolver only.
            sock.connect((upstream, 53))
            sock.send(data)
            deadline = time.monotonic() + timeout
            while True:
                response = sock.recv(4096)
                if _same_txn_id(data, response):
                    return response
                # Wrong transaction ID — a spoofed or stale datagram; keep
                # waiting for the legitimate reply until the deadline.
                if time.monotonic() >= deadline:
                    break
        except (socket.timeout, OSError):
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return None


_conn_log_dir_ready = False


def log_dns_query(qname: str, qtype: int, resolved_ips: list[str],
                  status: str) -> None:
    """Write a DNS query log entry to the connections JSONL."""
    global _conn_log_dir_ready
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
        if not _conn_log_dir_ready:
            log_dir = os.path.dirname(CONN_LOG_PATH)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            _conn_log_dir_ready = True
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
            # dict() snapshots atomically under the GIL so concurrent
            # _remember_ip calls can't mutate the dict mid-serialization.
            json.dump(dict(ip_to_domain), f)
        os.replace(tmp, IP_MAP_PATH)
    except Exception as e:
        logger.debug(f"Failed to write IP map: {e}")


def _map_flusher() -> None:
    """Persist the ip→domain map when dirty, at most every flush interval.

    A busy pipeline resolves hundreds of names; rewriting the whole JSON
    file per query is O(n) each time. The flusher writes promptly after
    the first change, then coalesces bursts.
    """
    while True:
        _map_dirty.wait()
        _map_dirty.clear()
        update_ip_map()
        time.sleep(MAP_FLUSH_INTERVAL)


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
        _remember_ip(ip, qname)

    if resolved_ips:
        _map_dirty.set()

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

    # Single writer for the ip→domain map file (see _map_flusher).
    threading.Thread(target=_map_flusher, daemon=True).start()

    # Bounded pool: queries are handled concurrently without letting a
    # query flood spawn an unbounded number of threads.
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="dns")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            executor.submit(handle_query, data, addr, sock, policy_engine)
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

    # Optionally load policy for DNS filtering. A missing policy file means
    # discovery mode (log everything, block nothing), but a policy that
    # exists and fails to load must not silently disable filtering — exit
    # non-zero so the container/CI step fails visibly (fail closed).
    engine = None
    policy_file = os.environ.get("POLICY_FILE", "")
    if policy_file and os.path.exists(policy_file):
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from policy.matcher import PolicyEngine
            from policy.parser import parse_policy_file
            parsed_mode, rules = parse_policy_file(policy_file)
            mode = os.environ.get("MODE") or parsed_mode or "monitor"
            engine = PolicyEngine(rules, mode=mode)
            print(f"[dns] Policy loaded: {len(rules)} rules, mode={mode}")
        except Exception as e:
            print(f"[dns] FATAL: could not load policy {policy_file!r}: {e}",
                  file=sys.stderr, flush=True)
            sys.exit(1)

    run_dns_server(engine)
