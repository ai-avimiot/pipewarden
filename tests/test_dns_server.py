"""Tests for the DNS server module."""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

import dns_server
from dns_server import (
    _make_nxdomain,
    _remember_ip,
    _same_txn_id,
    parse_dns_name,
    parse_dns_query,
    parse_dns_response,
)


def _build_dns_query(domain: str, qtype: int = 1, txn_id: int = 0x1234) -> bytes:
    """Build a minimal DNS query packet for testing."""
    # Header: ID, FLAGS(standard query), QDCOUNT=1, AN=0, NS=0, AR=0
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
    # Question: encode domain name
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    # QTYPE + QCLASS (IN)
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _build_dns_response(domain: str, ips: list[str], txn_id: int = 0x1234) -> bytes:
    """Build a minimal DNS response with A records."""
    header = struct.pack("!HHHHHH", txn_id, 0x8180, 1, len(ips), 0, 0)
    # Question section
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    # Answer section
    answers = b""
    for ip in ips:
        # Name pointer to offset 12 (start of question name)
        answers += struct.pack("!H", 0xC00C)
        # TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4
        answers += struct.pack("!HHIH", 1, 1, 300, 4)
        answers += bytes(int(x) for x in ip.split("."))
    return header + question + answers


class TestParseDnsName:
    def test_simple_domain(self):
        data = b"\x07example\x03com\x00"
        name, offset = parse_dns_name(data, 0)
        assert name == "example.com"

    def test_subdomain(self):
        data = b"\x03www\x07example\x03com\x00"
        name, offset = parse_dns_name(data, 0)
        assert name == "www.example.com"


class TestParseDnsQuery:
    def test_parse_a_query(self):
        pkt = _build_dns_query("example.com", qtype=1, txn_id=0xABCD)
        txn_id, qname, qtype = parse_dns_query(pkt)
        assert txn_id == 0xABCD
        assert qname == "example.com"
        assert qtype == 1

    def test_parse_aaaa_query(self):
        pkt = _build_dns_query("test.org", qtype=28, txn_id=0x1111)
        txn_id, qname, qtype = parse_dns_query(pkt)
        assert qname == "test.org"
        assert qtype == 28


class TestParseDnsResponse:
    def test_single_a_record(self):
        pkt = _build_dns_response("example.com", ["1.2.3.4"])
        ips = parse_dns_response(pkt)
        assert ips == ["1.2.3.4"]

    def test_multiple_a_records(self):
        pkt = _build_dns_response("example.com", ["1.2.3.4", "5.6.7.8"])
        ips = parse_dns_response(pkt)
        assert ips == ["1.2.3.4", "5.6.7.8"]

    def test_no_answers(self):
        # Response with 0 answers
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack("!HH", 1, 1)
        pkt = header + question
        ips = parse_dns_response(pkt)
        assert ips == []


class TestMakeNxdomain:
    def test_nxdomain_response(self):
        query = _build_dns_query("blocked.com")
        response = _make_nxdomain(query)
        # Check QR=1 (response bit set)
        assert response[2] & 0x80 == 0x80
        # Check RCODE=3 (NXDOMAIN)
        assert response[3] & 0x0F == 3

    def test_preserves_txn_id(self):
        query = _build_dns_query("test.com", txn_id=0xBEEF)
        response = _make_nxdomain(query)
        txn_id = struct.unpack("!H", response[0:2])[0]
        assert txn_id == 0xBEEF


class TestSameTxnId:
    """Transaction-ID matching used to reject spoofed/stale upstream replies."""

    def test_matching_ids(self):
        q = _build_dns_query("a.com", txn_id=0x1234)
        r = _build_dns_response("a.com", ["1.2.3.4"], txn_id=0x1234)
        assert _same_txn_id(q, r) is True

    def test_mismatched_ids(self):
        q = _build_dns_query("a.com", txn_id=0x1234)
        r = _build_dns_response("a.com", ["1.2.3.4"], txn_id=0x5678)
        assert _same_txn_id(q, r) is False

    def test_short_packets_never_match(self):
        assert _same_txn_id(b"", b"") is False
        assert _same_txn_id(b"\x12", b"\x12") is False


class TestRememberIp:
    """The ip→domain map must stay bounded and refresh recency."""

    def setup_method(self):
        self._orig_max = dns_server.MAX_IP_MAP_ENTRIES
        dns_server.ip_to_domain.clear()

    def teardown_method(self):
        dns_server.MAX_IP_MAP_ENTRIES = self._orig_max
        dns_server.ip_to_domain.clear()

    def test_records_mapping(self):
        _remember_ip("1.2.3.4", "a.com")
        assert dns_server.ip_to_domain["1.2.3.4"] == "a.com"

    def test_evicts_oldest_over_cap(self):
        dns_server.MAX_IP_MAP_ENTRIES = 3
        for i in range(5):
            _remember_ip(f"10.0.0.{i}", f"host{i}.com")
        assert len(dns_server.ip_to_domain) == 3
        # The two oldest (10.0.0.0, 10.0.0.1) should have been evicted.
        assert "10.0.0.0" not in dns_server.ip_to_domain
        assert "10.0.0.1" not in dns_server.ip_to_domain
        assert "10.0.0.4" in dns_server.ip_to_domain

    def test_refresh_moves_to_most_recent(self):
        dns_server.MAX_IP_MAP_ENTRIES = 3
        for i in range(3):
            _remember_ip(f"10.0.0.{i}", f"host{i}.com")
        # Refresh the oldest so it's now most-recent, then push one more.
        _remember_ip("10.0.0.0", "host0.com")
        _remember_ip("10.0.0.9", "host9.com")
        # 10.0.0.1 was the oldest after the refresh and should be evicted.
        assert "10.0.0.1" not in dns_server.ip_to_domain
        assert "10.0.0.0" in dns_server.ip_to_domain
