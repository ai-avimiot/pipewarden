"""Unit tests for IP enrichment module."""

import socket
from unittest.mock import patch

from scripts.ip_enrichment import (
    _reverse_ip,
    enrich_ips,
    lookup_asn,
    reverse_dns,
)


class TestReverseIp:
    def test_basic(self):
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_same_octets(self):
        assert _reverse_ip("8.8.8.8") == "8.8.8.8"

    def test_real_ip(self):
        assert _reverse_ip("52.44.38.1") == "1.38.44.52"


class TestLookupAsn:
    def test_private_ip_returns_private(self):
        result = lookup_asn("192.168.1.1")
        assert result["owner"] == "private"

    def test_loopback_returns_private(self):
        result = lookup_asn("127.0.0.1")
        assert result["owner"] == "private"

    def test_invalid_ip_returns_empty(self):
        result = lookup_asn("not-an-ip")
        assert result["owner"] == ""
        assert result["asn"] == ""

    @patch("scripts.ip_enrichment._dns_txt")
    def test_cymru_lookup_success(self, mock_dns):
        # First call: origin query
        # Second call: ASN query
        mock_dns.side_effect = [
            "16509 | 52.44.0.0/14 | US | arin | 2016-08-09",
            "16509 | US | arin | 2005-09-29 | AMAZON-02 - Amazon.com, Inc.",
        ]
        result = lookup_asn("52.44.38.1")
        assert result["asn"] == "16509"
        assert result["prefix"] == "52.44.0.0/14"
        assert result["country"] == "US"
        assert result["owner"] == "AMAZON-02 - Amazon.com, Inc."

    @patch("scripts.ip_enrichment._dns_txt")
    def test_cymru_origin_fails(self, mock_dns):
        mock_dns.return_value = ""
        result = lookup_asn("52.44.38.1")
        assert result["owner"] == ""

    @patch("scripts.ip_enrichment._dns_txt")
    def test_cymru_asn_query_fails(self, mock_dns):
        mock_dns.side_effect = [
            "16509 | 52.44.0.0/14 | US | arin | 2016-08-09",
            "",  # ASN query fails
        ]
        result = lookup_asn("52.44.38.1")
        assert result["asn"] == "16509"
        assert result["owner"] == ""  # No org name


class TestReverseDns:
    @patch("socket.gethostbyaddr")
    def test_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = (
            "ec2-52-44-38-1.compute-1.amazonaws.com", [], ["52.44.38.1"]
        )
        assert reverse_dns("52.44.38.1") == "ec2-52-44-38-1.compute-1.amazonaws.com"

    @patch("socket.gethostbyaddr", side_effect=socket.herror("not found"))
    def test_failure_returns_empty(self, mock_gethostbyaddr):
        assert reverse_dns("192.0.2.1") == ""


class TestEnrichIps:
    @patch("scripts.ip_enrichment.lookup_asn")
    @patch("scripts.ip_enrichment.reverse_dns")
    def test_enriches_multiple_ips(self, mock_rdns, mock_asn):
        mock_asn.return_value = {
            "asn": "16509", "prefix": "52.0.0.0/8",
            "country": "US", "owner": "AMAZON-02",
        }
        mock_rdns.return_value = "host.example.com"

        result = enrich_ips(["52.44.38.1", "52.44.38.2"])
        assert len(result) == 2
        assert result["52.44.38.1"]["owner"] == "AMAZON-02"
        assert result["52.44.38.1"]["reverse_dns"] == "host.example.com"

    @patch("scripts.ip_enrichment.lookup_asn")
    @patch("scripts.ip_enrichment.reverse_dns")
    def test_deduplicates_ips(self, mock_rdns, mock_asn):
        mock_asn.return_value = {"asn": "", "prefix": "", "country": "", "owner": ""}
        mock_rdns.return_value = ""

        result = enrich_ips(["1.2.3.4", "1.2.3.4", "1.2.3.4"])
        assert len(result) == 1
        # lookup_asn should only be called once
        assert mock_asn.call_count == 1

    def test_empty_list(self):
        result = enrich_ips([])
        assert result == {}
