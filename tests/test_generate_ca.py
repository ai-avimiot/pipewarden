"""Tests for the TLS CA certificate generator (openssl-based)."""

import os
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from scripts.generate_ca import generate_ca


class TestGenerateCa:
    """Tests for generate_ca() which uses openssl CLI."""

    def test_creates_output_directory(self, tmp_path):
        out_dir = tmp_path / "new_dir"
        generate_ca(str(out_dir))
        assert out_dir.is_dir()

    def test_writes_cert_and_key_files(self, tmp_path):
        generate_ca(str(tmp_path))
        assert (tmp_path / "ca.pem").exists()
        assert (tmp_path / "ca-key.pem").exists()

    def test_cert_file_is_valid_pem(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        assert cert.subject is not None

    def test_key_file_is_valid_pem(self, tmp_path):
        generate_ca(str(tmp_path))
        key_data = (tmp_path / "ca-key.pem").read_bytes()
        key = serialization.load_pem_private_key(key_data, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_cert_is_self_signed(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        assert cert.subject == cert.issuer

    def test_cert_subject_contains_expected_cn(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        from cryptography.x509.oid import NameOID
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "Network Monitor CA" in cn

    def test_cert_is_ca(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True

    def test_cert_has_key_usage(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True

    def test_cert_valid_for_one_year(self, tmp_path):
        generate_ca(str(tmp_path))
        cert_data = (tmp_path / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 364 <= delta.days <= 366

    def test_returns_file_paths(self, tmp_path):
        cert_path, key_path = generate_ca(str(tmp_path))
        assert cert_path == os.path.join(str(tmp_path), "ca.pem")
        assert key_path == os.path.join(str(tmp_path), "ca-key.pem")
