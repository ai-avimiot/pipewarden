#!/usr/bin/env python3
"""Generate a self-signed CA certificate and private key for TLS interception.

Uses the openssl CLI (available on ubuntu) instead of the Python
cryptography library to keep the Docker image small.
"""

import argparse
import os
import subprocess


def generate_ca(out_dir: str) -> tuple[str, str]:
    """Generate a self-signed CA cert + key using openssl CLI."""
    os.makedirs(out_dir, exist_ok=True)

    cert_path = os.path.join(out_dir, "ca.pem")
    key_path = os.path.join(out_dir, "ca-key.pem")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-days", "365",
            "-subj", "/CN=CI\\/CD Network Monitor CA/O=pipewarden",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        ],
        check=True,
        capture_output=True,
    )

    return cert_path, key_path


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed CA certificate and key."
    )
    parser.add_argument(
        "--out", required=True,
        help="Output directory for ca.pem and ca-key.pem",
    )
    args = parser.parse_args()

    cert_path, key_path = generate_ca(args.out)
    print(f"CA certificate written to: {cert_path}")
    print(f"CA private key written to: {key_path}")


if __name__ == "__main__":
    main()
