"""Tiny DNS responder for demo-pipewarden-v3-guards.yml.

Answers A queries for the names given on the command line and forwards
everything else to the runner's real resolver, so the job can point
systemd-resolved at it and PipeWarden's interceptor picks it up as upstream.

    pw_test_dns.py LISTEN_IP[:PORT] UPSTREAM_IP name=ip [name=ip ...]
"""

import socket
import struct
import sys


def qname(packet: bytes) -> tuple[str, int]:
    labels, i = [], 12
    while packet[i]:
        n = packet[i]
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(labels).lower(), i + 1


def answer(packet: bytes, ip: str) -> bytes:
    _, end = qname(packet)
    qtype = struct.unpack("!H", packet[end:end + 2])[0]
    question = packet[12:end + 4]
    flags = 0x8180
    if qtype != 1:
        return packet[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return packet[:2] + struct.pack("!HHHHH", flags, 1, 1, 0, 0) + question + rr


def main() -> None:
    host, _, port = sys.argv[1].partition(":")
    upstream = sys.argv[2]
    table = dict(arg.split("=", 1) for arg in sys.argv[3:])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port or 53)))
    while True:
        packet, client = sock.recvfrom(4096)
        try:
            name, _ = qname(packet)
            if name in table:
                sock.sendto(answer(packet, table[name]), client)
                continue
            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(3)
            fwd.sendto(packet, (upstream, 53))
            sock.sendto(fwd.recvfrom(4096)[0], client)
            fwd.close()
        except (OSError, IndexError, ValueError):
            continue


if __name__ == "__main__":
    main()
