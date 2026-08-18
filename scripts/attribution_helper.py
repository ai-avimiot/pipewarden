#!/usr/bin/env python3
"""Root-owned attribution helper: which process opened this socket?

The proxy cannot answer this itself. ``/proc/<pid>/fd`` is readable only by the
process owner or root, mitmdump runs as ``pipewardenuser``, and build steps run
as the runner user — so the socket-inode lookup that maps a connection back to
a process is structurally unavailable to the addon. This helper runs as root
and answers that one question over a unix socket, so the privilege stays in a
small process with a fixed job instead of being handed to the proxy.

Two independent sources, because each covers the other's blind spot:

* **/proc socket table** — join the client's source port to a socket inode, then
  scan open file descriptors for the process holding it. Exact. Misses any
  process that exited before the query arrived, which for a one-shot ``curl``
  is a real possibility.

* **audit netlink** — a ``connect()`` rule installed directly on the kernel's
  audit subsystem, streamed and parsed here. Catches processes that live for
  microseconds, but the record carries the destination the caller passed, not a
  source port, so simultaneous connections to the same host are ambiguous.

Queries try ``/proc`` first and fall back to the audit ring. Everything the
audit stream sees is also appended to an events file, which teardown merges
into conntrack-only connections — the ones with no proxy leg to ask about.

No auditd, no libaudit, no packages: the netlink protocol is spoken directly,
which keeps the "PipeWarden installs nothing from the internet" property intact.
"""

from __future__ import annotations

import argparse
import errno
import grp
import json
import os
import platform
import re
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.attribution import Attribution, redact_cmdline, sanitize  # noqa: E402
from policy.exfil import build_watchlist, load_watch_values  # noqa: E402

# ---------------------------------------------------------------------------
# Netlink / audit constants (linux/audit.h, linux/netlink.h)
# ---------------------------------------------------------------------------

NETLINK_AUDIT = 9

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04

NLMSG_ERROR = 0x02

AUDIT_GET = 1000
AUDIT_SET = 1001
AUDIT_ADD_RULE = 1011
AUDIT_DEL_RULE = 1012

AUDIT_SYSCALL = 1300
AUDIT_SOCKADDR = 1306
AUDIT_EOE = 1320

AUDIT_STATUS_ENABLED = 0x0001
AUDIT_STATUS_PID = 0x0004

# 0x02 is AUDIT_FILTER_ENTRY, which the kernel removed in 4.17 and now rejects
# with EINVAL — an easy value to reach for, and the rule never installs.
AUDIT_FILTER_EXIT = 0x04
AUDIT_ALWAYS = 2
AUDIT_NEVER = 0

AUDIT_BITMASK_SIZE = 64
AUDIT_MAX_FIELDS = 64

AUDIT_ARCH_FIELD = 11
AUDIT_EQUAL = 0x40000000

# arch token → (AUDIT_ARCH value, connect(2) syscall number)
_ARCHS = {
    "x86_64": (0xC000003E, 42),
    "aarch64": (0xC00000B7, 203),
    "arm64": (0xC00000B7, 203),
}

# ---------------------------------------------------------------------------
# /proc parsing — pure functions over text, so they are testable off-runner
# ---------------------------------------------------------------------------

PROC_NET_TCP_PATHS = ("/proc/net/tcp", "/proc/net/tcp6")


def _hex_to_port(token: str) -> int:
    return int(token, 16)


def parse_proc_net(text: str) -> dict[int, tuple[int, int]]:
    """Map local port → (inode, uid) from ``/proc/net/tcp`` content.

    Only the local port is keyed. The address half is deliberately ignored:
    with a transparent redirect the client's socket may be bound to any local
    address, and an ephemeral source port is already unique across the machine
    for the lifetime of the socket.
    """
    table: dict[int, tuple[int, int]] = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local = fields[1]
        if ":" not in local:
            continue
        try:
            port = _hex_to_port(local.rsplit(":", 1)[1])
            uid = int(fields[7])
            inode = int(fields[9])
        except (ValueError, IndexError):
            continue
        if inode:
            table[port] = (inode, uid)
    return table


def read_socket_table(paths: tuple[str, ...] = PROC_NET_TCP_PATHS) -> dict[int, tuple[int, int]]:
    """Merged local-port → (inode, uid) table across IPv4 and IPv6."""
    table: dict[int, tuple[int, int]] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                table.update(parse_proc_net(fh.read()))
        except OSError:
            continue
    return table


_SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")


def find_pid_for_inode(inode: int, proc_root: str = "/proc") -> int:
    """Scan open descriptors for the process holding *inode*.

    Requires root: ``/proc/<pid>/fd`` is mode 0500 and owned by the process's
    own uid, which is the whole reason this code does not live in the addon.
    Returns 0 when no process holds it — normal, and the common outcome for a
    client that has already exited.
    """
    needle = f"socket:[{inode}]"
    try:
        pids = os.listdir(proc_root)
    except OSError:
        return 0
    for name in pids:
        if not name.isdigit():
            continue
        fd_dir = os.path.join(proc_root, name, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            # ESRCH (exited mid-scan) and EACCES are both expected and boring.
            continue
        for fd in fds:
            try:
                if os.readlink(os.path.join(fd_dir, fd)) == needle:
                    return int(name)
            except OSError:
                continue
    return 0


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def parse_status(text: str) -> tuple[str, int]:
    """Extract (name, ppid) from ``/proc/<pid>/status`` content."""
    name = ""
    ppid = 0
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("PPid:"):
            try:
                ppid = int(line.split(":", 1)[1].strip())
            except ValueError:
                ppid = 0
        if name and ppid:
            break
    return name, ppid


def process_info(
    pid: int,
    include_cmdline: bool = False,
    watchlist: list | None = None,
    proc_root: str = "/proc",
) -> Attribution:
    """Describe *pid*, with the command line scrubbed if it is collected at all."""
    base = os.path.join(proc_root, str(pid))
    comm, ppid = parse_status(_read_text(os.path.join(base, "status")))
    if not comm:
        comm = _read_text(os.path.join(base, "comm")).strip()
    if not comm:
        return Attribution()

    try:
        exe = os.readlink(os.path.join(base, "exe"))
    except OSError:
        exe = ""

    pcomm = ""
    if ppid:
        pcomm, _ = parse_status(_read_text(os.path.join(proc_root, str(ppid), "status")))

    cmdline = ""
    if include_cmdline:
        raw = _read_text(os.path.join(base, "cmdline"))
        cmdline = redact_cmdline(raw.replace("\x00", " ").strip(), watchlist)

    return Attribution(
        source="proc",
        pid=pid,
        comm=sanitize(comm, 32),
        exe=sanitize(exe, 128),
        ppid=ppid,
        pcomm=sanitize(pcomm, 32),
        cmdline=cmdline,
    )


# ---------------------------------------------------------------------------
# Audit record parsing — also pure, and the part most worth testing
# ---------------------------------------------------------------------------

_LINUX_AF_INET = 2
_LINUX_AF_INET6 = 10

_AUDIT_ID = re.compile(r"^audit\((?P<ts>[\d.]+):(?P<serial>\d+)\)")
_QUOTED = re.compile(r'(\w+)="([^"]*)"')
_BARE = re.compile(r"(\w+)=([^\s\"]+)")


def audit_serial(text: str) -> str:
    """Return the event serial shared by every record of one syscall event."""
    match = _AUDIT_ID.match(text)
    return match.group("serial") if match else ""


def parse_syscall_record(text: str) -> dict:
    """Pull the process identity out of an AUDIT_SYSCALL record."""
    fields: dict[str, str] = {}
    fields.update({k: v for k, v in _BARE.findall(text)})
    # Quoted values win: comm="my prog" would otherwise be truncated at the space.
    fields.update({k: v for k, v in _QUOTED.findall(text)})

    def as_int(key: str) -> int:
        try:
            return int(fields.get(key, "0"))
        except ValueError:
            return 0

    return {
        "pid": as_int("pid"),
        "ppid": as_int("ppid"),
        "uid": as_int("uid"),
        "comm": sanitize(fields.get("comm", ""), 32),
        "exe": sanitize(fields.get("exe", ""), 128),
        "success": fields.get("success", ""),
    }


def parse_sockaddr(saddr_hex: str) -> tuple[str, int]:
    """Decode the hex ``saddr=`` blob of an AUDIT_SOCKADDR record.

    Returns ("", 0) for address families that are not IPv4 or IPv6 — audit
    reports every ``connect()``, and a CI runner makes far more unix-socket
    connections (dbus, docker, systemd) than network ones.
    """
    try:
        raw = bytes.fromhex(saddr_hex)
    except ValueError:
        return "", 0
    if len(raw) < 4:
        return "", 0
    family = struct.unpack_from("<H", raw, 0)[0]
    port = struct.unpack_from(">H", raw, 2)[0]
    # Compared against Linux's AF_* numbers, not the running platform's: the
    # value came out of a Linux audit record. socket.AF_INET6 is 10 on Linux but
    # 30 on BSD/macOS, so using the local constant would misparse every IPv6
    # record when this module is read anywhere but the runner.
    if family == _LINUX_AF_INET and len(raw) >= 8:
        return socket.inet_ntop(socket.AF_INET, raw[4:8]), port
    if family == _LINUX_AF_INET6 and len(raw) >= 24:
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), port
    return "", 0


def parse_sockaddr_record(text: str) -> dict:
    """Extract destination address and port from an AUDIT_SOCKADDR record."""
    match = re.search(r"saddr=([0-9A-Fa-f]+)", text)
    if not match:
        return {}
    ip, port = parse_sockaddr(match.group(1))
    if not ip or not port:
        return {}
    return {"dst_ip": ip, "dst_port": port}


# ---------------------------------------------------------------------------
# Audit netlink client
# ---------------------------------------------------------------------------


def build_rule_data(arch_value: int, syscall_nr: int) -> bytes:
    """Serialize an ``audit_rule_data`` selecting one syscall on one arch.

    The arch field is not optional: syscall numbers are per-architecture, so a
    rule without it means something different on arm64 than on x86_64 and the
    kernel rejects it outright.
    """
    mask = [0] * AUDIT_BITMASK_SIZE
    mask[syscall_nr // 32] |= 1 << (syscall_nr % 32)

    fields = [0] * AUDIT_MAX_FIELDS
    values = [0] * AUDIT_MAX_FIELDS
    fieldflags = [0] * AUDIT_MAX_FIELDS
    fields[0] = AUDIT_ARCH_FIELD
    values[0] = arch_value
    fieldflags[0] = AUDIT_EQUAL

    return struct.pack(
        "=III" + f"{AUDIT_BITMASK_SIZE}I" + f"{AUDIT_MAX_FIELDS}I" * 3 + "I",
        AUDIT_FILTER_EXIT,
        AUDIT_ALWAYS,
        1,  # field_count
        *mask,
        *fields,
        *values,
        *fieldflags,
        0,  # buflen
    )


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def audit_owner_conflict(status: dict | None, self_pid: int) -> int:
    """The pid already receiving audit records, or 0 if it is free to claim.

    Only one process at a time receives audit records, so claiming delivery
    takes it from whoever holds it — auditd, on a self-hosted runner — and
    handing it back to nobody at teardown would leave that consumer silenced
    for good. The kernel does not clear the owner when the owning process dies,
    though, so a pid left over from something long gone would otherwise block
    this tier for the life of the machine.
    """
    if not status:
        return 0
    holder = status.get("pid", 0)
    if holder in (0, self_pid):
        return 0
    return holder if _pid_alive(holder) else 0


def _nl_message(msg_type: int, payload: bytes, seq: int, portid: int) -> bytes:
    length = 16 + len(payload)
    header = struct.pack("=IHHII", length, msg_type, NLM_F_REQUEST | NLM_F_ACK,
                         seq, portid)
    return header + payload


class AuditListener:
    """Owns the audit netlink socket, the rule, and the parsed event ring."""

    def __init__(self, ring_size: int = 4096, ignore_uids: tuple[int, ...] = ()):
        self.sock: socket.socket | None = None
        self.portid = 0
        self.seq = 1
        self.rule: bytes | None = None
        self.prior_enabled: int | None = None
        self.claimed = False
        self.ring: OrderedDict[tuple[str, int], dict] = OrderedDict()
        self.ring_size = ring_size
        self.ignore_uids = set(ignore_uids)
        self.events: list[dict] = []
        self.lock = threading.Lock()
        self.running = False
        self.error = ""
        self._pending: dict[str, dict] = {}

    # -- setup ------------------------------------------------------------

    def start(self) -> bool:
        """Claim the audit subsystem and install the connect() rule.

        Returns False (with ``error`` set) rather than raising: losing process
        attribution must never take down egress control, and a runner where the
        audit subsystem is already owned by something else is a supported
        environment, not a failure.
        """
        arch = _ARCHS.get(platform.machine())
        if arch is None:
            self.error = f"unsupported architecture {platform.machine()!r}"
            return False
        arch_value, syscall_nr = arch

        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
            self.sock.bind((os.getpid(), 0))
            self.portid = self.sock.getsockname()[0]
        except OSError as exc:
            self.error = f"cannot open audit netlink socket: {exc}"
            return False

        # Only one process at a time receives audit records, so claiming
        # delivery takes it away from whoever holds it. On a self-hosted runner
        # that is auditd, and handing the subsystem back to nobody at teardown
        # would leave it silenced for good — so an occupied subsystem is left
        # alone and this tier simply does not run.
        current = self._status()
        holder = audit_owner_conflict(current, os.getpid())
        if holder:
            self.error = (f"audit delivery already claimed by pid {holder}"
                          " — leaving it alone")
            self.stop()
            return False
        self.prior_enabled = current["enabled"] if current else None

        # Claim delivery. Without this the kernel has nowhere to send records
        # and the rule below would be installed to no effect.
        status = struct.pack(
            "=8I",
            AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID,
            1,          # enabled
            0,          # failure
            os.getpid(),
            0, 0, 0, 0,
        )
        if not self._request(AUDIT_SET, status):
            self.error = self.error or "kernel refused AUDIT_SET (audit may be locked)"
            self.stop()
            return False
        self.claimed = True

        self.rule = build_rule_data(arch_value, syscall_nr)
        if not self._request(AUDIT_ADD_RULE, self.rule):
            self.error = self.error or "kernel refused the connect() audit rule"
            self.rule = None
            self.stop()
            return False

        self.running = True
        return True

    def _request(self, msg_type: int, payload: bytes) -> bool:
        assert self.sock is not None
        self.seq += 1
        try:
            self.sock.send(_nl_message(msg_type, payload, self.seq, self.portid))
        except OSError as exc:
            self.error = f"audit request {msg_type} failed to send: {exc}"
            return False

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                self.sock.settimeout(max(0.05, deadline - time.monotonic()))
                data = self.sock.recv(8192)
            except (TimeoutError, socket.timeout):
                break
            except OSError as exc:
                self.error = f"audit request {msg_type} failed: {exc}"
                return False
            for mtype, body in _iter_netlink(data):
                if mtype != NLMSG_ERROR:
                    # Records can arrive interleaved with the ack once the rule
                    # is live; keep them rather than dropping the first events.
                    self._ingest(mtype, body)
                    continue
                code = struct.unpack_from("=i", body, 0)[0]
                if code == 0:
                    return True
                self.error = f"audit request {msg_type} rejected: {os.strerror(-code)}"
                return False
        # No ack inside the window. Treated as failure so a silently ignored
        # rule cannot masquerade as working attribution.
        self.error = self.error or f"audit request {msg_type} was not acknowledged"
        return False

    def _status(self) -> dict | None:
        """Who currently owns audit delivery, and is the subsystem enabled?

        The kernel acks the request before sending the status record, so this
        keeps reading past the ack rather than stopping at it like
        ``_request`` does.
        """
        if self.sock is None:
            return None
        self.seq += 1
        try:
            self.sock.send(_nl_message(AUDIT_GET, b"", self.seq, self.portid))
        except OSError:
            return None

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                self.sock.settimeout(max(0.05, deadline - time.monotonic()))
                data = self.sock.recv(8192)
            except (TimeoutError, socket.timeout):
                break
            except OSError:
                return None
            for mtype, body in _iter_netlink(data):
                if mtype == AUDIT_GET and len(body) >= 32:
                    fields = struct.unpack_from("=8I", body, 0)
                    return {"enabled": fields[1], "pid": fields[3]}
                if mtype == NLMSG_ERROR:
                    if struct.unpack_from("=i", body, 0)[0] != 0:
                        return None
        return None

    # -- teardown ---------------------------------------------------------

    def stop(self) -> None:
        """Remove the rule and release the subsystem.

        A rule left installed outlives the job and keeps the kernel generating
        records for every later step on this runner, so removal is not
        best-effort housekeeping — it is the contract for touching audit at all.
        """
        self.running = False
        if self.sock is None:
            return
        # Cleanup requests set self.error on their own, which would otherwise
        # bury the reason start() gave up under whatever the last teardown call
        # reported.
        reason = self.error
        try:
            if self.rule is not None:
                self._request(AUDIT_DEL_RULE, self.rule)
                self.rule = None
            # Only hand back delivery that was actually taken. Releasing a claim
            # held by someone else sets the owner to nobody, which is the one
            # outcome worse than not running this tier at all.
            if self.claimed:
                self._request(
                    AUDIT_SET,
                    struct.pack("=8I", AUDIT_STATUS_PID, 0, 0, 0, 0, 0, 0, 0),
                )
                # Turning audit on is a machine-wide change, and the promise
                # that nothing outlives the job covers the switch as well as
                # the rule.
                if self.prior_enabled is not None and self.prior_enabled != 1:
                    self._request(
                        AUDIT_SET,
                        struct.pack("=8I", AUDIT_STATUS_ENABLED, self.prior_enabled,
                                    0, 0, 0, 0, 0, 0),
                    )
            self.claimed = False
            self.prior_enabled = None
        except Exception:  # noqa: BLE001 - teardown must not raise
            pass
        finally:
            self.error = reason
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # -- streaming --------------------------------------------------------

    def run(self, on_event=None) -> None:
        """Read records until stopped, assembling syscall+sockaddr pairs."""
        assert self.sock is not None
        self.sock.settimeout(0.5)
        while self.running:
            try:
                data = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                continue
            except OSError as exc:
                if exc.errno in (errno.EBADF, errno.EINTR):
                    break
                continue
            for mtype, body in _iter_netlink(data):
                event = self._ingest(mtype, body)
                if event and on_event:
                    on_event(event)

    def _ingest(self, mtype: int, body: bytes) -> dict | None:
        """Fold one record into the pending event; return it once complete."""
        if mtype not in (AUDIT_SYSCALL, AUDIT_SOCKADDR, AUDIT_EOE):
            return None
        text = body.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        serial = audit_serial(text)
        if not serial:
            return None

        if mtype == AUDIT_EOE:
            self._pending.pop(serial, None)
            return None

        pending = self._pending.setdefault(serial, {})
        if mtype == AUDIT_SYSCALL:
            pending.update(parse_syscall_record(text))
        else:
            pending.update(parse_sockaddr_record(text))

        if not (pending.get("dst_ip") and pending.get("pid")):
            # Bound the half-assembled set: a runner makes a great many unix
            # socket connections whose SOCKADDR record never yields a dst_ip,
            # and their SYSCALL halves would otherwise accumulate forever.
            if len(self._pending) > self.ring_size:
                self._pending.pop(next(iter(self._pending)))
            return None

        self._pending.pop(serial, None)
        if pending.get("uid") in self.ignore_uids:
            # The proxy's own upstream connections. Attributing traffic to the
            # interceptor that forwarded it is noise, not attribution.
            return None

        event = {
            "source": "audit",
            "pid": pending.get("pid", 0),
            "ppid": pending.get("ppid", 0),
            "comm": pending.get("comm", ""),
            "exe": pending.get("exe", ""),
            "dst_ip": pending["dst_ip"],
            "dst_port": pending["dst_port"],
        }
        with self.lock:
            key = (event["dst_ip"], event["dst_port"])
            self.ring[key] = event
            self.ring.move_to_end(key)
            while len(self.ring) > self.ring_size:
                self.ring.popitem(last=False)
        return event

    def lookup(self, dst_ip: str, dst_port: int) -> Attribution:
        with self.lock:
            event = self.ring.get((dst_ip, int(dst_port)))
        if not event:
            return Attribution()
        return Attribution(
            source="audit",
            pid=event.get("pid", 0),
            ppid=event.get("ppid", 0),
            comm=event.get("comm", ""),
            exe=event.get("exe", ""),
        )


def _iter_netlink(data: bytes):
    """Yield (type, payload) for each netlink message in a datagram."""
    offset = 0
    while offset + 16 <= len(data):
        length, mtype, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, offset)
        if length < 16 or offset + length > len(data):
            break
        yield mtype, data[offset + 16:offset + length]
        offset += (length + 3) & ~3


# ---------------------------------------------------------------------------
# Query service
# ---------------------------------------------------------------------------


class Resolver:
    """Answers "who owns this connection?" from whichever source can."""

    def __init__(self, audit: AuditListener | None, include_cmdline: bool,
                 watchlist: list):
        self.audit = audit
        self.include_cmdline = include_cmdline
        self.watchlist = watchlist

    def resolve(self, request: dict) -> Attribution:
        src_port = request.get("src_port")
        if src_port:
            found = self._from_proc(int(src_port))
            if not found.is_empty():
                return found
        dst_ip = request.get("dst_ip") or ""
        dst_port = request.get("dst_port") or 0
        if self.audit is not None and dst_ip and dst_port:
            return self.audit.lookup(dst_ip, int(dst_port))
        return Attribution()

    def _from_proc(self, src_port: int) -> Attribution:
        # No uid filter here, unlike the audit tier. The caller asks about the
        # client's own source port, so this lookup is exact and can only name
        # the proxy if the proxy really opened that socket. Filtering by uid
        # would erase every answer whenever the proxy shares the runner's user,
        # which is how explicit-proxy mode runs.
        entry = read_socket_table().get(src_port)
        if entry is None:
            return Attribution()
        inode, _uid = entry
        pid = find_pid_for_inode(inode)
        if not pid:
            return Attribution()
        return process_info(pid, self.include_cmdline, self.watchlist)


class _Handler(socketserver.StreamRequestHandler):
    timeout = 2

    def handle(self) -> None:
        try:
            line = self.rfile.readline(8192)
            request = json.loads(line or b"{}")
            if not isinstance(request, dict):
                request = {}
            attribution = self.server.resolver.resolve(request)  # type: ignore[attr-defined]
            payload = attribution.to_dict()
        except Exception:  # noqa: BLE001 - a failed lookup answers "unknown"
            payload = {}
        try:
            self.wfile.write((json.dumps(payload) + "\n").encode())
        except OSError:
            pass


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, resolver: Resolver):
        self.resolver = resolver
        super().__init__(path, _Handler)


def query(socket_path: str, request: dict, timeout: float = 0.5) -> dict | None:
    """Client side of the protocol, used by the proxy addon (and by tests).

    ``{}`` means the helper answered and does not know; ``None`` means it could
    not be reached. Callers need the difference — an unattributable connection
    is routine, a dead helper is worth giving up on.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall((json.dumps(request) + "\n").encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        data = json.loads(b"".join(chunks) or b"{}")
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _resolve_uid(name: str) -> int | None:
    try:
        import pwd

        return pwd.getpwnam(name).pw_uid
    except (KeyError, ImportError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PipeWarden attribution helper")
    parser.add_argument("--socket", required=True, help="unix socket to serve on")
    parser.add_argument("--events", default="", help="append audit events here as JSONL")
    parser.add_argument("--group", default="", help="group granted access to the socket")
    parser.add_argument("--ignore-user", default="",
                        help="user the proxy runs as; its connect() records are dropped")
    parser.add_argument("--include-cmdline", action="store_true")
    parser.add_argument("--policy", default="", help="policy file, for cmdline redaction")
    parser.add_argument("--secrets", default="", help="watched-secrets file")
    parser.add_argument("--no-audit", action="store_true",
                        help="skip the connect() rule; /proc lookups only")
    args = parser.parse_args(argv)

    ignore_uids: tuple[int, ...] = ()
    if args.ignore_user:
        uid = _resolve_uid(args.ignore_user)
        if uid is not None:
            ignore_uids = (uid,)

    # Only needed to scrub command lines; with --include-cmdline off, no secret
    # value is loaded into this process at all.
    watchlist: list = []
    if args.include_cmdline and args.secrets and args.policy:
        try:
            from policy.parser import parse_policy_file_full

            cfg = parse_policy_file_full(args.policy).exfil
            watchlist = build_watchlist(
                load_watch_values(args.secrets), cfg.watch_env, cfg.min_secret_length
            )
        except Exception as exc:  # noqa: BLE001
            print(f"attribution: watchlist unavailable ({exc}); "
                  f"command lines will be pattern-redacted only", flush=True)

    audit: AuditListener | None = None
    if not args.no_audit:
        audit = AuditListener(ignore_uids=ignore_uids)
        if audit.start():
            print("attribution: connect() audit rule installed", flush=True)
        else:
            print(f"attribution: audit unavailable ({audit.error}); "
                  f"falling back to /proc lookups only", flush=True)
            audit = None

    events_lock = threading.Lock()

    def record(event: dict) -> None:
        if not args.events:
            return
        with events_lock:
            try:
                with open(args.events, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event) + "\n")
            except OSError:
                pass

    if args.events:
        # Created up front and world-readable: teardown runs as the runner user
        # and must be able to read it. It carries process names and paths, never
        # command lines — audit records do not include argv.
        try:
            with open(args.events, "a", encoding="utf-8"):
                pass
            os.chmod(args.events, 0o644)
        except OSError:
            pass

    try:
        os.unlink(args.socket)
    except OSError:
        pass

    resolver = Resolver(audit, args.include_cmdline, watchlist)
    server = _Server(args.socket, resolver)

    # The socket answers "which process owns this port", which non-root callers
    # cannot otherwise learn. Restrict it to the proxy's group rather than
    # leaving a 0666 oracle on the runner for the whole job.
    try:
        if args.group:
            os.chown(args.socket, 0, grp.getgrnam(args.group).gr_gid)
            os.chmod(args.socket, 0o660)
        else:
            os.chmod(args.socket, 0o600)
    except (OSError, KeyError):
        os.chmod(args.socket, 0o600)

    stopping = threading.Event()

    def shutdown(_signum=None, _frame=None):
        if stopping.is_set():
            return
        stopping.set()
        if audit is not None:
            audit.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    if audit is not None:
        threading.Thread(target=audit.run, args=(record,), daemon=True).start()

    print(f"attribution: serving on {args.socket}", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        shutdown()
        server.server_close()
        try:
            os.unlink(args.socket)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
