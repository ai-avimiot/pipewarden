"""Tests for the privileged attribution helper (scripts/attribution_helper.py).

The helper needs root to read ``/proc/<pid>/fd`` and to open a netlink audit
socket, so the code is split: every parser is pure and lives here under test,
and only the syscalls around them need a runner. The netlink rule packing is
covered because an off-by-one in that struct produces a rule the kernel accepts
and silently never matches — a failure that looks exactly like "no traffic".
"""

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading

import pytest

from scripts.attribution_helper import (
    AUDIT_ARCH_FIELD,
    AUDIT_EQUAL,
    Resolver,
    audit_owner_conflict,
    audit_serial,
    build_rule_data,
    find_pid_for_inode,
    parse_proc_net,
    parse_sockaddr,
    parse_sockaddr_record,
    parse_status,
    parse_syscall_record,
    process_info,
    query,
)

PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 26584 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C934 04030201:01BB 01 00000000:00000000 00:00000000 00000000  1001        0 31207 1 0000000000000000 20 4 30 10 -1
"""


class TestParseProcNet:
    def test_extracts_port_inode_uid(self):
        table = parse_proc_net(PROC_NET_TCP)
        assert table[0x1F90] == (26584, 1001)   # port 8080
        assert table[0xC934] == (31207, 1001)   # ephemeral source port

    def test_header_only(self):
        assert parse_proc_net(PROC_NET_TCP.splitlines()[0]) == {}

    def test_empty_and_garbage_are_tolerated(self):
        assert parse_proc_net("") == {}
        assert parse_proc_net("not a table at all\n") == {}

    def test_malformed_row_does_not_abort_the_scan(self):
        text = PROC_NET_TCP + "   2: BROKEN\n   3: 0100007F:0050 x 0A x x x x 0 0 999 1\n"
        table = parse_proc_net(text)
        assert 0x1F90 in table

    def test_ipv6_row_shape(self):
        text = (
            "  sl  local_address                         remote_address  "
            "st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            "   0: 00000000000000000000000000000000:0050 "
            "00000000000000000000000000000000:0000 0A 00000000:00000000 "
            "00:00000000 00000000  1001 0 44444 1 0000000000000000 100 0 0 10 0\n"
        )
        assert parse_proc_net(text)[0x50] == (44444, 1001)


class TestParseStatus:
    def test_name_and_ppid(self):
        text = "Name:\tnpm\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t7\n"
        assert parse_status(text) == ("npm", 7)

    def test_name_with_a_space(self):
        assert parse_status("Name:\tmy prog\nPPid:\t3\n") == ("my prog", 3)

    def test_missing_fields(self):
        assert parse_status("") == ("", 0)

    def test_non_numeric_ppid_is_ignored(self):
        assert parse_status("Name:\tx\nPPid:\tnope\n") == ("x", 0)


class TestAuditRecordParsing:
    SYSCALL = (
        "audit(1699999999.123:456): arch=c000003e syscall=42 success=yes exit=0 "
        "a0=3 a1=7ffd items=0 ppid=1234 pid=5678 auid=1001 uid=1001 gid=1001 "
        'comm="curl" exe="/usr/bin/curl" key=(null)'
    )
    SOCKADDR = "audit(1699999999.123:456): saddr=" + "02" + "00" + "01BB" + "04030201" + "0" * 16

    def test_serial(self):
        assert audit_serial(self.SYSCALL) == "456"
        assert audit_serial("no audit prefix") == ""

    def test_syscall_and_sockaddr_records_share_a_serial(self):
        """Correlation depends on it: the two records arrive separately."""
        assert audit_serial(self.SYSCALL) == audit_serial(self.SOCKADDR)

    def test_syscall_fields(self):
        rec = parse_syscall_record(self.SYSCALL)
        assert rec["pid"] == 5678
        assert rec["ppid"] == 1234
        assert rec["uid"] == 1001
        assert rec["comm"] == "curl"
        assert rec["exe"] == "/usr/bin/curl"

    def test_quoted_value_with_spaces_survives(self):
        """comm is quoted precisely because it can contain a space."""
        rec = parse_syscall_record('audit(1.1:2): pid=1 comm="my prog" exe="/tmp/my prog"')
        assert rec["comm"] == "my prog"
        assert rec["exe"] == "/tmp/my prog"

    def test_sockaddr_ipv4(self):
        # sin_family LE, sin_port network order, sin_addr network order.
        assert parse_sockaddr("0200" + "01BB" + "04030201") == ("4.3.2.1", 443)

    def test_sockaddr_ipv6(self):
        """AF_INET6 is Linux's 10, whatever the platform running the parser."""
        hex_addr = "0A00" + "01BB" + "00000000" + "2607F8B0" + "0" * 24
        ip, port = parse_sockaddr(hex_addr)
        assert port == 443
        assert ip.startswith("2607:f8b0")

    def test_non_inet_family_is_ignored(self):
        """A runner makes far more unix-socket connects than network ones."""
        assert parse_sockaddr("0100" + "2f746d702f736f636b") == ("", 0)

    def test_truncated_and_garbage_saddr(self):
        assert parse_sockaddr("02") == ("", 0)
        assert parse_sockaddr("") == ("", 0)
        assert parse_sockaddr("zzzz") == ("", 0)

    def test_sockaddr_record(self):
        assert parse_sockaddr_record(self.SOCKADDR) == {"dst_ip": "4.3.2.1",
                                                        "dst_port": 443}

    def test_sockaddr_record_without_saddr(self):
        assert parse_sockaddr_record("audit(1.1:2): items=0") == {}

    def test_unix_socket_record_yields_nothing(self):
        record = "audit(1.1:2): saddr=" + "0100" + "2f746d702f736f636b"
        assert parse_sockaddr_record(record) == {}


class TestRuleData:
    def test_size_and_layout(self):
        blob = build_rule_data(0xC000003E, 42)
        # flags, action, field_count, mask[64], fields[64], values[64],
        # fieldflags[64], buflen
        assert len(blob) == struct.calcsize("=III") + 4 * 64 * 4 + 4

    def test_syscall_bit_is_set_in_the_mask(self):
        blob = build_rule_data(0xC000003E, 42)
        mask = struct.unpack_from("=64I", blob, struct.calcsize("=III"))
        assert mask[42 // 32] & (1 << (42 % 32))

    def test_a_different_syscall_sets_a_different_bit(self):
        """aarch64 connect is 203, not 42 — a shared mask would be a silent miss."""
        mask_x86 = struct.unpack_from("=64I", build_rule_data(0xC000003E, 42),
                                      struct.calcsize("=III"))
        mask_arm = struct.unpack_from("=64I", build_rule_data(0xC00000B7, 203),
                                      struct.calcsize("=III"))
        assert mask_x86 != mask_arm
        assert mask_arm[203 // 32] & (1 << (203 % 32))

    def test_rule_targets_the_syscall_exit_filter(self):
        """0x02 is AUDIT_FILTER_ENTRY, which the kernel removed in 4.17.

        Installing against it is not a subtle mismatch — the kernel rejects the
        rule outright with EINVAL and the whole tier silently never runs. The
        struct-layout checks above all passed while this was wrong, so the
        constant is asserted on its own.
        """
        flags, action, _count = struct.unpack_from("=III", build_rule_data(0xC000003E, 42))
        assert flags == 0x04, "AUDIT_FILTER_EXIT is 0x04; 0x02 is the removed ENTRY list"
        assert action == 2  # AUDIT_ALWAYS

    def test_arch_field_is_mandatory_and_populated(self):
        """Without it the rule matches syscall 42 on every architecture."""
        arch = 0xC000003E
        blob = build_rule_data(arch, 42)
        base = struct.calcsize("=III")
        _flags, _action, field_count = struct.unpack_from("=III", blob)
        fields = struct.unpack_from("=64I", blob, base + 64 * 4)
        values = struct.unpack_from("=64I", blob, base + 2 * 64 * 4)
        fieldflags = struct.unpack_from("=64I", blob, base + 3 * 64 * 4)
        assert field_count >= 1
        assert fields[0] == AUDIT_ARCH_FIELD
        assert values[0] == arch
        assert fieldflags[0] == AUDIT_EQUAL


class TestProcLookups:
    def _fake_proc(self, tmp_path, pid, inode, name="npm", ppid=7):
        pid_dir = tmp_path / str(pid)
        (pid_dir / "fd").mkdir(parents=True)
        (pid_dir / "fd" / "3").symlink_to(f"socket:[{inode}]")
        (pid_dir / "status").write_text(f"Name:\t{name}\nPPid:\t{ppid}\n")
        (pid_dir / "cmdline").write_bytes(b"npm\x00ci\x00")
        (pid_dir / "exe").symlink_to("/usr/bin/npm")
        return pid_dir

    def test_finds_the_owning_pid(self, tmp_path):
        self._fake_proc(tmp_path, 5678, 31207)
        assert find_pid_for_inode(31207, proc_root=str(tmp_path)) == 5678

    def test_returns_zero_when_the_socket_is_gone(self, tmp_path):
        self._fake_proc(tmp_path, 5678, 31207)
        assert find_pid_for_inode(999999, proc_root=str(tmp_path)) == 0

    def test_non_numeric_entries_are_skipped(self, tmp_path):
        (tmp_path / "self").mkdir()
        (tmp_path / "meminfo").write_text("x")
        self._fake_proc(tmp_path, 5678, 31207)
        assert find_pid_for_inode(31207, proc_root=str(tmp_path)) == 5678

    def test_process_info_populates_the_attribution(self, tmp_path):
        self._fake_proc(tmp_path, 5678, 31207)
        (tmp_path / "7" / "fd").mkdir(parents=True)
        (tmp_path / "7" / "status").write_text("Name:\tbash\nPPid:\t1\n")
        info = process_info(5678, include_cmdline=False, proc_root=str(tmp_path))
        assert info.source == "proc"
        assert info.pid == 5678
        assert info.comm == "npm"
        assert info.ppid == 7
        assert info.pcomm == "bash"
        assert info.cmdline == ""

    def test_cmdline_is_opt_in(self, tmp_path):
        self._fake_proc(tmp_path, 5678, 31207)
        info = process_info(5678, include_cmdline=True, proc_root=str(tmp_path))
        assert info.cmdline == "npm ci"

    def test_cmdline_is_redacted_even_when_collected(self, tmp_path):
        pid_dir = self._fake_proc(tmp_path, 5678, 31207)
        token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        (pid_dir / "cmdline").write_bytes(f"git\x00push\x00https://{token}@h/r\x00".encode())
        info = process_info(5678, include_cmdline=True, proc_root=str(tmp_path))
        assert token not in info.cmdline

    def test_vanished_process_yields_nothing(self, tmp_path):
        info = process_info(4242, include_cmdline=False, proc_root=str(tmp_path))
        assert info.is_empty()


@pytest.fixture
def short_tmpdir():
    """A directory short enough for an AF_UNIX path.

    ``tmp_path`` follows TMPDIR, which on macOS is long enough to exceed the
    ~104-byte sun_path limit before a filename is even appended.
    """
    path = tempfile.mkdtemp(prefix="pwattr", dir="/tmp")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class TestQueryProtocol:
    """``{}`` and ``None`` are different answers and callers depend on it.

    The addon disables the helper after a run of failures. Counting "the process
    already exited" as a failure would disable attribution within seconds of a
    job starting, so the two outcomes must stay distinguishable.
    """

    @staticmethod
    def _serve_once(path, reply: bytes):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)

        def serve():
            try:
                conn, _ = server.accept()
                conn.recv(4096)
                conn.sendall(reply)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return server, thread

    def test_unreachable_socket_returns_none(self, short_tmpdir):
        path = os.path.join(short_tmpdir, "nope.sock")
        assert query(path, {"src_port": 1}, timeout=0.2) is None

    def test_answered_but_unknown_returns_empty_dict(self, short_tmpdir):
        path = os.path.join(short_tmpdir, "h.sock")
        server, thread = self._serve_once(path, b"{}\n")
        try:
            assert query(path, {"src_port": 1}, timeout=2.0) == {}
        finally:
            thread.join(timeout=2)
            server.close()

    def test_answer_is_returned(self, short_tmpdir):
        path = os.path.join(short_tmpdir, "h.sock")
        reply = json.dumps({"comm": "npm", "pid": 5}).encode() + b"\n"
        server, thread = self._serve_once(path, reply)
        try:
            assert query(path, {"src_port": 1}, timeout=2.0) == {"comm": "npm", "pid": 5}
        finally:
            thread.join(timeout=2)
            server.close()

    def test_malformed_answer_is_not_an_exception(self, short_tmpdir):
        path = os.path.join(short_tmpdir, "h.sock")
        server, thread = self._serve_once(path, b"not json\n")
        try:
            assert query(path, {"src_port": 1}, timeout=2.0) is None
        finally:
            thread.join(timeout=2)
            server.close()

    def test_silent_server_times_out_rather_than_hanging(self, short_tmpdir):
        """A wedged helper must not stall every request through the proxy."""
        path = os.path.join(short_tmpdir, "h.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        try:
            assert query(path, {"src_port": 1}, timeout=0.3) is None
        finally:
            server.close()


class TestAuditOwnership:
    """Claiming audit delivery takes it away from whoever already has it.

    On a GitHub-hosted runner nothing holds it, so this never fires; on a
    self-hosted one it is auditd, and releasing the claim at teardown sets the
    owner to nobody — silencing that runner's audit trail from a tool whose job
    is to improve visibility.
    """

    def test_free_subsystem_is_claimable(self):
        assert audit_owner_conflict({"enabled": 1, "pid": 0}, 4242) == 0

    def test_our_own_claim_is_not_a_conflict(self):
        assert audit_owner_conflict({"enabled": 1, "pid": 4242}, 4242) == 0

    def test_unreadable_status_does_not_block_the_tier(self):
        """A kernel that will not answer AUDIT_GET is not a kernel with auditd."""
        assert audit_owner_conflict(None, 4242) == 0

    def test_a_live_owner_is_reported(self):
        assert audit_owner_conflict({"enabled": 1, "pid": os.getppid()},
                                    os.getpid()) == os.getppid()

    def test_a_dead_owner_does_not_block_the_tier_forever(self):
        """The kernel keeps audit_pid set after that process exits."""
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        assert audit_owner_conflict({"enabled": 1, "pid": proc.pid}, os.getpid()) == 0


class TestResolverIgnoresNobodyOnTheSocketPath:
    """The socket lookup keys on the client's own source port, so it is exact.

    An earlier version also applied the audit tier's ignore-uid filter here.
    That filter names the user the proxy runs as, which in explicit-proxy mode
    is the user the build steps run as too — so every lookup came back empty and
    process attribution reported nothing at all while still announcing itself as
    enabled. A silent total blank is the worst possible failure for a feature
    whose whole output is diagnostics.
    """

    def test_resolver_takes_no_uid_filter(self):
        import inspect
        params = inspect.signature(Resolver.__init__).parameters
        assert "ignore_uids" not in params, (
            "a uid filter on the socket path erases the build's own traffic "
            "whenever the proxy shares the runner's user"
        )

    @pytest.mark.skipif(not os.path.exists("/proc/net/tcp"),
                        reason="needs a real /proc socket table")
    def test_a_real_socket_resolves_to_this_process(self):
        """End to end against /proc, not a stubbed socket table."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.socket()
        try:
            cli.connect(srv.getsockname())
            found = Resolver(None, False, []).resolve(
                {"src_port": cli.getsockname()[1]})
            assert found.pid == os.getpid()
        finally:
            cli.close()
            srv.close()


@pytest.mark.parametrize("arch,syscall", [(0xC000003E, 42), (0xC00000B7, 203)])
def test_rule_data_is_accepted_for_both_supported_arches(arch, syscall):
    assert len(build_rule_data(arch, syscall)) > 0
