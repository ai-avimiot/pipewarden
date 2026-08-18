"""Which client — and which process — made a connection.

An allowlist answers *where* traffic went. ``policy.exfil`` answers *what went
with it*. This answers *who sent it*, which is the question every incident
review asks first and which a destination log cannot address: eight requests to
`registry.npmjs.org` look identical whether npm made them or a postinstall
script did.

Three sources, in increasing cost and decreasing availability:

``user-agent``
    Self-reported by the client inside the decrypted request. Free, race-free,
    needs no privileges, and is only reachable because PipeWarden terminates
    TLS — a tool that merely watches the network cannot read it. A client that
    lies is believed, so this identifies *tools*, not *adversaries*.

``proc``
    The kernel socket table joined on the client's source port. Exact, and
    names the real process however it labelled itself — but a process that
    exits before the lookup lands leaves no ``/proc`` entry to read.

``audit``
    ``connect()`` syscalls captured as they happen. Never misses a short-lived
    process, but carries only the destination the caller passed, so two
    processes contacting the same host in the same moment are indistinguishable.

They are complementary rather than ranked: ``proc`` is precise but lossy,
``audit`` is complete but ambiguous, and the helper prefers the first and falls
back to the second.

Everything in this module is pure — no ``/proc``, no sockets, no clock — so the
rules deciding what lands in an uploaded artifact are testable without root.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Reused rather than duplicated: a command line is scrubbed against the same
# credential shapes the payload scanner looks for, so a token on an argv can
# never reach the report through a path the body scanner would have caught.
from policy.exfil import _PATTERNS, WatchedSecret

VALID_ATTRIBUTION_MODES = ("off", "client", "process")

# Sources, most to least trusted. Used to decide which of two attributions for
# the same connection wins.
SOURCE_PRECEDENCE = ("proc", "audit", "user-agent")

# Attribution strings are attacker-influenced: a User-Agent is whatever the
# client typed, and an argv[0] is whatever the caller chose. Both end up in
# report.json and in Markdown tables in the job summary. Restricting them to a
# conservative character set is what makes rendering them safe, rather than
# hoping every downstream formatter escapes correctly.
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._/+:@ -]")
MAX_FIELD_LENGTH = 96

REDACTED = "<redacted>"


@dataclass
class AttributionConfig:
    """How much attribution to collect.

    Deliberately an *action input* rather than a policy key. The policy file
    describes traffic that is allowed; this decides whether a privileged helper
    process runs on the runner, which is the same class of decision as
    ``dns:`` or ``tls-intercept:`` — infrastructure, not policy.
    """

    mode: str = "client"
    include_cmdline: bool = False

    def enabled(self) -> bool:
        return self.mode in ("client", "process")

    def wants_process(self) -> bool:
        return self.mode == "process"


@dataclass
class Attribution:
    """Who was responsible for one connection."""

    source: str = ""       # "user-agent" | "proc" | "audit"
    client: str = ""       # normalised User-Agent, e.g. "npm/10.2.4"
    pid: int = 0
    comm: str = ""         # kernel's 15-char process name
    exe: str = ""          # resolved binary path
    ppid: int = 0
    pcomm: str = ""        # parent's name — usually the step's shell
    cmdline: str = ""      # only when include_cmdline; always redacted

    def is_empty(self) -> bool:
        return not (self.client or self.pid or self.comm or self.exe)

    def to_dict(self) -> dict:
        """Serialize, dropping every field that was never populated.

        Connection entries are already the bulkiest part of the artifact; an
        attribution that only knows the client should cost one key, not eight.
        """
        d: dict = {}
        for key in ("source", "client", "comm", "exe", "pcomm", "cmdline"):
            value = getattr(self, key)
            if value:
                d[key] = value
        for key in ("pid", "ppid"):
            value = getattr(self, key)
            if value:
                d[key] = value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Attribution":
        return cls(
            source=str(data.get("source", "")),
            client=str(data.get("client", "")),
            pid=int(data.get("pid", 0) or 0),
            comm=str(data.get("comm", "")),
            exe=str(data.get("exe", "")),
            ppid=int(data.get("ppid", 0) or 0),
            pcomm=str(data.get("pcomm", "")),
            cmdline=str(data.get("cmdline", "")),
        )

    def label(self) -> str:
        """The single string a human should see for this connection.

        Prefers the process, because it is the thing that actually ran; falls
        back to the self-reported client. ``comm`` is truncated by the kernel to
        15 characters, so the basename of ``exe`` is preferred when both exist.
        """
        if self.exe:
            name = self.exe.rsplit("/", 1)[-1]
        else:
            name = self.comm
        if name and self.client and not self.client.startswith(name):
            # Both known and they disagree — worth showing, since a "curl"
            # User-Agent coming out of a process that is not curl is precisely
            # the discrepancy attribution exists to expose.
            return f"{name} ({self.client})"
        return name or self.client


def sanitize(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """Reduce an untrusted string to something safe to render and store."""
    if not value:
        return ""
    cleaned = _SAFE_CHARS.sub("", value).strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def client_from_user_agent(user_agent: str) -> str:
    """Reduce a ``User-Agent`` header to a stable client identifier.

    CI user agents are conventionally ``product/version`` followed by
    environment detail that varies per runner — ``npm/10.2.4 node/v20.11.0
    linux x64 workspaces/false`` differs between two runs of the same pipeline
    in everything after the first token. Keeping only that token is what makes
    the report's "who talked to this host" grouping stable.

    Returns "" for a header that carries no usable product token, so callers
    can treat "no attribution" as one case rather than two.
    """
    if not user_agent:
        return ""
    # Parenthesised comments hold OS and build detail, never the product.
    head = user_agent.split("(", 1)[0].strip()
    token = head.split()[0] if head.split() else ""
    return sanitize(token, 48)


def redact_cmdline(
    cmdline: str,
    watchlist: list[WatchedSecret] | None = None,
) -> str:
    """Remove credential material from a command line before it is recorded.

    ``/proc/<pid>/cmdline`` is world-readable, and CI scripts routinely put
    tokens on it — ``curl -H "Authorization: Bearer ..."``, ``npm publish
    --//registry:_authToken=...``. Recording it verbatim would publish those
    through the report artifact, which is the failure mode the exfil detector's
    fingerprinting exists to avoid. Both the job's watched values and the
    generic credential shapes are scrubbed, so a token nobody thought to add to
    ``watch_env`` is still removed.

    This is best-effort by nature, which is why ``include_cmdline`` is opt-in
    and off by default: a redactor cannot recognise a bespoke internal
    credential format, and the safe answer for an unknown format is not to
    collect the string at all.
    """
    if not cmdline:
        return ""

    text = cmdline
    for secret in watchlist or []:
        for variant in secret.variants:
            try:
                decoded = variant.decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001 - a redactor must never raise
                continue
            if decoded and decoded in text:
                text = text.replace(decoded, f"<redacted:{secret.label}>")

    raw = text.encode("utf-8", errors="ignore")
    for _label, pattern in _PATTERNS:
        raw = pattern.sub(REDACTED.encode(), raw)
    text = raw.decode("utf-8", errors="ignore")

    # Sanitising last, so a secret is removed before the character filter has a
    # chance to mangle it into something that no longer matches but still
    # carries most of its bytes.
    return sanitize(text, 200)


def attribution_from_user_agent(user_agent: str) -> Attribution:
    """Build the zero-privilege attribution available from a decrypted request."""
    client = client_from_user_agent(user_agent)
    if not client:
        return Attribution()
    return Attribution(source="user-agent", client=client)


def better(current: Attribution | None, candidate: Attribution) -> Attribution:
    """Pick the more informative of two attributions for the same connection.

    Process-level detail always beats a self-reported client, and ``proc`` beats
    ``audit`` because it identified the exact socket rather than a destination
    seen at roughly the right time. A candidate that adds a client to an
    existing process attribution is merged rather than discarded.
    """
    if current is None or current.is_empty():
        return candidate
    if candidate.is_empty():
        return current

    def rank(a: Attribution) -> int:
        try:
            return len(SOURCE_PRECEDENCE) - SOURCE_PRECEDENCE.index(a.source)
        except ValueError:
            return 0

    if rank(candidate) > rank(current):
        winner, loser = candidate, current
    else:
        winner, loser = current, candidate
    if not winner.client and loser.client:
        winner.client = loser.client
    return winner


def index_events(events: list[dict]) -> dict[tuple[str, int], Attribution]:
    """Index ``connect()`` events by destination for merging into flow records.

    Later events win: the audit stream is append-only and the last process to
    contact a destination is the one whose flow a teardown-time merge is most
    likely to be looking at.
    """
    index: dict[tuple[str, int], Attribution] = {}
    for event in events:
        dst_ip = event.get("dst_ip") or ""
        dst_port = event.get("dst_port")
        if not dst_ip or not dst_port:
            continue
        attribution = Attribution.from_dict(event)
        if attribution.is_empty():
            continue
        if not attribution.source:
            attribution.source = "audit"
        index[(dst_ip, int(dst_port))] = attribution
    return index


def apply_events(connections: list[dict], events: list[dict]) -> int:
    """Attach audit-derived attribution to connections that have none.

    This is what gives the ``tls-intercept: false`` path — and every
    non-intercepted port — a name against each flow: those entries come from
    conntrack, which records addresses and a uid but never a process. Entries
    that already carry attribution from the proxy are left alone, because a
    source-port match beat a destination match.

    Returns the number of connections that gained an attribution.
    """
    index = index_events(events)
    if not index:
        return 0

    attached = 0
    for conn in connections:
        if conn.get("attribution"):
            continue
        port = conn.get("port")
        if port is None:
            continue
        for addr in (conn.get("server_ip"), conn.get("host")):
            if not addr:
                continue
            found = index.get((addr, int(port)))
            if found is not None:
                conn["attribution"] = found.to_dict()
                attached += 1
                break
    return attached


@dataclass
class ActorSummary:
    """One row of the report's "who made these connections" table."""

    actor: str
    source: str = ""
    connections: int = 0
    destinations: list[str] = field(default_factory=list)
    blocked: int = 0
    with_findings: int = 0


def summarise(connections: list[dict]) -> dict:
    """Aggregate per-connection attribution into per-actor rows.

    Sorted by connection count so the noisiest client is first, with the actor
    that tripped a payload finding or a block promoted above it — those are the
    rows anyone reading the report actually came for.
    """
    actors: dict[str, ActorSummary] = {}
    attributed = 0

    for conn in connections:
        raw = conn.get("attribution")
        if not raw:
            continue
        attribution = Attribution.from_dict(raw)
        label = attribution.label()
        if not label:
            continue
        attributed += 1
        row = actors.setdefault(label, ActorSummary(actor=label,
                                                    source=attribution.source))
        row.connections += 1
        dest = f"{conn.get('host', 'unknown')}:{conn.get('port', 0)}"
        if dest not in row.destinations:
            row.destinations.append(dest)
        if conn.get("status") in ("blocked", "would_block"):
            row.blocked += 1
        if conn.get("exfil_findings"):
            row.with_findings += 1

    rows = sorted(
        actors.values(),
        key=lambda r: (r.with_findings > 0, r.blocked > 0, r.connections),
        reverse=True,
    )
    return {
        "attributed_connections": attributed,
        "unattributed_connections": len(connections) - attributed,
        "actors": [
            {
                "actor": r.actor,
                "source": r.source,
                "connections": r.connections,
                "destinations": r.destinations,
                "blocked": r.blocked,
                "with_findings": r.with_findings,
            }
            for r in rows
        ],
    }
