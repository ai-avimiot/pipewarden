"""Assert what PipeWarden did and did not see during the bypass suite.

The credibility gap against connection-level tools is scrutiny, not design:
PipeWarden has had far fewer eyes on it, which is not the same as having fewer
holes. A suite that actively tries to evade the intercept and records the
outcome of each attempt turns "we think this is covered" into a checked claim.

Two expectations, and the second is the interesting one:

``observed``
    The attempt must appear in the report. Absence is a regression — the
    intercept stopped seeing something it used to see.

``gap``
    The attempt is *known* not to be covered, and must stay absent. If one
    starts appearing, this fails too: the gap has closed and the documentation
    that tells users about it is now wrong. A tool that silently misses
    something is worse than one that says which things it misses, and a tool
    that silently *stops* missing something has stale docs pointing users at a
    workaround they no longer need.

Usage:
    python3 scripts/check_bypass.py <report.json> <cases.json>
"""

from __future__ import annotations

import json
import os
import sys

VALID_EXPECTATIONS = ("observed", "gap")


def load_connections(report_path: str) -> list[dict]:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    conns = report.get("connections", [])
    return [c for c in conns if isinstance(c, dict)]


def matches(conn: dict, case: dict) -> bool:
    """Does *conn* satisfy the identifying fields of *case*?

    Matching is on whichever of host/port/protocol the case specifies, so a
    case can be as loose as "anything on port 853" or as tight as a hostname
    plus protocol.
    """
    if case.get("host_is_ip"):
        # Discriminates a direct-to-IP request from the control case: a
        # connection made without DNS records the literal IP as its host,
        # while the hostname-based control never does. Matching on
        # port+protocol alone let the control satisfy this case, so the suite
        # stayed green even if direct-to-IP interception broke.
        import ipaddress

        try:
            ipaddress.ip_address(str(conn.get("host", "")))
        except ValueError:
            return False
    host = case.get("host")
    if host:
        haystack = " ".join(
            str(conn.get(k, "")) for k in ("host", "tls_sni", "server_ip")
        )
        if host not in haystack:
            return False
    port = case.get("port")
    if port is not None and conn.get("port") != port:
        return False
    protocol = case.get("protocol")
    if protocol and conn.get("protocol") != protocol:
        return False
    status = case.get("status")
    if status and conn.get("status") != status:
        return False
    return True


def evaluate(connections: list[dict], cases: list[dict]) -> list[dict]:
    results = []
    for case in cases:
        expectation = case.get("expect")
        if expectation not in VALID_EXPECTATIONS:
            raise ValueError(
                f"case {case.get('name')!r}: 'expect' must be one of "
                f"{VALID_EXPECTATIONS}, got {expectation!r}"
            )
        hits = [c for c in connections if matches(c, case)]
        seen = bool(hits)
        if expectation == "observed":
            ok = seen
            verdict = "caught" if seen else "MISSED"
        else:
            ok = not seen
            verdict = "known gap" if not seen else "GAP CLOSED"
        results.append({**case, "seen": seen, "ok": ok, "verdict": verdict, "hits": len(hits)})
    return results


def render(results: list[dict]) -> str:
    lines = [
        "## PipeWarden bypass suite",
        "",
        "| Attempt | Expected | Result | Note |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        mark = "✅" if r["ok"] else "❌"
        lines.append(
            f"| {r['name']} | {r['expect']} | {mark} {r['verdict']} | {r.get('note', '')} |"
        )

    missed = [r for r in results if not r["ok"] and r["expect"] == "observed"]
    closed = [r for r in results if not r["ok"] and r["expect"] == "gap"]
    if missed:
        lines += ["", "**Regression.** These were expected to be visible and were not:", ""]
        lines += [f"- {r['name']}" for r in missed]
    if closed:
        lines += [
            "",
            "**A documented gap appears to be closed.** That is good news, but the "
            "docs still tell users it is open — update them and flip `expect` to "
            "`observed` so it stays covered:",
            "",
        ]
        lines += [f"- {r['name']}" for r in closed]
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_bypass.py <report.json> <cases.json>", file=sys.stderr)
        return 2

    report_path, cases_path = sys.argv[1], sys.argv[2]

    try:
        connections = load_connections(report_path)
    except (OSError, ValueError) as exc:
        # A missing or unreadable report means the run produced no evidence at
        # all. Passing here would report "no bypasses found" from an empty set,
        # which is precisely the false-green this suite exists to prevent.
        print(f"::error::cannot read report {report_path}: {exc}")
        return 1

    # Same treatment as the report read above: a malformed cases file or a
    # typo'd `expect:` must produce the ::error:: annotation CI surfaces, not
    # a raw traceback the reader has to dig out of the step log.
    try:
        with open(cases_path, encoding="utf-8") as fh:
            cases = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"::error::cannot read cases file {cases_path}: {exc}")
        return 1

    if not connections:
        print(
            "::error::the report contains no connections — the intercept "
            "recorded nothing, so no case can be verified"
        )
        return 1

    try:
        results = evaluate(connections, cases)
    except ValueError as exc:
        print(f"::error::invalid bypass case: {exc}")
        return 1
    summary = render(results)
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")

    failed = [r for r in results if not r["ok"]]
    if failed:
        print(f"::error::{len(failed)} bypass case(s) did not match expectation")
        return 1
    print(f"All {len(results)} bypass cases matched expectation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
