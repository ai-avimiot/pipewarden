"""Materialise watched secret values for the proxy process.

The transparent-mode proxy runs as ``sudo -u pipewardenuser env POLICY_FILE=...
MODE=... LOG_PATH=... mitmdump``. sudo strips the environment and ``env`` passes
exactly those three variables, so the addon's ``os.environ`` contains none of
the job's secrets — the ``env-secrets`` detector would resolve an empty
watchlist and silently detect nothing, which is the failure mode that let a
broken discovery mode look healthy for two days (#102).

The values are handed over in a file rather than on the command line: argv is
world-readable through ``/proc/<pid>/cmdline``, so passing secrets there would
expose them to every process on the runner in order to detect them leaving it.

The file is created fresh with O_CREAT|O_EXCL|O_NOFOLLOW at mode 0600, so it is
owner-only before any content is written and an existing file at the path —
stale from a cancelled job, or a planted symlink — is an error rather than
something to write through. Reusing a stale file was worse than it sounds: the
leftover is owned by the proxy user, this script runs as the runner, the write
failed, and the caller then handed the *previous* job's secrets to the proxy.
setup.sh removes the path before invoking this and on rollback; teardown.sh
removes it at the end of the job.

Usage:
    python3 scripts/write_watch_secrets.py <policy-file> <output-path>

Exits 0 and writes ``{}`` when the policy does not enable payload scanning, so
callers need no special case.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.parser import parse_policy_file_full  # noqa: E402


def collect(policy_file: str, env: dict[str, str]) -> dict[str, str]:
    """Return the watched name→value pairs present in *env*.

    Absent names are skipped: a policy that watches a secret this particular
    job was not granted is normal. Length filtering is left to
    ``exfil.build_watchlist`` so there is one definition of "too short".
    """
    if not policy_file:
        return {}
    policy = parse_policy_file_full(policy_file)
    if not policy.exfil.enabled() or "env-secrets" not in policy.exfil.detectors:
        return {}
    return {
        name: env[name]
        for name in policy.exfil.watch_env
        if env.get(name)
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: write_watch_secrets.py <policy-file> <output-path>",
            file=sys.stderr,
        )
        return 2

    policy_file, out_path = sys.argv[1], sys.argv[2]

    try:
        values = collect(policy_file, dict(os.environ))
    except (FileNotFoundError, OSError, ValueError) as exc:
        # Never fatal: losing the detector is bad, losing egress control
        # because a detector could not be configured is worse.
        print(f"write_watch_secrets: {exc}", file=sys.stderr)
        values = {}

    # O_EXCL: an existing file here is a stale leftover or a planted symlink,
    # and either way writing through it hands the proxy the wrong contents —
    # fail loudly so the caller can refuse to use the path at all. O_NOFOLLOW
    # is belt-and-braces with O_EXCL, and 0o600 applies before any byte lands.
    try:
        fd = os.open(
            out_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        print(
            f"write_watch_secrets: refusing to write {out_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(values, fh)

    # Count only — naming them here would put the list in the build log.
    print(f"write_watch_secrets: {len(values)} watched value(s) available")
    return 0


if __name__ == "__main__":
    sys.exit(main())
