#!/usr/bin/env python3
"""Fail-fast watcher: cancel the workflow run on the first blocked connection.

Used in enforce mode when ``fail-fast`` is enabled. Tails the connections log
and, the moment a connection with status "blocked" appears, cancels the current
GitHub Actions run via the REST API so the pipeline stops right away instead of
continuing until teardown.

Requires GH_TOKEN (actions:write), GITHUB_REPOSITORY and GITHUB_RUN_ID in env.
Best-effort: any error is logged, never raised.
"""

import json
import os
import sys
import time
import urllib.request


def first_blocked(lines) -> dict | None:
    """Return the first connection record with status 'blocked', else None.

    Pure function over an iterable of JSONL lines — unit-testable.
    """
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if rec.get("status") == "blocked":
            return rec
    return None


def cancel_run(repo: str, run_id: str, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/cancel"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        print("[fail-fast] run cancellation requested")
    except Exception as e:  # noqa: BLE001 — best-effort
        print(f"[fail-fast] cancel request failed: {e}")


def watch(log_path: str, repo: str, run_id: str, token: str,
          interval: float = 2.0) -> None:
    pos = 0
    while True:
        try:
            if os.path.exists(log_path):
                with open(log_path) as f:
                    f.seek(pos)
                    new = f.readlines()
                    pos = f.tell()
                rec = first_blocked(new)
                if rec is not None:
                    host = rec.get("host", "?")
                    port = rec.get("port", "?")
                    print(
                        f"::error title=PipeWarden fail-fast::Blocked connection to "
                        f"{host}:{port} — cancelling the run."
                    )
                    cancel_run(repo, run_id, token)
                    return
        except Exception as e:  # noqa: BLE001 — best-effort
            print(f"[fail-fast] watcher error: {e}")
        time.sleep(interval)


def main() -> int:
    log_path = os.environ.get("LOG_PATH", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    token = os.environ.get("GH_TOKEN", "")
    if not (log_path and repo and run_id and token):
        print("[fail-fast] missing LOG_PATH/GITHUB_REPOSITORY/GITHUB_RUN_ID/GH_TOKEN — not watching")
        return 0
    watch(log_path, repo, run_id, token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
