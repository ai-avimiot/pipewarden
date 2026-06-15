#!/usr/bin/env python3
"""Post the network monitor report as a GitHub PR or issue comment.

Reads the event payload from GITHUB_EVENT_PATH to determine the PR/issue
number, then posts the report markdown via the GitHub REST API.

The comment body is truncated to 65 000 characters if necessary to stay
within GitHub's limit, with a notice appended at the end.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

_MAX_COMMENT_CHARS = 65_000
_TRUNCATION_NOTICE = "\n\n> ⚠️ Report truncated — see the [job summary]({run_url}) for the full output."


def _get_issue_number(event_path: str) -> int | None:
    """Extract the PR or issue number from the GitHub event payload."""
    if not event_path:
        return None
    try:
        with open(event_path) as f:
            event = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[post-comment] Could not read event payload: {exc}", file=sys.stderr)
        return None

    number = (
        event.get("pull_request", {}).get("number")
        or event.get("issue", {}).get("number")
    )
    return int(number) if number else None


def _build_comment_body(report_path: str, run_url: str) -> str:
    """Read the report markdown and truncate if needed."""
    with open(report_path) as f:
        body = f.read()

    if len(body) <= _MAX_COMMENT_CHARS:
        return body

    notice = _TRUNCATION_NOTICE.format(run_url=run_url)
    return body[: _MAX_COMMENT_CHARS - len(notice)] + notice


def post_comment(token: str, repo: str, issue_number: int, body: str) -> None:
    """Post a comment to a GitHub PR or issue."""
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
    payload = json.dumps({"body": body}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.load(resp)
            print(f"[post-comment] Comment posted: {result.get('html_url', url)}")
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        print(
            f"[post-comment] HTTP {exc.code} error posting comment: {body_bytes.decode(errors='replace')}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post the network monitor report as a GitHub comment."
    )
    parser.add_argument("--report", required=True, help="Path to summary.md")
    parser.add_argument("--token", required=True, help="GitHub token")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--event-path", default="", help="Path to GITHUB_EVENT_PATH JSON")
    parser.add_argument("--run-url", default="", help="URL to the current Actions run")
    args = parser.parse_args()

    issue_number = _get_issue_number(args.event_path)
    if issue_number is None:
        print(
            "[post-comment] Could not determine PR/issue number from event payload; "
            "skipping comment. post-comment only works on pull_request and issues events.",
            file=sys.stderr,
        )
        sys.exit(0)

    body = _build_comment_body(args.report, args.run_url)
    post_comment(args.token, args.repo, issue_number, body)


if __name__ == "__main__":
    main()
