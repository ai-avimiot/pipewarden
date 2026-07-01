#!/usr/bin/env bash
# update-lock-files.sh
#
# Regenerate hash-pinned requirements lock files from the source files.
# Run this whenever you update requirements/requirements.txt or proxy/requirements.in.
#
# Uses `uv pip compile --universal` so the locks resolve for every platform and
# for the whole supported Python range (>=3.12), not just the machine you run
# this on. That matters because the locks are consumed on Linux (CI runners and
# the proxy container) — a platform-specific lock would be wrong or incomplete
# there. `--universal` records environment markers so a single lock works for
# both the 3.12 and 3.13 CI matrix legs.
#
# Prerequisites:
#   uv (https://docs.astral.sh/uv/) — `pip install uv` or `pipx install uv`
#
# Usage:
#   ./scripts/update-lock-files.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v uv >/dev/null 2>&1; then
  echo "error: 'uv' is required but not installed. Install with: pip install uv" >&2
  exit 1
fi

# Lock generation targets the minimum supported Python; --universal makes the
# result valid for newer interpreters in the range too.
PYTHON_VERSION="3.12"

echo "==> Compiling proxy/requirements-lock.txt..."
uv pip compile \
  --universal \
  --generate-hashes \
  --python-version "${PYTHON_VERSION}" \
  --output-file "${REPO_ROOT}/proxy/requirements-lock.txt" \
  "${REPO_ROOT}/proxy/requirements.in"

echo "==> Compiling requirements/requirements-lock.txt..."
uv pip compile \
  --universal \
  --generate-hashes \
  --python-version "${PYTHON_VERSION}" \
  --output-file "${REPO_ROOT}/requirements/requirements-lock.txt" \
  "${REPO_ROOT}/requirements/requirements.txt"

echo ""
echo "Done. Review the generated files and commit them:"
echo "  git add proxy/requirements-lock.txt requirements/requirements-lock.txt"
echo "  git commit -m 'chore: update dependency lock files'"
