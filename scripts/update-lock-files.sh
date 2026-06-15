#!/usr/bin/env bash
# update-lock-files.sh
#
# Regenerate hash-pinned requirements lock files from the source files.
# Run this whenever you update requirements/requirements.txt or proxy/requirements.in.
#
# Prerequisites:
#   pip install pip-tools
#
# Usage:
#   ./scripts/update-lock-files.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Installing pip-tools..."
pip install --quiet pip-tools

echo "==> Compiling proxy/requirements-lock.txt..."
pip-compile \
  --generate-hashes \
  --no-header \
  --output-file "${REPO_ROOT}/proxy/requirements-lock.txt" \
  "${REPO_ROOT}/proxy/requirements.in"

echo "==> Compiling requirements/requirements-lock.txt..."
pip-compile \
  --generate-hashes \
  --no-header \
  --output-file "${REPO_ROOT}/requirements/requirements-lock.txt" \
  "${REPO_ROOT}/requirements/requirements.txt"

echo ""
echo "Done. Review the generated files and commit them:"
echo "  git add proxy/requirements-lock.txt requirements/requirements-lock.txt"
echo "  git commit -m 'chore: update dependency lock files'"
