# Contributing to PipeWarden

Thanks for your interest in contributing! This document covers the basics.

## Development Setup

```bash
git clone https://github.com/ai-avimiot/pipewarden.git
cd pipewarden
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/requirements.txt
pytest
```

## Running Tests

```bash
pytest                  # all tests
pytest -v               # verbose
pytest tests/test_*.py  # specific test file
```

Tests include property-based tests via [Hypothesis](https://hypothesis.readthedocs.io/).

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes and add tests
4. Run `pytest` to ensure all tests pass
5. Commit with a clear message (e.g., `fix: correct blocked count key in post.js`)
6. Open a pull request against `main`

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — new feature
- `fix:` — bug fix
- `security:` — security improvement
- `docs:` — documentation only
- `test:` — adding or updating tests
- `ci:` — CI/CD changes
- `perf:` — performance improvement
- `cleanup:` — code cleanup or refactoring

## Reporting Bugs

Open a [GitHub issue](https://github.com/ai-avimiot/pipewarden/issues/new?template=bug_report.yml) with steps to reproduce.

## Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions. Do not report security vulnerabilities through public issues.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
