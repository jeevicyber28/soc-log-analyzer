# Contributing

Thank you for helping improve SOC Log Analyzer. Contributions should strengthen defensive analysis, explainability, testability, and safe handling of security data.

## Before opening a pull request

Please open an issue for substantial changes so the design can be discussed first. For small documentation or test fixes, a pull request is welcome directly. Never include real authentication logs, credentials, tokens, personal data, or private infrastructure details in an issue, sample, or pull request.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

## Pull-request expectations

Keep each pull request focused on one improvement. Add or update tests for behavior changes, update the README or detection documentation when appropriate, and explain false-positive considerations for new rules. Use clear commit messages such as `feat: detect repeated invalid usernames` or `docs: explain report schema`.

Before submitting, run `pytest`, `python3 -m compileall -q src tests`, and `git diff --check`. A pull request should describe the problem, the change, the test evidence, and any limitations.

## Responsible use

This project is for authorized defensive log analysis and security education. It does not authorize access to systems, networks, accounts, or data that you do not own or have permission to inspect.
