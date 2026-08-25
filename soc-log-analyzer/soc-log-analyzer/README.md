# SOC Log Analyzer

A defensive Python tool for analyzing syslog-style SSH authentication logs. It parses failed and successful login events, detects possible brute-force activity, identifies invalid-username probing, highlights successful logins after repeated failures, and exports an explainable JSON report.

> **Educational and defensive use only.** Analyze logs that you own or are explicitly authorized to inspect. This project performs local file analysis and does not scan networks, contact source IPs, or attempt authentication.

## Why this project exists

Security Operations Center analysts regularly turn raw authentication events into useful findings. This project demonstrates that workflow in a small, testable codebase: normalize raw events, apply transparent detection rules, assign severity, preserve evidence line numbers, and produce a report that another analyst can review.

## Features

| Feature | Description |
|---|---|
| SSH parsing | Supports common `sshd` messages for failed passwords, invalid users, and successful password or public-key logins. |
| Brute-force detection | Flags repeated failures from one source IP within a configurable time window. |
| Username probing | Flags repeated attempts using invalid usernames from one source IP. |
| Suspicious success | Flags a successful login after the configured number of recent failures. |
| Explainable alerts | Every alert includes a rule ID, severity, time range, source IP, event count, description, and evidence line numbers. |
| JSON reporting | Exports normalized events, configuration, summary counts, and alerts. |
| Test coverage | Includes parser, detection, validation, and report tests. |

## Quick start

The project uses only the Python standard library at runtime.

```bash
git clone https://github.com/YOUR-USERNAME/soc-log-analyzer.git
cd soc-log-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Analyze the included sanitized sample log:

```bash
soc-analyzer samples/auth.log --output reports/sample-report.json
```

You can also run it without installing the command-line entry point:

```bash
PYTHONPATH=src python -m soc_analyzer.cli samples/auth.log --output reports/sample-report.json
```

Use a stricter or more relaxed detection configuration when needed:

```bash
soc-analyzer /path/to/auth.log \
  --year 2026 \
  --threshold 5 \
  --window 600 \
  --output reports/auth-report.json
```

The `--window` value is expressed in seconds. Syslog timestamps do not contain a year, so supply `--year` when analyzing an older log.

## Example output

The included sample contains six failed logins followed by a successful login from the same address and three invalid usernames from another address.

```text
Events analyzed: 11
Failed logins:   9
Successful logins: 2
Unique source IPs: 3
Alerts:          3
[MEDIUM] SSH-BRUTE-FORCE-001: Detected 6 failed SSH logins from 198.51.100.24 within 600 seconds. (lines 1, 2, 3, 4, 5, 6)
[HIGH] SSH-SUCCESS-AFTER-FAIL-001: A successful SSH login from 198.51.100.24 followed 6 failed attempts within 600 seconds. (lines 1, 2, 3, 4, 5, 6, 7)
[MEDIUM] SSH-USER-PROBING-001: Detected 3 invalid usernames from 192.0.2.44 within 600 seconds. (lines 9, 10, 11)
```

The report format is versioned with `schema_version` so later releases can add fields without silently changing the meaning of existing reports.

## Detection rules

| Rule ID | Meaning | Default trigger | Severity |
|---|---|---|---|
| `SSH-BRUTE-FORCE-001` | Repeated failed SSH logins from one source | At least five failures in ten minutes | Medium; high at twice the threshold |
| `SSH-USER-PROBING-001` | Repeated invalid usernames from one source | At least three invalid usernames in ten minutes | Medium |
| `SSH-SUCCESS-AFTER-FAIL-001` | Successful login after repeated failures | At least five preceding failures in ten minutes | High |

These are triage heuristics, not proof of compromise. Analysts should correlate alerts with asset criticality, known maintenance, VPN or NAT behavior, user context, and other telemetry.

## Development

Run the test suite with:

```bash
pytest
```

The CI workflow runs the tests on supported Python versions. Contributions should include tests for new parser formats or detection rules and should keep sample data sanitized.

## Project structure

```text
soc-log-analyzer/
├── src/soc_analyzer/
│   ├── cli.py          # Command-line interface
│   ├── detections.py   # Explainable detection rules
│   ├── parser.py       # SSH/syslog event normalization
│   └── report.py       # JSON report assembly
├── tests/              # Automated tests
├── samples/            # Sanitized example logs
├── docs/               # Detection-rule documentation
├── .github/workflows/  # Continuous integration
├── pyproject.toml
└── LICENSE
```

## Roadmap

The next improvements are CSV input support, configurable rule definitions, a human-readable HTML report, additional Linux authentication formats, and MITRE ATT&CK technique metadata for each rule.

## Responsible disclosure and safe handling

Never commit real authentication logs, passwords, tokens, usernames, private IP inventories, or personal data. Replace sensitive values with documentation addresses and synthetic identities before sharing examples. If a sensitive file was committed, remove it from the repository history and rotate exposed credentials.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
