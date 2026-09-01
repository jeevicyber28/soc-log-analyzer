# Detection Rules

## SSH Brute Force

This rule identifies repeated failed SSH login attempts from the same source IP within a configured time window.

## Invalid Username Probing

This rule identifies repeated authentication attempts using invalid usernames from the same source IP.

## Successful Login After Failures

This rule identifies a successful login after multiple recent failed login attempts from the same source IP.

## Investigation guidance

These rules are triage heuristics and are not proof of compromise. Analysts should review the alert with asset criticality, known maintenance activity, VPN or NAT behavior, user context, and other available security telemetry.

## Safety note

Use this project only with logs that you own or are explicitly authorized to inspect. Do not commit real authentication logs, passwords, tokens, or personal data.
