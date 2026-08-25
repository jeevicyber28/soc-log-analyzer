# Detection Rules

The analyzer uses transparent threshold rules so that an analyst can understand why an alert was produced. The rules operate on normalized SSH authentication events and preserve source log line numbers as evidence.

## SSH-BRUTE-FORCE-001

This rule groups failed login events by source IP and finds the largest set occurring inside the configured time window. It triggers when the set reaches the configured threshold, which defaults to five failures in 600 seconds. The alert is `medium` severity at the threshold and `high` severity at twice the threshold.

This rule may produce false positives when many users share one egress address, such as a corporate NAT or VPN. Correlate the source with identity, asset, and network telemetry before treating it as an incident.

## SSH-USER-PROBING-001

This rule counts failed events whose message contains `Invalid user`. It triggers when at least three different or repeated invalid usernames are attempted from one source in the configured window. The default severity is `medium` because username probing is suspicious but does not by itself demonstrate a successful compromise.

## SSH-SUCCESS-AFTER-FAIL-001

This rule checks each successful login for at least the configured number of preceding failures from the same source in the configured window. It is `high` severity because the sequence deserves prompt review, especially when the account is privileged or the source is unfamiliar.

The sequence can still be legitimate, for example when a user mistypes a password and then succeeds or when a shared address represents many users. Review the username, authentication method, time, host role, and surrounding events.

## Data handling

Use synthetic or sanitized samples for demonstrations. Do not commit real authentication logs or any file containing passwords, tokens, personal data, or sensitive network details. The example addresses in `samples/auth.log` are documentation ranges and are not intended to represent real source systems.
