"""Detection rules for normalized SSH authentication events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Iterable

from .parser import AuthEvent


@dataclass(frozen=True)
class Alert:
    """A explainable security alert produced by a detection rule."""

    rule_id: str
    title: str
    severity: str
    source_ip: str
    username: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    description: str
    evidence_lines: tuple[int, ...]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        data["evidence_lines"] = list(self.evidence_lines)
        return data


def _by_source(events: Iterable[AuthEvent]) -> dict[str, list[AuthEvent]]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip:
            grouped[event.source_ip].append(event)
    for source_events in grouped.values():
        source_events.sort(key=lambda event: event.timestamp)
    return grouped


def _max_window(events: list[AuthEvent], *, event_type: str, window: int) -> list[AuthEvent]:
    """Return the largest contiguous window containing the requested event type."""
    candidates = [event for event in events if event.event_type == event_type]
    best: list[AuthEvent] = []
    left = 0
    for right, event in enumerate(candidates):
        while event.timestamp - candidates[left].timestamp > timedelta(seconds=window):
            left += 1
        current = candidates[left : right + 1]
        if len(current) > len(best):
            best = current
    return best


def detect_alerts(
    events: Iterable[AuthEvent], *, threshold: int = 5, window: int = 600
) -> list[Alert]:
    """Apply explainable threshold rules to parsed authentication events.

    The default threshold is five events in ten minutes. All rules operate on
    supplied log data only and do not perform network activity.
    """
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window <= 0:
        raise ValueError("window must be greater than zero")

    grouped = _by_source(events)
    alerts: list[Alert] = []

    for source_ip, source_events in grouped.items():
        failures = _max_window(source_events, event_type="failed_login", window=window)
        if len(failures) >= threshold:
            alerts.append(
                Alert(
                    rule_id="SSH-BRUTE-FORCE-001",
                    title="Possible SSH brute-force attack",
                    severity="high" if len(failures) >= threshold * 2 else "medium",
                    source_ip=source_ip,
                    username=failures[-1].username,
                    first_seen=failures[0].timestamp,
                    last_seen=failures[-1].timestamp,
                    event_count=len(failures),
                    description=(
                        f"Detected {len(failures)} failed SSH logins from {source_ip} "
                        f"within {window} seconds."
                    ),
                    evidence_lines=tuple(event.line_number for event in failures[:10]),
                )
            )

        invalid_users = [
            event
            for event in source_events
            if event.event_type == "failed_login" and "Invalid user" in event.message
        ]
        invalid_window = _max_window(
            invalid_users, event_type="failed_login", window=window
        )
        if len(invalid_window) >= 3:
            alerts.append(
                Alert(
                    rule_id="SSH-USER-PROBING-001",
                    title="Possible SSH username probing",
                    severity="medium",
                    source_ip=source_ip,
                    username=None,
                    first_seen=invalid_window[0].timestamp,
                    last_seen=invalid_window[-1].timestamp,
                    event_count=len(invalid_window),
                    description=(
                        f"Detected {len(invalid_window)} invalid usernames from {source_ip} "
                        f"within {window} seconds."
                    ),
                    evidence_lines=tuple(event.line_number for event in invalid_window[:10]),
                )
            )

        successes = [
            event for event in source_events if event.event_type == "successful_login"
        ]
        all_failures = [
            event for event in source_events if event.event_type == "failed_login"
        ]
        for success in successes:
            preceding = [
                failure
                for failure in all_failures
                if timedelta(0) <= success.timestamp - failure.timestamp <= timedelta(seconds=window)
            ]
            if len(preceding) >= threshold:
                alerts.append(
                    Alert(
                        rule_id="SSH-SUCCESS-AFTER-FAIL-001",
                        title="Successful SSH login after repeated failures",
                        severity="high",
                        source_ip=source_ip,
                        username=success.username,
                        first_seen=preceding[0].timestamp,
                        last_seen=success.timestamp,
                        event_count=len(preceding) + 1,
                        description=(
                            f"A successful SSH login from {source_ip} followed "
                            f"{len(preceding)} failed attempts within {window} seconds."
                        ),
                        evidence_lines=tuple(
                            event.line_number for event in (preceding[-9:] + [success])
                        ),
                    )
                )

    return sorted(alerts, key=lambda alert: alert.last_seen)
