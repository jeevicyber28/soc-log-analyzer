"""Report assembly for SOC Log Analyzer results."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from .detections import Alert
from .parser import AuthEvent


def build_report(
    events: Iterable[AuthEvent],
    alerts: Iterable[Alert],
    *,
    source_file: str,
    threshold: int,
    window: int,
) -> dict[str, object]:
    """Build a stable JSON-serializable report."""
    event_list = list(events)
    alert_list = list(alerts)
    severity_counts = Counter(alert.severity for alert in alert_list)
    source_ips = {event.source_ip for event in event_list if event.source_ip}

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": source_file,
        "configuration": {
            "failed_login_threshold": threshold,
            "window_seconds": window,
        },
        "summary": {
            "events_analyzed": len(event_list),
            "failed_logins": sum(event.event_type == "failed_login" for event in event_list),
            "successful_logins": sum(
                event.event_type == "successful_login" for event in event_list
            ),
            "unique_source_ips": len(source_ips),
            "alerts": len(alert_list),
            "severity_counts": dict(sorted(severity_counts.items())),
        },
        "events": [event.to_dict() for event in event_list],
        "alerts": [alert.to_dict() for alert in alert_list],
    }
