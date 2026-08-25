from datetime import datetime

import pytest

from soc_analyzer import build_report, detect_alerts, parse_line, parse_lines


FAILED = (
    "Aug 25 09:00:01 lab-host sshd[1001]: "
    "Failed password for alice from 198.51.100.24 port 51231 ssh2"
)
SUCCESS = (
    "Aug 25 09:06:20 lab-host sshd[1007]: "
    "Accepted password for alice from 198.51.100.24 port 51237 ssh2"
)


def test_parse_failed_login_line():
    event = parse_line(FAILED, year=2026, line_number=4)

    assert event is not None
    assert event.event_type == "failed_login"
    assert event.username == "alice"
    assert event.source_ip == "198.51.100.24"
    assert event.pid == 1001
    assert event.timestamp == datetime(2026, 8, 25, 9, 0, 1)
    assert event.line_number == 4


def test_unrelated_line_is_ignored():
    assert parse_line("Aug 25 09:30:00 lab-host systemd[1]: Started service.") is None
    assert parse_line("not a syslog line") is None


def test_brute_force_alert_is_created():
    lines = [
        f"Aug 25 09:0{i}:00 lab-host sshd[10{i}]: Failed password for alice from 198.51.100.24 port 5000{i} ssh2"
        for i in range(1, 6)
    ]
    events = parse_lines(lines, year=2026)
    alerts = detect_alerts(events, threshold=5, window=600)

    brute_force = [alert for alert in alerts if alert.rule_id == "SSH-BRUTE-FORCE-001"]
    assert len(brute_force) == 1
    assert brute_force[0].event_count == 5
    assert brute_force[0].severity == "medium"


def test_success_after_repeated_failures_is_high_severity():
    lines = [
        f"Aug 25 09:0{i}:00 lab-host sshd[20{i}]: Failed password for alice from 198.51.100.24 port 6000{i} ssh2"
        for i in range(1, 6)
    ] + [SUCCESS]
    alerts = detect_alerts(parse_lines(lines, year=2026), threshold=5, window=600)

    matching = [alert for alert in alerts if alert.rule_id == "SSH-SUCCESS-AFTER-FAIL-001"]
    assert len(matching) == 1
    assert matching[0].severity == "high"
    assert matching[0].event_count == 6


def test_invalid_user_probing_alert_is_created():
    lines = [
        f"Aug 25 09:1{i}:00 lab-host sshd[30{i}]: Invalid user user{i} from 192.0.2.44 port 4000{i}"
        for i in range(1, 4)
    ]
    alerts = detect_alerts(parse_lines(lines, year=2026), threshold=5, window=600)

    probing = [alert for alert in alerts if alert.rule_id == "SSH-USER-PROBING-001"]
    assert len(probing) == 1
    assert probing[0].event_count == 3


def test_report_contains_summary_counts():
    events = parse_lines([FAILED, SUCCESS], year=2026)
    report = build_report(
        events,
        [],
        source_file="samples/auth.log",
        threshold=5,
        window=600,
    )

    assert report["schema_version"] == "1.0"
    assert report["summary"]["events_analyzed"] == 2
    assert report["summary"]["failed_logins"] == 1
    assert report["summary"]["successful_logins"] == 1


def test_invalid_detection_configuration_is_rejected():
    events = parse_lines([FAILED], year=2026)
    with pytest.raises(ValueError):
        detect_alerts(events, threshold=1)
    with pytest.raises(ValueError):
        detect_alerts(events, window=0)
