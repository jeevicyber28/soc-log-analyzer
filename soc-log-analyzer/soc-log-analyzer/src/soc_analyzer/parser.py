"""Parsing helpers for common SSH authentication log lines."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
import ipaddress
import re
from typing import Iterable


_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_PREFIX_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_USER = r"(?P<user>\S+)"

_FAILED_PATTERNS = [
    re.compile(rf"Failed password for (?:invalid user )?{_USER} from {_IP} port"),
    re.compile(rf"Invalid user {_USER} from {_IP} port"),
    re.compile(rf"authentication failure;.*?user={_USER}.*?rhost={_IP}"),
]
_SUCCESS_RE = re.compile(
    rf"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    rf"(?:invalid user )?{_USER} from {_IP} port"
)


@dataclass(frozen=True)
class AuthEvent:
    """A normalized SSH authentication event."""

    timestamp: datetime
    host: str
    process: str
    pid: int | None
    event_type: str
    username: str | None
    source_ip: str | None
    message: str
    line_number: int
    raw: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


def _parse_timestamp(match: re.Match[str], year: int) -> datetime:
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    clock = match.group("time")
    return datetime.strptime(
        f"{year}-{month:02d}-{day:02d} {clock}", "%Y-%m-%d %H:%M:%S"
    )


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_line(line: str, *, year: int = 2026, line_number: int = 0) -> AuthEvent | None:
    """Parse one syslog-style line, returning an event only for auth activity."""
    raw = line.rstrip("\n")
    prefix = _PREFIX_RE.match(raw)
    if not prefix:
        return None

    message = prefix.group("message")
    event_type: str | None = None
    username: str | None = None
    source_ip: str | None = None

    for pattern in _FAILED_PATTERNS:
        found = pattern.search(message)
        if found:
            event_type = "failed_login"
            username = found.group("user")
            source_ip = _valid_ip(found.group("ip"))
            break

    if event_type is None:
        found = _SUCCESS_RE.search(message)
        if found:
            event_type = "successful_login"
            username = found.group("user")
            source_ip = _valid_ip(found.group("ip"))

    if event_type is None:
        return None

    return AuthEvent(
        timestamp=_parse_timestamp(prefix, year),
        host=prefix.group("host"),
        process=prefix.group("process"),
        pid=int(prefix.group("pid")) if prefix.group("pid") else None,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        message=message,
        line_number=line_number,
        raw=raw,
    )


def parse_lines(lines: Iterable[str], *, year: int = 2026) -> list[AuthEvent]:
    """Parse an iterable of lines and ignore malformed or unrelated entries."""
    events: list[AuthEvent] = []
    for line_number, line in enumerate(lines, start=1):
        event = parse_line(line, year=year, line_number=line_number)
        if event is not None:
            events.append(event)
    return events
