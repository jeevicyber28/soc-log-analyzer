"""SOC Log Analyzer public package API."""

from .detections import Alert, detect_alerts
from .parser import AuthEvent, parse_line, parse_lines
from .report import build_report

__all__ = [
    "Alert",
    "AuthEvent",
    "build_report",
    "detect_alerts",
    "parse_line",
    "parse_lines",
]
