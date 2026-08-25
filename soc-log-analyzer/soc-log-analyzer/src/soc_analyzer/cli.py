"""Command-line interface for SOC Log Analyzer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .detections import detect_alerts
from .parser import parse_lines
from .report import build_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="Analyze SSH authentication logs for defensive SOC investigations.",
    )
    parser.add_argument("log_file", type=Path, help="Path to a syslog-style SSH log file")
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the complete JSON report to this path",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year to apply to syslog timestamps (default: 2026)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed-login threshold for detection (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=600,
        help="Detection window in seconds (default: 600)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.log_file.is_file():
        print(f"error: log file not found: {args.log_file}", file=sys.stderr)
        return 2

    try:
        with args.log_file.open("r", encoding="utf-8", errors="replace") as handle:
            events = parse_lines(handle, year=args.year)
        alerts = detect_alerts(events, threshold=args.threshold, window=args.window)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(
        events,
        alerts,
        source_file=str(args.log_file),
        threshold=args.threshold,
        window=args.window,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    summary = report["summary"]
    print(f"Events analyzed: {summary['events_analyzed']}")
    print(f"Failed logins:   {summary['failed_logins']}")
    print(f"Successful logins: {summary['successful_logins']}")
    print(f"Unique source IPs: {summary['unique_source_ips']}")
    print(f"Alerts:          {summary['alerts']}")

    for alert in alerts:
        print(
            f"[{alert.severity.upper()}] {alert.rule_id}: {alert.description} "
            f"(lines {', '.join(map(str, alert.evidence_lines))})"
        )

    if args.output:
        print(f"JSON report:      {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
