#!/usr/bin/env python3
"""Analyze security and system logs from the command line."""

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
FAILED_LOGIN_MARKERS = ("failed login", "login_failed", "authentication failure")


def extract_ipv4(line):
    """Return the first valid IPv4 address in a log line, if present."""
    for candidate in IPV4_PATTERN.findall(line):
        try:
            return str(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            continue
    return None


def analyze_log(path, threshold=4):
    """Analyze a log file and return summary data."""
    summary = {
        "total_events": 0,
        "information": 0,
        "warnings": 0,
        "errors": 0,
        "failed_logins": 0,
        "successful_logins": 0,
    }
    failed_ip_counts = Counter()
    error_lines = []

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for raw_line in log_file:
            line = raw_line.strip()
            if not line:
                continue

            summary["total_events"] += 1
            lower = line.lower()

            # Count severity labels independently from authentication events.
            if "information" in lower or re.search(r"\binfo\b", lower):
                summary["information"] += 1
            if "warning" in lower or re.search(r"\bwarn\b", lower):
                summary["warnings"] += 1
            if re.search(r"\berror\b", lower):
                summary["errors"] += 1
                error_lines.append(line)

            if any(marker in lower for marker in FAILED_LOGIN_MARKERS):
                summary["failed_logins"] += 1
                ip_address = extract_ipv4(line)
                if ip_address:
                    failed_ip_counts[ip_address] += 1

            if "login_success" in lower or "login successful" in lower:
                summary["successful_logins"] += 1

    alerts = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in sorted(
            failed_ip_counts.items(), key=lambda item: (-item[1], item[0])
        )
        if count >= threshold
    ]

    return {
        "source_file": str(path),
        "threshold": threshold,
        "summary": summary,
        "failed_attempts_by_ip": dict(
            sorted(failed_ip_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "alerts": alerts,
        "error_lines": error_lines,
    }


def print_report(report):
    summary = report["summary"]
    print("\n=== SECURITY LOG ANALYZER ===")
    print(f"Source file         : {report['source_file']}")
    print(f"Total events        : {summary['total_events']}")
    print(f"Information events  : {summary['information']}")
    print(f"Warning events      : {summary['warnings']}")
    print(f"Error events        : {summary['errors']}")
    print(f"Failed logins       : {summary['failed_logins']}")
    print(f"Successful logins   : {summary['successful_logins']}")

    print("\nFailed login attempts by IP:")
    counts = report["failed_attempts_by_ip"]
    if counts:
        for ip, count in counts.items():
            print(f"  {ip:<18} {count}")
    else:
        print("  No valid IP addresses found in failed-login events.")

    print(f"\nAlerts (threshold: {report['threshold']} failed attempts):")
    if report["alerts"]:
        for alert in report["alerts"]:
            print(
                f"  [ALERT] {alert['ip']} — "
                f"{alert['failed_attempts']} failed attempts"
            )
    else:
        print("  No IP addresses reached the alert threshold.")

    if report["error_lines"]:
        print("\nError log entries:")
        for line in report["error_lines"]:
            print(f"  [ERROR] {line}")


def export_json(report, output_path):
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def export_csv(report, output_path):
    """Export summary, IP counts, and alerts as a simple normalized CSV."""
    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(["section", "metric", "value"])
        for key, value in report["summary"].items():
            writer.writerow(["summary", key, value])
        for ip, count in report["failed_attempts_by_ip"].items():
            writer.writerow(["failed_attempts_by_ip", ip, count])
        for alert in report["alerts"]:
            writer.writerow(["alert", alert["ip"], alert["failed_attempts"]])
        writer.writerow(["configuration", "threshold", report["threshold"]])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze system/authentication logs and flag repeated failed logins."
    )
    parser.add_argument(
        "-i", "--input", default="security.log",
        help="Path to input log file (default: security.log)",
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=4,
        help="Failed attempts from one IP required to trigger an alert (default: 4)",
    )
    parser.add_argument(
        "--format", choices=("json", "csv"),
        help="Optional report format to export",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output report path (default: report.json or report.csv)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.threshold < 1:
        print("Error: --threshold must be at least 1.", file=sys.stderr)
        return 2

    input_path = Path(args.input)
    if not input_path.is_file():
        print(
            f"Error: input log file not found: {input_path}\n"
            "Use --input PATH to specify an existing log file.",
            file=sys.stderr,
        )
        return 2

    try:
        report = analyze_log(input_path, args.threshold)
        print_report(report)

        if args.format:
            default_name = "report.json" if args.format == "json" else "report.csv"
            output_path = Path(args.output) if args.output else Path(default_name)
            if output_path.resolve() == input_path.resolve():
                print("Error: report output cannot overwrite the input log.", file=sys.stderr)
                return 2
            if args.format == "json":
                export_json(report, output_path)
            else:
                export_csv(report, output_path)
            print(f"\nReport exported to: {output_path}")

    except OSError as exc:
        print(f"Error reading or writing file: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
