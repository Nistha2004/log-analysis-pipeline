from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
import argparse
import re

TIMESTAMP_RE = re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+)")
IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

@dataclass
class ParsedEvent:
    timestamp: datetime
    ip: str
    status: str   # "failed" | "success" | "unknown"
    username: str


def parse_auth_log(log_file: str, year: int):
    events = []

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            timestamp_match = TIMESTAMP_RE.search(line)
            if not timestamp_match:
                continue

            timestamp = datetime.strptime(
                f"{year} {timestamp_match.group(1)}",
                "%Y %b %d %H:%M:%S",
            )

            failed_match = FAILED_RE.search(line)
            if failed_match:
                events.append(
                    ParsedEvent(
                        timestamp=timestamp,
                        ip=failed_match.group(2),
                        status="failed",
                        username=failed_match.group(1),
                    )
                )
                continue

            accepted_match = ACCEPTED_RE.search(line)
            if accepted_match:
                events.append(
                    ParsedEvent(
                        timestamp=timestamp,
                        ip=accepted_match.group(2),
                        status="success",
                        username=accepted_match.group(1),
                    )
                )
                continue

            generic_ip = IP_RE.search(line)
            if generic_ip:
                events.append(
                    ParsedEvent(
                        timestamp=timestamp,
                        ip=generic_ip.group(1),
                        status="unknown",
                        username="-",
                    )
                )

    return events


def detect_suspicious_activity(events, fail_threshold, rapid_window_seconds, stuffing_user_threshold):
    failed_by_ip = defaultdict(list)
    failed_users_by_ip = defaultdict(set)
    success_by_ip = defaultdict(int)
    success_after_fail = set()

    for event in events:
        if event.status == "failed":
            failed_by_ip[event.ip].append(event.timestamp)
            failed_users_by_ip[event.ip].add(event.username)
        elif event.status == "success":
            success_by_ip[event.ip] += 1
            if event.ip in failed_by_ip:
                success_after_fail.add(event.ip)

    alerts = []

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        total_failures = len(timestamps)

        rapid_attack = False

        if total_failures >= fail_threshold:
            for i in range(total_failures - fail_threshold + 1):
                window = (timestamps[i + fail_threshold - 1] - timestamps[i]).total_seconds()

                if window <= rapid_window_seconds:
                    alerts.append(
                        f"HIGH ALERT: Rapid brute-force from {ip} "
                        f"({fail_threshold} failures in {int(window)}s)"
                    )
                    rapid_attack = True
                    break

        if not rapid_attack and total_failures >= fail_threshold:
            alerts.append(
                f"HIGH ALERT: Persistent brute-force from {ip} "
                f"({total_failures} failed attempts)"
            )
        elif 1 < total_failures < fail_threshold:
            alerts.append(
                f"MEDIUM ALERT: Multiple failed attempts from {ip} "
                f"({total_failures} failures)"
            )
        elif total_failures == 1:
            alerts.append(f"LOW ALERT: Single failed attempt from {ip}")

        distinct_users = len(failed_users_by_ip[ip])
        if distinct_users >= stuffing_user_threshold:
            alerts.append(
                f"HIGH ALERT: Possible credential stuffing from {ip} "
                f"({distinct_users} usernames targeted)"
            )

    for ip, count in success_by_ip.items():
        if ip in success_after_fail:
            alerts.append(
                f"INFO: Successful login after failures from {ip} "
                f"({count} successful logins)"
            )
        else:
            alerts.append(f"INFO: Successful login from {ip} ({count} successful logins)")

    stats = {
        "total_events": len(events),
        "failed_events": sum(1 for e in events if e.status == "failed"),
        "successful_events": sum(1 for e in events if e.status == "success"),
        "ips_with_failures": len(failed_by_ip),
        "ips_with_successes": len(success_by_ip),
    }

    return alerts, stats


def write_report(report_path, alerts, stats):
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Suspicious Activity Report\n\n")

        report.write("Summary\n")
        for key, value in stats.items():
            report.write(f"- {key}: {value}\n")

        report.write("\nAlerts\n")
        for alert in alerts:
            report.write(f"- {alert}\n")


def print_console_report(alerts, stats):
    print("\nSuspicious Activity Report\n")

    print("Summary")
    for key, value in stats.items():
        print(f"- {key}: {value}")

    print("\nAlerts")
    for alert in alerts:
        print(f"- {alert}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-file", default="logs/auth.log")
    parser.add_argument("--report-file", default="report.txt")
    parser.add_argument("--year", type=int, default=datetime.utcnow().year)
    parser.add_argument("--fail-threshold", type=int, default=3)
    parser.add_argument("--rapid-window-seconds", type=int, default=10)
    parser.add_argument("--stuffing-user-threshold", type=int, default=3)

    args = parser.parse_args()

    events = parse_auth_log(args.log_file, args.year)

    alerts, stats = detect_suspicious_activity(
        events,
        args.fail_threshold,
        args.rapid_window_seconds,
        args.stuffing_user_threshold,
    )

    print_console_report(alerts, stats)
    write_report(args.report_file, alerts, stats)


if __name__ == "__main__":
    main()
