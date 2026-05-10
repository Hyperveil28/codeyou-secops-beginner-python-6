from enum import Enum
from collections import Counter


class AlertType(Enum):
    LOGIN_FAILURE = "login_failure"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    MALWARE_DETECTION = "malware_detection"
    NETWORK_SCAN = "network_scan"
    UNKNOWN = "unknown"


class SecurityAlert:
    """
    Represents a single cybersecurity alert.

    Each alert contains an asset, an indicator, an alert type, and a severity.
    The severity is assigned automatically based on the alert type.
    """

    def __init__(self, timestamp, asset, alert_type, indicator, description):
        self.timestamp = timestamp
        self.asset = asset
        self.alert_type = self.parse_alert_type(alert_type)
        self.indicator = indicator
        self.description = description
        self.severity = self.classify_severity()

    def parse_alert_type(self, alert_type):
        """
        Converts raw text from the alert file into a valid AlertType enum.
        If the type is not recognized, it is marked as UNKNOWN.
        """
        normalized_type = alert_type.strip().lower()

        for valid_type in AlertType:
            if normalized_type == valid_type.value:
                return valid_type

        return AlertType.UNKNOWN

    def classify_severity(self):
        """
        Assigns severity based on the alert type.
        """
        if self.alert_type == AlertType.MALWARE_DETECTION:
            return "High"
        elif self.alert_type == AlertType.NETWORK_SCAN:
            return "Medium"
        elif self.alert_type == AlertType.SUSPICIOUS_DOMAIN:
            return "Medium"
        elif self.alert_type == AlertType.LOGIN_FAILURE:
            return "Low"
        else:
            return "Unknown"

    def to_report_line(self):
        """
        Formats one alert into a readable report entry.
        """
        return (
            f"Timestamp: {self.timestamp}\n"
            f"Asset: {self.asset}\n"
            f"Alert Type: {self.alert_type.value}\n"
            f"Indicator: {self.indicator}\n"
            f"Severity: {self.severity}\n"
            f"Description: {self.description}\n"
        )


def read_alerts_from_file(filename):
    """
    Reads alert records from a text file and returns a list of SecurityAlert objects.

    Expected file format:
    timestamp|asset|alert_type|indicator|description
    """
    alerts = []

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if not line:
                    continue

                parts = line.split("|")

                if len(parts) != 5:
                    print(f"[!] Skipping malformed line {line_number}: {line}")
                    continue

                timestamp, asset, alert_type, indicator, description = parts
                alert = SecurityAlert(timestamp, asset, alert_type, indicator, description)
                alerts.append(alert)

    except FileNotFoundError:
        print(f"[!] Error: The file '{filename}' was not found.")

    return alerts


def summarize_alerts(alerts):
    """
    Creates summary statistics for the alert list.
    """
    total_alerts = len(alerts)
    severity_counts = Counter(alert.severity for alert in alerts)
    type_counts = Counter(alert.alert_type.value for alert in alerts)

    return total_alerts, severity_counts, type_counts


def write_report(alerts, output_filename):
    """
    Writes a structured incident triage report to a text file.
    """
    total_alerts, severity_counts, type_counts = summarize_alerts(alerts)

    with open(output_filename, "w", encoding="utf-8") as report:
        report.write("=" * 60 + "\n")
        report.write("INCIDENT TRIAGE TRACKER REPORT\n")
        report.write("=" * 60 + "\n\n")

        report.write("SUMMARY\n")
        report.write("-" * 60 + "\n")
        report.write(f"Total Alerts Reviewed: {total_alerts}\n\n")

        report.write("Alerts by Severity:\n")
        for severity, count in severity_counts.items():
            report.write(f"- {severity}: {count}\n")

        report.write("\nAlerts by Type:\n")
        for alert_type, count in type_counts.items():
            report.write(f"- {alert_type}: {count}\n")

        report.write("\n")
        report.write("=" * 60 + "\n")
        report.write("DETAILED ALERTS\n")
        report.write("=" * 60 + "\n\n")

        for alert in alerts:
            report.write(alert.to_report_line())
            report.write("-" * 60 + "\n")

    print(f"[+] Report written to {output_filename}")


def display_console_summary(alerts):
    """
    Displays a short analyst-friendly summary in the terminal.
    """
    total_alerts, severity_counts, type_counts = summarize_alerts(alerts)

    print("\nIncident Triage Tracker Summary")
    print("-" * 40)
    print(f"Total Alerts Reviewed: {total_alerts}")

    print("\nAlerts by Severity:")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    print("\nAlerts by Type:")
    for alert_type, count in type_counts.items():
        print(f"{alert_type}: {count}")


def main():
    input_file = "alerts.txt"
    output_file = "incident_report.txt"

    alerts = read_alerts_from_file(input_file)

    if not alerts:
        print("[!] No valid alerts were found. Report was not created.")
        return

    display_console_summary(alerts)
    write_report(alerts, output_file)


if __name__ == "__main__":
    main()