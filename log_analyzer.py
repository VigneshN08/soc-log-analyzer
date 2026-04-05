# SOC Web Log Analyzer
# I built this to practice log analysis and detection engineering.
# The tool reads web server logs, applies detection rules, and
# outputs a report showing what suspicious activity was found.
# Inspired by how SIEM tools like Splunk work under the hood.

import re
from collections import defaultdict

# -------------------------------------------------------------------
# Configuration
# I put all the thresholds and lists up here so they are easy to
# find and adjust without digging through the actual logic below.
# -------------------------------------------------------------------

# If an IP fails to log in this many times, I treat it as brute force.
# 5 felt like a reasonable cutoff after testing a few values.
BRUTE_FORCE_THRESHOLD = 5

# These are fragments that show up in SQL injection attempts.
# I based this list on the OWASP Top 10 injection examples.
SQL_INJECTION_PATTERNS = [
    "' OR '",
    "1=1",
    "DROP TABLE",
    "UNION SELECT",
    "INSERT INTO",
    "--",
    "';",
]

# Paths that normal users would never request but attackers commonly probe.
# Things like admin panels, config files, backup archives, and so on.
SUSPICIOUS_PATHS = [
    "/admin",
    "/admin/",
    "/config",
    "/.env",
    "/wp-admin",
    "/backup",
    "/phpmyadmin",
    "/shell",
    "/.git",
    "/etc/passwd",
]


# -------------------------------------------------------------------
# Step 1: Parse each log line into its individual fields
# -------------------------------------------------------------------

def parse_log_line(line):
    # Standard Apache/Nginx log format.
    # I use a regex here because the log line has quoted sections and
    # brackets that make a simple split unreliable.
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(\w+) ([^\s]+) HTTP.*?" (\d+)'
    match = re.search(pattern, line)

    if match:
        return {
            "ip":     match.group(1),
            "method": match.group(2),
            "path":   match.group(3),
            "status": int(match.group(4)),
        }

    # If the line does not match the expected format, return None
    # so the caller knows to skip it.
    return None


# -------------------------------------------------------------------
# Step 2: Read the log file and apply the three detection rules
# -------------------------------------------------------------------

def analyze_logs(log_file_path):
    # These track counts and paths per IP across the whole file.
    failed_logins  = defaultdict(int)
    sql_attempts   = defaultdict(list)
    recon_attempts = defaultdict(list)

    alerts = []

    try:
        with open(log_file_path, "r") as log_file:
            for line in log_file:
                entry = parse_log_line(line.strip())

                # Skip lines that do not look like valid log entries.
                if not entry:
                    continue

                ip     = entry["ip"]
                method = entry["method"]
                path   = entry["path"]
                status = entry["status"]

                # Rule 1: Brute force detection
                # I check for POST to /login with a 401 response.
                # All three conditions together reduce false positives.
                if method == "POST" and "/login" in path and status == 401:
                    failed_logins[ip] += 1

                # Rule 2: SQL injection detection
                # I convert both sides to uppercase so the check catches
                # mixed-case attempts like 'Drop Table' or 'union select'.
                for pattern in SQL_INJECTION_PATTERNS:
                    if pattern.upper() in path.upper():
                        sql_attempts[ip].append(path)
                        break

                # Rule 3: Reconnaissance detection
                # Using startswith so something like /about-admin-page
                # does not accidentally get flagged.
                for sensitive_path in SUSPICIOUS_PATHS:
                    if path.lower().startswith(sensitive_path.lower()):
                        recon_attempts[ip].append(path)
                        break

    except FileNotFoundError:
        print(f"Could not find the log file: {log_file_path}")
        return []

    # Now turn the raw counts and lists into structured alert objects.

    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type":           "Brute Force Attack",
                "ip":             ip,
                "severity":       "🔴 HIGH",
                "details":        f"{count} failed login attempts from this IP",
                "recommendation": "Block this IP and check if any attempt succeeded",
            })

    for ip, paths in sql_attempts.items():
        unique_paths = list(set(paths))
        alerts.append({
            "type":           "SQL Injection Attempt",
            "ip":             ip,
            "severity":       "🔴 CRITICAL",
            "details":        f"{len(unique_paths)} malicious request(s) detected",
            "recommendation": "Block IP, review database logs, check for data loss",
        })

    for ip, paths in recon_attempts.items():
        unique_paths = list(set(paths))
        alerts.append({
            "type":           "Reconnaissance / Probing",
            "ip":             ip,
            "severity":       "🟡 MEDIUM",
            "details":        f"Accessed {len(unique_paths)} sensitive path(s): {', '.join(unique_paths)}",
            "recommendation": "Monitor this IP and block if activity continues",
        })

    return alerts


# -------------------------------------------------------------------
# Step 3: Print the report to the terminal
# -------------------------------------------------------------------

def generate_report(alerts):
    print("\n" + "=" * 55)
    print("         SOC SECURITY DETECTION REPORT")
    print("=" * 55)

    if not alerts:
        print("\nNo suspicious activity found. Logs look clean.")
        return

    print(f"\nTotal alerts: {len(alerts)}\n")
    print("-" * 55)

    for index, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{index}")
        print(f"  Type       : {alert['type']}")
        print(f"  Source IP  : {alert['ip']}")
        print(f"  Severity   : {alert['severity']}")
        print(f"  Details    : {alert['details']}")
        print(f"  Action     : {alert['recommendation']}")
        print("-" * 55)

    critical = sum(1 for a in alerts if "CRITICAL" in a["severity"])
    high     = sum(1 for a in alerts if "HIGH"     in a["severity"])
    medium   = sum(1 for a in alerts if "MEDIUM"   in a["severity"])

    print(f"\nSummary")
    print(f"  Critical : {critical}")
    print(f"  High     : {high}")
    print(f"  Medium   : {medium}")
    print("\n" + "=" * 55 + "\n")


# -------------------------------------------------------------------
# Step 4: Save the report to a text file
# -------------------------------------------------------------------

def save_report(alerts, output_path="security_report.txt"):
    with open(output_path, "w") as report_file:
        report_file.write("SOC SECURITY DETECTION REPORT\n")
        report_file.write("=" * 55 + "\n\n")

        if not alerts:
            report_file.write("No suspicious activity found.\n")
            return

        report_file.write(f"Total alerts: {len(alerts)}\n\n")

        for index, alert in enumerate(alerts, start=1):
            report_file.write(f"Alert #{index}\n")
            report_file.write(f"  Type       : {alert['type']}\n")
            report_file.write(f"  Source IP  : {alert['ip']}\n")
            report_file.write(f"  Severity   : {alert['severity']}\n")
            report_file.write(f"  Details    : {alert['details']}\n")
            report_file.write(f"  Action     : {alert['recommendation']}\n")
            report_file.write("-" * 55 + "\n\n")

        critical = sum(1 for a in alerts if "CRITICAL" in a["severity"])
        high     = sum(1 for a in alerts if "HIGH"     in a["severity"])
        medium   = sum(1 for a in alerts if "MEDIUM"   in a["severity"])

        report_file.write("Summary\n")
        report_file.write(f"  Critical : {critical}\n")
        report_file.write(f"  High     : {high}\n")
        report_file.write(f"  Medium   : {medium}\n")

    print(f"Report saved to {output_path}")


# -------------------------------------------------------------------
# Run everything
# -------------------------------------------------------------------

if __name__ == "__main__":
    LOG_FILE = "sample_logs.txt"

    print(f"Reading {LOG_FILE}...")

    alerts = analyze_logs(LOG_FILE)
    generate_report(alerts)
    save_report(alerts)
    