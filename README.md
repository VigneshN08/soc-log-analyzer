# SOC Log Analyzer

A Python tool that parses web server logs and automatically detects common attack patterns — built to practice the kind of log analysis work that SOC analysts do daily.

---

## What it detects

| Attack | How it works | Severity |
|--------|-------------|----------|
| Brute Force | Flags any IP with 5+ failed logins to `/login` | 🔴 HIGH |
| SQL Injection | Scans URLs for known SQL payloads (DROP TABLE, UNION SELECT, etc.) | 🔴 CRITICAL |
| Reconnaissance | Catches IPs probing sensitive paths like `/admin`, `/.env`, `/backup` | 🟡 MEDIUM |

---

## How it works

```
sample_logs.txt  →  parse each line  →  apply detection rules  →  security_report.txt
```

1. Reads every line of the log file
2. Extracts IP address, HTTP method, request path, and status code using regex
3. Applies three rules-based detection checks
4. Outputs a structured report with severity levels and recommended actions

---

## Sample output

```
=======================================================
         SOC SECURITY DETECTION REPORT
=======================================================

Total alerts: 3

-------------------------------------------------------

Alert #1
  Type       : Brute Force Attack
  Source IP  : 192.168.1.50
  Severity   : 🔴 HIGH
  Details    : 8 failed login attempts from this IP
  Action     : Block this IP and check if any attempt succeeded

-------------------------------------------------------

Alert #2
  Type       : SQL Injection Attempt
  Source IP  : 10.0.0.25
  Severity   : 🔴 CRITICAL
  Details    : 3 malicious request(s) detected
  Action     : Block IP, review database logs, check for data loss

-------------------------------------------------------

Alert #3
  Type       : Reconnaissance / Probing
  Source IP  : 172.16.0.99
  Severity   : 🟡 MEDIUM
  Details    : Accessed 5 sensitive path(s): /admin, /.env, /wp-admin, /backup.zip, /admin/config.php
  Action     : Monitor this IP and block if activity continues

-------------------------------------------------------

Summary
  Critical : 1
  High     : 1
  Medium   : 1
=======================================================
```

---

## Project structure

```
soc-log-analyzer/
  log_analyzer.py       # main script — parses logs and runs detection
  sample_logs.txt       # test log file with simulated attack traffic
  security_report.txt   # generated automatically when you run the tool
```

---

## Getting started

**Requirements:** Python 3 — no external libraries needed, only built-ins.

```bash
# Clone the repo
git clone https://github.com/YOUR-USERNAME/soc-log-analyzer.git
cd soc-log-analyzer

# Run the analyzer
python log_analyzer.py
```

The tool reads `sample_logs.txt` and writes the report to `security_report.txt`.

To analyze your own log file, change this line in `log_analyzer.py`:

```python
LOG_FILE = "your_log_file.txt"
```

---

## Detection logic

**Brute force** — triggers when the same IP sends 5 or more `POST /login` requests that return `401`. All three conditions are required together to avoid false positives.

**SQL injection** — checks every request path for known SQL fragments. The comparison is case-insensitive so it catches attempts like `union select` or `DrOp TaBlE` too.

**Reconnaissance** — uses `startswith` rather than a general string match so pages like `/about-admin-features` don't accidentally trigger the rule.

---

## What I'd add next

- Real-time monitoring by watching the log file for new lines as they come in
- IP reputation lookup using the AbuseIPDB or VirusTotal API
- JSON export for feeding alerts into a SIEM dashboard
- Anomaly-based detection to catch patterns that don't match known signatures

---

## Skills demonstrated

`log analysis` `threat detection` `detection engineering` `Python` `regex` `SOC workflows` `incident triage`
