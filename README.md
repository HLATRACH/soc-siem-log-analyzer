# python-siem-log-parser

A quick script I wrote to simulate a basic SIEM engine in a SOC environment. It parses server/traffic logs to detect specific web attacks and brute force attempts, then outputs alerts and creates a log report for incident investigation.

## What it does
1. **Generates sample log data**: Simulates standard enterprise log entries (`network_traffic.log`) mixed with bad payloads.
2. **Scans lines using Regex**: Parses the logs line by line to match known attack signatures.
3. **Triggers alerts & Saves history**: Prints real-time alerts to console (simulating a Slack webhook trigger) and logs the data to `soc_alerts.txt`.

## Attacks Covered
* **Brute Force**: Detects if an IP address hits 5 failed login attempts in less than 30 seconds.
* **SQL Injection**: Catches standard bypass techniques like `OR 1=1`.
* **XSS**: Flags basic script injections (`<script>`).
* **Path Traversal**: Flags unauthorized access attempts to files like `/etc/passwd`.

## Code Breakdown
* `generate_sample_logs()`: Sets up the fake network log file.
* `run_siem_rules()`: The logic loop. It keeps track of failed login timestamps per IP and runs standard regex for web vector signatures.
* `trigger_alert()`: Formats the alert output and appends it to the threat history file.

## Sample Console Output
```text
[*] Monitoring network_traffic.log for security incidents...

[🚨 SIEM ALERT] Brute Force Attack Detected
Time: 2026-08-08 05:00:00
Source IP: 45.33.22.11
Details: Exceeded 5 failed logins within 30s.
Action: Blocked & Blacklisted via Firewall


