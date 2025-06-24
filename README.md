# SSH Log Analyzer

A Python script for analyzing SSH log files to detect potential brute-force attacks, invalid user attempts, and other suspicious activities. The analyzer provides a summary of failed login attempts, invalid user attempts, and highlights brute-force alerts based on configurable thresholds.

## Features
- Detects brute-force attacks from single IPs or targeted usernames within a configurable time window.
- Suppresses repeated alerts for the same (IP, Username) pair using a cooldown period.
- Summarizes failed login attempts by IP address.
- Summarizes invalid user login attempts by IP address and username.
- Prints a readable report of all findings and detected alerts.

## How It Works
- Parses SSH log files (e.g., `/var/log/auth.log` or exported logs) using regular expressions.
- Tracks failed login attempts and invalid user attempts per IP and username.
- Triggers alerts if the number of failed attempts from an IP (or for a username) exceeds a threshold within a short time window.
- Suppresses duplicate alerts for the same source within a cooldown period.

## Configuration
You can adjust the following parameters at the top of the script:
- `FAILED_ATTEMPTS_THRESHOLD`: Number of failed attempts within the time window to trigger an alert (default: 5).
- `TIME_WINDOW_SECONDS`: Time window (in seconds) for brute-force detection (default: 60).
- `ALERT_COOLDOWN_SECONDS`: Cooldown period (in seconds) before re-alerting on the same (IP, Username) pair (default: 300).

## Usage
1. Place your SSH log file in the same directory as the script, or specify the path to your log file.
2. Run the script using Python 3:

```bash
python ssh_log_analyzer.py
```

By default, it analyzes `./OpenSSH_2k.log`. To analyze a different file, modify the `log_file_path` argument in the `analyze_ssh_log` function call.

## Output
The script prints:
- Detected brute-force alerts (with suppression)
- Summary of failed login attempts by IP
- Summary of invalid user login attempts by IP
- Frequently targeted invalid usernames

## Example Output
```
---- Log Analysis Complete ----

--- Detected Brute-Force Alerts (Suppressed) ---
[ALERT] Possible Brute-Force from IP 192.168.1.10 (Target: root) - 5 attempts in 60 seconds.

-- Overall Failed Login Attempts by IP --
  IP: 192.168.1.10 - Total Attempts: 12

-- Overall Invalid User Login Attempts by IP --
  IP: 192.168.1.20 - Total Invalid User Attempts: 7

-- Overall Frequently Targeted Invalid Usernames --
  Username: 'admin' - Total Attempts: 4

--- End of Analysis ---
```

## Requirements
- Python 3.x
- No external dependencies (uses only standard library)

## File Structure
- `ssh_log_analyzer.py` — Main script for log analysis
- `OpenSSH_2k.log` — Example log file

## License
This project is provided for educational and security research purposes. Use responsibly.
