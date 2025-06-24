import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# --- Configuration ---
FAILED_ATTEMPTS_THRESHOLD = 5 # Corrected typo: should be plural 'ATTEMPTS'
TIME_WINDOW_SECONDS = 60 # For single IP/user brute force detection
ALERT_COOLDOWN_SECONDS = 300 # 5 minutes cooldown before re-alerting on the same (IP, Username) pair

# --- Global Dictionaries for state management ---
# Stores deque of timestamps for failed attempts by IP for time-based analysis
# Key: IP Address (str) -> Value: deque of datetime objects
ip_failed_attempts_timeline = defaultdict(lambda: deque(maxlen=100)) # Maxlen to prevent infinite memory growth

# Stores the last time an alert was sent for a specific (IP, Username) pair
# Key: (IP Address, Username) tuple -> Value: datetime object of last alert
active_alerts_cooldown = defaultdict(lambda: datetime.min) # Initialize with min datetime


def analyze_ssh_log(log_file_path="./OpenSSH_2k.log"):
    """
    Performs basic log analysis on an SSH log file to detect potential
    brute-force or scanning attempts.

    Args:
        log_file_path (str): The path to the SSH log file (e.g., /var/log/auth.log).

    Returns:
        dict: A dictionary containing analysis results, including:
              - 'failed_attempts_by_ip': Count of failed attempts per source IP.
              - 'invalid_users_by_ip': Count of invalid user attempts per source IP.
              - 'targeted_invalid_users': Count of attempts for specific invalid usernames.
              - 'detected_alerts': A list of unique, suppressed alerts generated during the analysis.
    """
    # Dictionaries to count attempts by IP and username (for summary report)
    failed_attempts_by_ip = defaultdict(int)
    invalid_users_by_ip = defaultdict(int)
    targeted_invalid_users = defaultdict(int)
    
    # NEW: List to store all generated alerts (will be returned in results)
    detected_alerts = []

    # Regex patterns to extract information from SSH log lines
    failed_password_pattern = re.compile(
        r".*Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    invalid_user_pattern = re.compile(
        r".*Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    auth_failure_pattern = re.compile(
        r".*authentication failure;.*rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    # This pattern captures the Timestamp from the start of then line
    timestamp_pattern = re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
    current_year = datetime.now().year # Assuming current year for log lines without year

    try:
        # Open the log file for reading
        with open(log_file_path, 'r') as f:
            for line in f:
                line = line.strip() # Remove leading/trailing whitespace

                # check the timestamp
                timestamp_match = timestamp_pattern.search(line)
                if not timestamp_match:
                    print(f"[WARNING] Line without timestamp data: {line}")
                    continue

                timestamp_string = timestamp_match.group(1)
                try:
                    # Add current year to parse correctly
                    event_time = datetime.strptime(f"{timestamp_string} {current_year}", "%b %d %H:%M:%S %Y")
                except ValueError:
                    print(f"[WARNING] Could not parse timestamp '{timestamp_string}' from line: {line}")
                    # If timestamp cannot be parsed, this line cannot be used for time-based analysis
                    continue 

                # Flag to check if any specific pattern matched
                matched_specific_pattern = False

                # Check for 'Failed password' entries (most detailed)
                match_failed_pass = failed_password_pattern.search(line)
                if match_failed_pass:
                    username = match_failed_pass.group(1)
                    ip_address = match_failed_pass.group(2)
                    failed_attempts_by_ip[ip_address] += 1
                    
                    # NEW: Add event to timeline for brute force check
                    ip_failed_attempts_timeline[ip_address].append(event_time)
                    
                    # Check for brute force alert and collect it
                    alert_message = _check_brute_force_alert(ip_address, username, event_time)
                    if alert_message:
                        detected_alerts.append(alert_message)

                    # If the user is explicitly 'invalid user', count that too for summary
                    if "invalid user" in line:
                         invalid_users_by_ip[ip_address] += 1
                         targeted_invalid_users[username] += 1
                    matched_specific_pattern = True
                    # Do NOT use continue here if you want other patterns to potentially match
                    # or if the order is not strictly hierarchical.
                    # Given the structure, 'continue' is fine if you prioritize specific patterns.
                    continue

                # Check for 'Invalid user' entries (less detailed than failed_password, but still contains user/ip)
                # Only process if not already caught by failed_password_pattern for this line
                if not matched_specific_pattern:
                    match_invalid_user = invalid_user_pattern.search(line)
                    if match_invalid_user:
                        username = match_invalid_user.group(1)
                        ip_address = match_invalid_user.group(2)
                        invalid_users_by_ip[ip_address] += 1
                        targeted_invalid_users[username] += 1
                        
                        # NEW: Add event to timeline for brute force check
                        ip_failed_attempts_timeline[ip_address].append(event_time)
                        
                        # Check for brute force alert and collect it
                        alert_message = _check_brute_force_alert(ip_address, username, event_time)
                        if alert_message:
                            detected_alerts.append(alert_message)
                        matched_specific_pattern = True
                        continue

                # Check for general 'authentication failure' entries (least detailed, IP only)
                # Only process if not already caught by more specific patterns for this line
                if not matched_specific_pattern:
                    match_auth_failure = auth_failure_pattern.search(line)
                    if match_auth_failure:
                        ip_address = match_auth_failure.group(1)
                        failed_attempts_by_ip[ip_address] += 1
                        
                        # NEW: Add event to timeline for brute force check
                        # Use "unknown_user" as a placeholder since this pattern doesn't capture username
                        ip_failed_attempts_timeline[ip_address].append(event_time)
                        
                        # Check for brute force alert and collect it
                        alert_message = _check_brute_force_alert(ip_address, "unknown_user", event_time)
                        if alert_message:
                            detected_alerts.append(alert_message)
                        matched_specific_pattern = True
                        continue # Done with this line

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return {}
    except Exception as e:
        print(f"An error occurred during log analysis: {e}")
        return {}

    # Return the analysis results, including the collected alerts
    return {
        "failed_attempts_by_ip": dict(failed_attempts_by_ip),
        "invalid_users_by_ip": dict(invalid_users_by_ip),
        "targeted_invalid_users": dict(targeted_invalid_users),
        "detected_alerts": detected_alerts # NEW: Return the list of alerts
    }

def _check_brute_force_alert(ip_address, username, current_event_time):
    """
    Checks for single IP/user brute-force within the time window and applies alert suppression.

    Args:
        ip_address (str): The source IP of the failed attempt.
        username (str): The targeted username.
        current_event_time (datetime): The timestamp of the current event.

    Returns:
        str or None: An alert message if a new alert needs to be triggered, otherwise None.
    """
    # Define the unique alert key for suppression (IP + targeted username)
    alert_key = (ip_address, username)

    # 1. Prune old entries from the deque (sliding window logic)
    while ip_failed_attempts_timeline[ip_address] and \
          (current_event_time - ip_failed_attempts_timeline[ip_address][0]).total_seconds() > TIME_WINDOW_SECONDS:
        ip_failed_attempts_timeline[ip_address].popleft()

    # 2. Check if the threshold for the current window is met
    if len(ip_failed_attempts_timeline[ip_address]) >= FAILED_ATTEMPTS_THRESHOLD:
        # 3. Check for alert suppression
        last_alert_time = active_alerts_cooldown[alert_key]
        
        # If no alert has been sent for this key, or if enough time has passed since the last alert
        if last_alert_time == datetime.min or \
           (current_event_time - last_alert_time).total_seconds() >= ALERT_COOLDOWN_SECONDS:
            
            # Generate the alert message
            alert_message = (f"[ALERT] Possible Brute-Force from IP {ip_address} (Target: {username}) - "
                             f"{len(ip_failed_attempts_timeline[ip_address])} attempts in {TIME_WINDOW_SECONDS} seconds.")
            
            # Update the last alert time for this key
            active_alerts_cooldown[alert_key] = current_event_time
            
            return alert_message
            
    return None # No alert to send


# Print the analysis results in a readable format
def print_analysis_results(results):
    """
    Prints the analysis results in a readable format.
    """
    if not results:
        print("------ No Results ------")
        return
    
    print("---- Log Analysis Complete ----")

    # NEW: Print the detected alerts first
    print("\n--- Detected Brute-Force Alerts (Suppressed) ---")
    if results.get('detected_alerts'): # Use .get() for safety
        # Sorting alerts by timestamp or IP might be useful for readability
        for alert in results['detected_alerts']:
            print(alert)
    else:
        print("  No brute-force alerts detected based on thresholds.")

    # Print overall failed login attempts by IP
    print("\n-- Overall Failed Login Attempts by IP --")
    if results['failed_attempts_by_ip']:
        # Sort the IP by count for better readability
        sorted_ips = sorted(results['failed_attempts_by_ip'].items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_ips:
            print(f"  IP: {ip} - Total Attempts: {count}")
    else:
        print("  No overall failed login attempts.")

    # Print overall invalid user login attempts by IP
    print("\n-- Overall Invalid User Login Attempts by IP --")
    if results['invalid_users_by_ip']:
        sorted_ips = sorted(results['invalid_users_by_ip'].items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_ips:
            print(f"  IP: {ip} - Total Invalid User Attempts: {count}")
    else:
        print("  No overall invalid user login attempts.")

    # Print overall frequently targeted invalid usernames
    print("\n-- Overall Frequently Targeted Invalid Usernames --")
    if results['targeted_invalid_users']:
        sorted_users = sorted(results['targeted_invalid_users'].items(), key=lambda item: item[1], reverse=True)
        for user, count in sorted_users:
            print(f"  Username: '{user}' - Total Attempts: {count}")
    else:
        print("  No overall specific invalid usernames targeted.")

    print("\n--- End of Analysis ---")


if __name__=="__main__":
    print("Starting Log analysis...")
    log = "./OpenSSH_2k.log"
    print(f"Analyzing log file: {log}\n")
    log_data = analyze_ssh_log(log)
    print_analysis_results(log_data)
