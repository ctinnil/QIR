import re
from collections import Counter

# Path to your web server's access log and output file for alerts
LOG_FILE_PATH = 'access.log'
ALERT_OUTPUT_PATH = 'alerts.txt'

# Adjusted Patterns dictionary to include both active and passive reconnaissance indicators
PATTERNS = {
    'active_user_agents': re.compile(r'(Nmap Scripting Engine|sqlmap|nikto|gobuster|dirbuster|curl|python-requests|python-urllib|wget)', re.IGNORECASE),
    'passive_reconnaissance': re.compile(r'(Shodan\/|CensysScan|ZoomEye)', re.IGNORECASE),
    'sql_injection_attempt': re.compile(r'(UNION SELECT|SELECT.*FROM|AND extractvalue|AND xp_).*', re.IGNORECASE),
    'directory_traversal': re.compile(r'(\.\./|\.\.\\)'),
    'malicious_dorks': re.compile(r'(inurl:|intitle:|filetype:|site:).*', re.IGNORECASE),
    'excessive_requests': 100,  # Threshold of requests from a single IP to trigger an alert
}

def analyze_logs(log_path, patterns):
    with open(log_path, 'r') as file:
        logs = file.readlines()

    alerts = []
    ip_counter = Counter()
    event_counts = {'Normal': 0, 'Suspicious': 0}

    for log in logs:
        ip = log.split(' ')[0]
        ip_counter[ip] += 1
        event_classified_as_normal = True

        # Check for active reconnaissance patterns
        if re.search(patterns['active_user_agents'], log) or re.search(patterns['passive_reconnaissance'], log) or re.search(patterns['malicious_dorks'], log):
            alerts.append(f"Suspicious Activity Detected by {ip}.")
            event_counts['Suspicious'] += 1
            event_classified_as_normal = False

        # Check for other patterns (SQL injection, directory traversal)
        for pattern_name, pattern in patterns.items():
            if pattern_name not in ['active_user_agents', 'passive_reconnaissance', 'malicious_dorks', 'excessive_requests'] and re.search(pattern, log):
                alerts.append(f"Suspicious Activity Detected by {ip}: Pattern matched for {pattern_name}.")
                event_counts['Suspicious'] += 1
                event_classified_as_normal = False
                break  # Once a match is found, no need to check other patterns for the same log entry

        if event_classified_as_normal:
            event_counts['Normal'] += 1

    # Write alerts to output file
    with open(ALERT_OUTPUT_PATH, 'w') as output_file:
        for alert in alerts:
            output_file.write(f"{alert}\n")

    return event_counts

def main():
    event_counts = analyze_logs(LOG_FILE_PATH, PATTERNS)
    print(f"Event Counts: {event_counts}")

if __name__ == '__main__':
    main()

