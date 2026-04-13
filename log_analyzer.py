# Security Log Analyzer
# Author: Joseph Campbell
# Purpose: Analyze security logs for suspicious patterns, failed logins, and after-hours access

# Step 1: Open and read the log file
with open('security_log.txt', 'r') as file:
    logs = file.readlines()  # Read all lines from the file into a list

# Step 2: Parse the log data and store it in a structured format
parsed_logs = []  # Create an empty list to store parsed log entries

for line in logs:
    # Split each line by the pipe character (|) to separate fields
    parts = line.split("|")
    
    # Extract timestamp from the first part of the line and remove extra whitespace
    timestamp = parts[0].strip()
    
    # Extract IP address: split by colon and take the second part, remove whitespace
    ip = parts[1].split(":")[1].strip()
    
    # Extract username: split by colon and take the second part, remove whitespace
    user = parts[2].split(":")[1].strip()
    
    # Extract status (SUCCESS or FAILED): split by colon and take the second part, remove whitespace
    status = parts[3].split(":")[1].strip()
    
    # Store the parsed data as a dictionary and add it to the list
    parsed_logs.append({
        "timestamp": timestamp,
        "ip": ip,
        "user": user,
        "status": status
    })

# Step 3: Analyze the logs for suspicious patterns

# Count failed login attempts for each IP address
failed_attempts = {}  # Create a dictionary to track failed attempts per IP

for log in parsed_logs:
    # Check if the log entry has a FAILED status
    if log['status'] == 'FAILED':
        ip = log['ip']  # Get the IP address from the log entry
        
        # If this IP is already in the dictionary, increment the count
        if ip in failed_attempts:
            failed_attempts[ip] += 1
        # If this is the first failed attempt from this IP, set count to 1
        else:
            failed_attempts[ip] = 1

# Flag IPs with 4 or more failed login attempts as suspicious
suspicious_ips = {}  # Create a dictionary for suspicious IPs

for ip, count in failed_attempts.items():
    # If an IP has 4 or more failed attempts, add it to suspicious list
    if count >= 4:
        suspicious_ips[ip] = count

# Flag access attempts that occur during after-hours (10 PM to 6 AM)
after_hours = []  # Create a list to store after-hours access attempts

for log in parsed_logs:
    # Extract the time portion from the timestamp (e.g., "22:33:22")
    time_part = log['timestamp'].split()[1]
    
    # Extract just the hour (e.g., 22 from "22:33:22")
    hour = int(time_part.split(':')[0])
    
    # Check if the hour is 10 PM (22) or later, or before 6 AM
    # This captures all after-hours access from 10 PM to 6 AM
    if hour >= 22 or hour < 6:
        after_hours.append(log)  # Add this log entry to the after-hours list

# Step 4: Output a formatted security report

# Print the report header
print("\n" + "="*50)
print("SECURITY LOG ANALYSIS REPORT")
print("="*50)

# Print total number of log entries processed
print(f"\nTotal entries processed: {len(parsed_logs)}")

# Print section for suspicious IPs with high failed login counts
print("\nSuspicious IPs (4+ failed attempts):")
if suspicious_ips:
    # If suspicious IPs were found, print each one with its failed attempt count
    for ip, count in suspicious_ips.items():
        print(f"  - {ip}: {count} failed attempts")
else:
    # If no suspicious IPs were found, print a message indicating this
    print("  None detected")

# Print section for after-hours access attempts
print("\nAfter-hours access (10 PM - 6 AM):")
if after_hours:
    # If after-hours access was found, print details for each attempt
    for log in after_hours:
        print(f"  - {log['timestamp']} | {log['ip']} ({log['user']}) - {log['status']}")
else:
    # If no after-hours access was found, print a message indicating this
    print("  None detected")

# Print the report footer
print("\n" + "="*50)