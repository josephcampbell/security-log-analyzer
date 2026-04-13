# Security Log Analyzer

## Project Description
A Python script that analyzes security logs for suspicious patterns, including failed login attempts and after-hours access.

## Features
- Parses security log files in a structured format
- Counts failed login attempts per IP address
- Flags suspicious IPs with 4+ failed attempts
- Identifies after-hours access (10 PM - 6 AM)
- Generates a formatted security report

## Files
- `log_analyzer.py` - Main Python script
- `security_log.txt` - Sample log file for testing

## How to Run
1. Ensure you have Python 3 installed
2. Place `log_analyzer.py` and `security_log.txt` in the same directory
3. Open a terminal in that directory
4. Run: `python log_analyzer.py`

## Sample Output

==================================================
SECURITY LOG ANALYSIS REPORT
Total entries processed: 10
Suspicious IPs (4+ failed attempts):

203.45.67.89: 4 failed attempts

After-hours access (10 PM - 6 AM):

2026-04-12 22:45:33 | 10.0.0.42 (admin) - SUCCESS
2026-04-12 23:12:15 | 10.0.0.42 (admin) - SUCCESS
2026-04-12 22:33:22 | 172.16.0.15 (kdavis) - FAILED


## Skills Demonstrated
- File I/O in Python
- String parsing and manipulation
- Data structures (dictionaries, lists)
- Conditional logic
- Loop iteration
- Report generation

## Author
Joseph Campbell