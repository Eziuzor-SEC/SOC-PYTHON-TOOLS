# Log Parser - Failed Login Detector
# Author: Eziuzor Michael Ekene 
# Description: Reads a log file, detects failed login attempts,
# counts them per IP, and flags IPs that cross a threshold.
# Use case: SOC brute force detection, log triage automation

failed_logins = {}
threshold = 3

try: 
    with open("sample.log", "r") as log_file:
        for line in log_file:
            if "Failed login attempt from" in line:
                ip = line.strip().split()[-1]
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

        for ip, count in failed_logins.items():
            if count >= threshold:
                 print("ALERT: " + ip + " had " + str(count) + " failed logins - possible brute force!") 
except FileNotFoundError:
    print("Error: sample.log file not found. Please check the file path.")               
    