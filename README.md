# SOC Python Tools

A collection of Python scripts built for SOC automation, IOC checking, and threat detection.

## About
Built by Eziuzor Michael Ekene. SOC Analyst and Blue Team Practitioner based in Lagos, Nigeria. These tools demonstrate practical Python application in real SOC workflows.

## Tools

### 1. IOC Checker
**File:** `ioc_checker.py`  
**What it does:** Takes an IP address as input and checks it against a list of known malicious IPs. Returns an ALERT or CLEAN verdict.  
**SOC use case:** Tier 1 triage, manual IOC verification during incident investigation.  
**Concepts used:** Lists, while loops, conditions, string methods, user input.

## Skills Demonstrated
- Python scripting for security automation
- IOC verification logic
- Input sanitisation using string methods
- Continuous loop for analyst workflow

### 2. Log Parser - Brute Force Detector
**File:** `log_parser.py`  
**What it does:** Reads a log file, counts failed login attempts per IP address, and flags any IP that crosses a defined threshold as a possible brute force attack.  
**SOC use case:** Automated brute force detection, log triage, reducing manual log review time.  
**Concepts used:** File reading, for loops, dictionaries, conditions, string methods, try/except error handling.

## Roadmap
More tools coming. log parser, brute force detector, alert enrichment script.
