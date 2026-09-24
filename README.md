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

### 3. Threat Intelligence Aggregator
**File:** `threat_intel.py`  
**What it does:** A Python class that queries VirusTotal and AbuseIPDB APIs for any IP address, calculates a composite risk score out of 100, and generates a structured investigation report saved to a text file.  
**SOC use case:** IOC enrichment, alert triage, automated threat investigation during incident response.  
**Concepts used:** Object oriented programming, API integration, JSON parsing, file writing, environment variables, error handling.

### 4. Automated Alert Triage Bot
**File:** `triage_bot.py`  
**What it does:** Reads a JSON alert queue, enriches each IP using the ThreatIntel class, calculates a combined severity score using threat intel results and alert type weights, sorts alerts by priority, and generates a complete triage report saved to a file.  
**SOC use case:** Tier 1 SOC automation, alert queue prioritisation, reducing manual triage time.  
**Concepts used:** JSON parsing, class importing, functions, sorting, f-strings, file writing, error handling.

## Roadmap
Portfolio complete. Four production-ready SOC automation tools demonstrating Python scripting, API integration, object oriented programming, and end-to-end alert triage automation.