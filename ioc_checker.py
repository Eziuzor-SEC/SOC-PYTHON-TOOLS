# IOC Checker - Basic IP Reputation Tool
# Author: Eziuzor Michael Ekene (Loz)
# Description: Takes an IP address as input and checks it against
# A list of known malicious IPs. Returns ALERT or CLEAN verdict.
# Use case: SOC tier 1 triage, manual IOC verification

malicious_ips = ["185.220.101.5", "45.155.205.233", "194.26.29.156"] 
while True:
    user_input = input("Enter IP to check (or 'quit' to exit): ") 
    ip = user_input.strip().lower() 

    if ip == "quit":
        print("Exiting IOC checker.")
        break
    elif ip in malicious_ips:
        print("ALERT: " + ip + " is a known malicious IP!")
    else:
        print("CLEAN: " + ip + " is not in the malicious IP list.")    
