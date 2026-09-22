# Threat Intelligence Aggregator
# Author: Eziuzor Michael Ekene 
# Description: A Python class that queries VirusTotal and AbuseIPDB
# for any IP address and generates a structured threat intel report.
# Use case: SOC IOC enrichment, alert triage, threat investigation

import requests
import json
from datetime import datetime

from dotenv import load_dotenv
import os

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

class ThreatIntel:
    def __init__(self, indicator):
        self.indicator = indicator
        self.vt_result = None
        self.abuse_result = None
        self.risk_score = 0

    def check_virustotal(self):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.indicator}"
        headers = {"x-apikey": VT_API_KEY}

        try: 
            response = requests.get(url, headers=headers)
            self.vt_result = response.json()
            return self.vt_result
        except Exception as e:
            print("VirusTotal error: " + str(e))
            return None 

    def check_abuseipdb(self):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": self.indicator,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            self.abuse_result = response.json()
            return self.abuse_result
        except Exception as e:
            print("AbuseIPDB error: " + str(e))
            return None

    def calculate_risk_score(self):
        score = 0

        if self.vt_result:
            try:
                stats = self.vt_result["data"]["attributes"]["last_analysis_stats"]
                malicious = stats["malicious"]
                total = sum(stats.values())
                if total > 0:
                    score += (malicious / total) * 50
            except KeyError:
                pass

        if self.abuse_result:
            try:
                abuse_score = self.abuse_result["data"]["abuseConfidenceScore"]
                score += abuse_score * 0.5
            except KeyError:
                pass

        self.risk_score = round(score)
        return self.risk_score
    
    def generate_report(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if self.risk_score >= 61:
            verdict = "HIGH RISK"
            recommendation = "Block this IP immediately and investigate all connections."
        elif self.risk_score >= 31:
            verdict = "MEDIUM RISK"
            recommendation = "Monitor closely and investigate recent activity from this IP."
        else:
            verdict = "LOW RISK"
            recommendation = "No immediate action required. Continue monitoring."

        report = f"""
====================================================
THREAT INTELLIGENCE REPORT
====================================================
Timestamp     : {timestamp}
Indicator     : {self.indicator}
Risk Score    : {self.risk_score}/100
Verdict       : {verdict}

VIRUSTOTAL FINDINGS
----------------------------------------------------
"""
        if self.vt_result:
            try:
                stats = self.vt_result["data"]["attributes"]["last_analysis_stats"]
                report += f"Malicious Detections : {stats['malicious']}\n"
                report += f"Harmless Detections  : {stats['harmless']}\n"
                report += f"Suspicious           : {stats['suspicious']}\n"
            except KeyError:
                report += "VirusTotal data unavailable.\n"
        else:
            report += "VirusTotal query failed.\n"

        report += f"""
ABUSEIPDB FINDINGS
----------------------------------------------------
"""
        if self.abuse_result:
            try:
                data = self.abuse_result["data"]
                report += f"Abuse Confidence Score : {data['abuseConfidenceScore']}/100\n"
                report += f"Total Reports          : {data['totalReports']}\n"
                report += f"Country                : {data['countryCode']}\n"
            except KeyError:
                report += "AbuseIPDB data unavailable.\n"
        else:
            report += "AbuseIPDB query failed.\n"

        report += f"""
RECOMMENDATION
----------------------------------------------------
{recommendation}
====================================================
"""
        filename = f"report_{self.indicator}_{timestamp.replace(':', '-').replace(' ', '_')}.txt"
        
        with open(filename, "w") as f:
            f.write(report)
        
        print(report)
        print(f"Report saved to: {filename}")

if __name__ == "__main__":
    indicator = input("Enter IP address to investigate: ")
    
    print("\nInitialising threat intelligence check...")
    
    intel = ThreatIntel(indicator)
    
    print("Querying VirusTotal...")
    intel.check_virustotal()
    
    print("Querying AbuseIPDB...")
    intel.check_abuseipdb()
    
    print("Calculating risk score...")
    intel.calculate_risk_score()
    
    print("Generating report...")
    intel.generate_report()