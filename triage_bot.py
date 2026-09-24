# Automated Alert Triage Bot
# Author: Eziuzor Michael Ekene 
# Description: Reads a JSON alert queue, enriches each IP using the
# ThreatIntel class, scores alerts by severity, sorts by priority,
# and generates a complete triage report.
# Use case: SOC tier 1 automation, alert queue prioritisation

import json
from datetime import datetime
from threat_intel import ThreatIntel

ALERT_TYPE_WEIGHTS = {
    "Malware C2": 30,
    "Brute Force": 20,
    "Suspicious Outbound": 15,
    "Port Scan": 10,
    "DNS Anomaly": 5
}

def load_alerts(filename):
    try:
        with open(filename, "r") as f:
            alerts = json.load(f)
            return alerts
    except FileNotFoundError:
        print("Error: alerts.json file not found.")
        return []
    except json.JSONDecodeError:
        print("Error: alerts.json is not valid JSON.")
        return []

def calculate_severity(risk_score, alert_type):
    base_score = risk_score
    weight = ALERT_TYPE_WEIGHTS.get(alert_type, 0)
    severity_score = base_score + weight
    
    if severity_score >= 80:
        severity = "CRITICAL"
    elif severity_score >= 60:
        severity = "HIGH"
    elif severity_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return severity_score, severity

def process_alerts(alerts):
    results = []
    
    for alert in alerts:
        print(f"\nProcessing alert {alert['alert_id']} - {alert['ip']}...")
        
        intel = ThreatIntel(alert['ip'])
        intel.check_virustotal()
        intel.check_abuseipdb()
        intel.calculate_risk_score()
        
        severity_score, severity = calculate_severity(
            intel.risk_score, 
            alert['alert_type']
        )
        
        results.append({
            "alert_id": alert['alert_id'],
            "timestamp": alert['timestamp'],
            "ip": alert['ip'],
            "alert_type": alert['alert_type'],
            "description": alert['description'],
            "risk_score": intel.risk_score,
            "severity_score": severity_score,
            "severity": severity
        })
    
    results.sort(key=lambda x: x['severity_score'], reverse=True)
    
    return results

def generate_triage_report(results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"triage_report_{timestamp.replace(':', '-').replace(' ', '_')}.txt"
    
    report = f"""
====================================================
SOC ALERT TRIAGE REPORT
====================================================
Generated   : {timestamp}
Total Alerts: {len(results)}
====================================================

"""
    for result in results:
        report += f"""
ALERT ID    : {result['alert_id']}
Timestamp   : {result['timestamp']}
IP Address  : {result['ip']}
Alert Type  : {result['alert_type']}
Description : {result['description']}
Risk Score  : {result['risk_score']}/100
Severity    : {result['severity']} ({result['severity_score']}/130)
----------------------------------------------------
"""
    
    with open(filename, "w") as f:
        f.write(report)
    
    print(report)
    print(f"Triage report saved to: {filename}")


if __name__ == "__main__":
    print("SOC Alert Triage Bot starting...")
    
    alerts = load_alerts("alerts.json")
    
    if not alerts:
        print("No alerts to process. Exiting.")
    else:
        print(f"Loaded {len(alerts)} alerts. Beginning enrichment...")
        results = process_alerts(alerts)
        generate_triage_report(results)
        print("\nTriage complete.")