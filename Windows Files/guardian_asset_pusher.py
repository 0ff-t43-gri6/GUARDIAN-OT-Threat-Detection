from influxdb import InfluxDBClient
from datetime import datetime

INFLUX_HOST = "192.168.29.226"
INFLUX_PORT = 8086
DATABASE    = "guardian"

try:
    db = InfluxDBClient(INFLUX_HOST, INFLUX_PORT)
    db.switch_database(DATABASE)
    print("[+] Connected to InfluxDB")
except Exception as e:
    print(f"[-] Failed: {e}")
    exit(1)

# Simulate asset impact events
asset_impacts = [
    {
        "asset_name":    "Temperature Controller — Zone A",
        "process":       "Heat Exchange System",
        "safety_risk":   "HIGH",
        "recovery_time": "2-4 hours",
        "attack_type":   "UNAUTHORIZED_WRITE",
        "src_ip":        "192.168.1.99",
        "severity":      "CRITICAL",
        "risk_score":    85
    },
    {
        "asset_name":    "Safety Instrumented System",
        "process":       "Emergency Shutdown System",
        "safety_risk":   "CRITICAL",
        "recovery_time": "Days/Weeks",
        "attack_type":   "UNAUTHORIZED_WRITE",
        "src_ip":        "192.168.1.99",
        "severity":      "CRITICAL",
        "risk_score":    99
    },
    {
        "asset_name":    "Motor Speed Drive — Pump Station A",
        "process":       "Water Pumping System",
        "safety_risk":   "HIGH",
        "recovery_time": "1-2 days",
        "attack_type":   "VALUE_INJECTION",
        "src_ip":        "192.168.1.99",
        "severity":      "CRITICAL",
        "risk_score":    78
    },
    {
        "asset_name":    "Pressure Control Valve — Line B",
        "process":       "Pipeline Pressure Management",
        "safety_risk":   "CRITICAL",
        "recovery_time": "4-8 hours",
        "attack_type":   "REPLAY_ATTACK",
        "src_ip":        "192.168.1.99",
        "severity":      "HIGH",
        "risk_score":    92
    },
    {
        "asset_name":    "Valve Actuator — Feed Line C",
        "process":       "Raw Material Feed Control",
        "safety_risk":   "MEDIUM",
        "recovery_time": "30min - 2hrs",
        "attack_type":   "UNAUTHORIZED_WRITE",
        "src_ip":        "192.168.1.99",
        "severity":      "HIGH",
        "risk_score":    65
    }
]

print("\n[*] Pushing asset impact data...")

for impact in asset_impacts:
    try:
        db.write_points([{
            "measurement": "asset_impacts",
            "tags": {
                "asset_name":  impact["asset_name"],
                "safety_risk": impact["safety_risk"],
                "severity":    impact["severity"],
                "attack_type": impact["attack_type"],
                "src_ip":      impact["src_ip"]
            },
            "fields": {
                "process":       impact["process"],
                "recovery_time": impact["recovery_time"],
                "risk_score":    int(impact["risk_score"]),
                "count":         1
            }
        }])
        print(f"  [+] {impact['asset_name']} → "
              f"Risk: {impact['risk_score']}/100")
    except Exception as e:
        print(f"  [-] Failed: {e}")

print("\n[+] Asset impact data pushed!")
print("[+] Check Grafana dashboard now")