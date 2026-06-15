from pymodbus.client import ModbusTcpClient
from influxdb import InfluxDBClient
import time
from datetime import datetime

# Change this to your Windows IP
WINDOWS_IP = "192.168.29.226"

# Connect to PLC (ModRSsim2)
plc = ModbusTcpClient(WINDOWS_IP, port=502)
plc.connect()

# Connect to InfluxDB
db = InfluxDBClient(WINDOWS_IP, 8086)
db.switch_database('guardian')

def log_alert(rule, severity, description, mitre):
    db.write_points([{
        "measurement": "alerts",
        "tags": {
            "severity": severity,
            "rule": rule,
            "src_ip": "192.168.1.99"
        },
        "fields": {
            "description": description,
            "mitre": mitre,
            "count": 1
        }
    }])
    print(f"[{severity}] {rule}: {description}")

print("=" * 50)
print("  GUARDIAN Attack Simulation Starting...")
print("=" * 50)

# Attack 1 — Unauthorized Write
print("\n[1] Unauthorized Write Attack...")
for i in range(5):
    plc.write_register(0, 9999)
    log_alert("UNAUTHORIZED_WRITE", "CRITICAL",
              "Unauthorized Modbus write detected",
              "T0855 - Unauthorized Command Message")
    time.sleep(1)

# Attack 2 — Excessive Polling (Recon)
print("\n[2] Excessive Polling (Recon)...")
for i in range(10):
    plc.read_holding_registers(address=0, count=10)
    db.write_points([{
        "measurement": "modbus_traffic",
        "tags": {"src_ip": "192.168.1.99", "function_code": "3"},
        "fields": {"count": 1, "unit_id": 1}
    }])
    time.sleep(0.2)
log_alert("EXCESSIVE_POLLING", "MEDIUM",
          "High frequency polling detected — possible recon",
          "T0840 - Network Connection Enumeration")

# Attack 3 — Rogue Device
print("\n[3] Rogue Device Simulation...")
log_alert("ROGUE_DEVICE", "HIGH",
          "Unknown device appeared on OT network",
          "T0846 - Remote System Discovery")
time.sleep(1)

# Attack 4 — Out of Range Value
print("\n[4] Out-of-Range Value Injection...")
plc.write_register(0, 65535)
log_alert("VALUE_INJECTION", "CRITICAL",
          "Out-of-range value injected into PLC register",
          "T0855 - Unauthorized Command Message")

plc.close()
print("\n" + "=" * 50)
print("  All attacks complete!")
print("  Check GUARDIAN dashboard now!")
print("=" * 50)

