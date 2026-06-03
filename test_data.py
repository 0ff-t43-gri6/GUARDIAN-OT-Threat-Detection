
from influxdb import InfluxDBClient
import random
import time
from datetime import datetime

WINDOWS_IP = "localhost"
INFLUX_PORT = 8086
DATABASE = "guardian"

print("=" * 55)
print("  GUARDIAN — Test Data Generator")
print("=" * 55)

try:
    client = InfluxDBClient(WINDOWS_IP, INFLUX_PORT)
    client.create_database(DATABASE)
    client.switch_database(DATABASE)
    print(f"[+] Connected to InfluxDB at {WINDOWS_IP}:{INFLUX_PORT}")
except Exception as e:
    print(f"[-] InfluxDB connection failed: {e}")
    exit(1)

# ============================================================
# HELPER FUNCTION — Write Alert
# ============================================================
def write_alert(rule, severity, description, mitre, src_ip="192.168.1.99"):
    point = [{
        "measurement": "alerts",
        "tags": {
            "severity": severity,
            "rule": rule,
            "src_ip": src_ip
        },
        "fields": {
            "description": description,
            "mitre": mitre,
            "count": 1
        }
    }]
    try:
        client.write_points(point)
        print(f"  [{severity}] {rule}: {description}")
    except Exception as e:
        print(f"  [ERROR] Failed to write alert: {e}")

# ============================================================
# HELPER FUNCTION — Write Modbus Traffic
# ============================================================
def write_traffic(src_ip, function_code, count=1):
    point = [{
        "measurement": "modbus_traffic",
        "tags": {
            "src_ip": src_ip,
            "function_code": str(function_code)
        },
        "fields": {
            "count": int(count),
            "unit_id": int(1)
        }
    }]
    try:
        client.write_points(point)
    except Exception as e:
        print(f"  [ERROR] Failed to write traffic: {e}")

# ============================================================
# HELPER FUNCTION — Write Process Data
# ALL values explicitly cast to float to avoid type conflicts
# ============================================================
def write_process_data(temperature, pressure, motor_speed, valve_pos):
    point = [{
        "measurement": "process_data",
        "tags": {
            "device": "PLC-01",
            "location": "Plant-A"
        },
        "fields": {
            "temperature":   float(temperature),
            "pressure":      float(pressure),
            "motor_speed":   float(motor_speed),
            "valve_position": float(valve_pos)
        }
    }]
    try:
        client.write_points(point)
    except Exception as e:
        print(f"  [ERROR] Failed to write process data: {e}")

# ============================================================
# SCENARIO 1 — Normal Operations (Baseline)
# ============================================================
print("\n[*] Scenario 1: Normal Operations (baseline data)...")
for i in range(20):
    write_traffic("192.168.1.10", 3)
    write_process_data(
        temperature  = float(75.0 + random.uniform(-2.0, 2.0)),
        pressure     = float(101.3 + random.uniform(-1.0, 1.0)),
        motor_speed  = float(1450.0 + random.uniform(-20.0, 20.0)),
        valve_pos    = float(45.0 + random.uniform(-2.0, 2.0))
    )
    time.sleep(0.1)
print("  [+] Normal baseline data pushed")

# ============================================================
# SCENARIO 2 — Unauthorized Write Attack
# ============================================================
print("\n[*] Scenario 2: Unauthorized Write Attack...")
for i in range(5):
    write_traffic("192.168.1.99", 6)
    write_alert(
        rule        = "UNAUTHORIZED_WRITE",
        severity    = "CRITICAL",
        description = "Unauthorized Modbus write detected on register 0",
        mitre       = "T0855 - Unauthorized Command Message",
        src_ip      = "192.168.1.99"
    )
    time.sleep(0.5)

# ============================================================
# SCENARIO 3 — Excessive Polling (Recon)
# ============================================================
print("\n[*] Scenario 3: Excessive Polling / Recon...")
for i in range(15):
    write_traffic("192.168.1.99", 3)
    time.sleep(0.1)

write_alert(
    rule        = "EXCESSIVE_POLLING",
    severity    = "MEDIUM",
    description = "High frequency polling detected — possible reconnaissance",
    mitre       = "T0840 - Network Connection Enumeration",
    src_ip      = "192.168.1.99"
)

# ============================================================
# SCENARIO 4 — Rogue Device
# ============================================================
print("\n[*] Scenario 4: Rogue Device Detection...")
write_alert(
    rule        = "ROGUE_DEVICE",
    severity    = "HIGH",
    description = "Unknown device appeared on OT network: 192.168.1.77",
    mitre       = "T0846 - Remote System Discovery",
    src_ip      = "192.168.1.77"
)
time.sleep(0.5)

# ============================================================
# SCENARIO 5 — Out-of-Range Value Injection
# ============================================================
print("\n[*] Scenario 5: Out-of-Range Value Injection...")
write_traffic("192.168.1.99", 6)
write_alert(
    rule        = "VALUE_INJECTION",
    severity    = "CRITICAL",
    description = "Out-of-range value 65535 injected into temperature register",
    mitre       = "T0855 - Unauthorized Command Message",
    src_ip      = "192.168.1.99"
)

write_process_data(
    temperature  = float(999.9),
    pressure     = float(999.9),
    motor_speed  = float(99999.0),
    valve_pos    = float(100.0)
)

# ============================================================
# SCENARIO 6 — Replay Attack
# ============================================================
print("\n[*] Scenario 6: Replay Attack...")
for i in range(5):
    write_traffic("192.168.1.99", 6)
    time.sleep(0.2)

write_alert(
    rule        = "REPLAY_ATTACK",
    severity    = "HIGH",
    description = "Identical Modbus command replayed 5 times in 10 seconds",
    mitre       = "T0856 - Spoof Reporting Message",
    src_ip      = "192.168.1.99"
)

print("\n" + "=" * 55)
print("  GUARDIAN Test Data Generation Complete!")
print("=" * 55)
print("\n  Data pushed to InfluxDB:")
print("  → Measurement: alerts")
print("  → Measurement: modbus_traffic")
print("  → Measurement: process_data")
print("\n  Scenarios simulated:")
print("   Scenario 1 — Normal operations baseline")
print("   Scenario 2 — Unauthorized write attack")
print("   Scenario 3 — Excessive polling / recon")
print("   Scenario 4 — Rogue device detection")
print("   Scenario 5 — Out-of-range value injection")
print("   Scenario 6 — Replay attack")
print("\n  Open Grafana → http://localhost:3000")
print("  Check GUARDIAN dashboard for live data!")
print("=" * 55)
