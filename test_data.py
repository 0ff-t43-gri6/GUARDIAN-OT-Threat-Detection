from influxdb import InfluxDBClient
import random
import time
from datetime import datetime

client = InfluxDBClient('localhost', 8086)
client.create_database('guardian')
client.switch_database('guardian')

print("[+] Pushing test OT data to InfluxDB...")

for i in range(20):
    # Push fake Modbus traffic
    client.write_points([{
        "measurement": "modbus_traffic",
        "tags": {"src_ip": "192.168.1.10", "function_code": "3"},
        "fields": {"count": 1, "unit_id": 1}
    }])

    # Push fake alerts
    if i % 5 == 0:
        client.write_points([{
            "measurement": "alerts",
            "tags": {
                "severity": "CRITICAL",
                "rule": "UNAUTHORIZED_WRITE",
                "src_ip": "192.168.1.99"
            },
            "fields": {
                "description": "Unauthorized Modbus write detected",
                "mitre": "T0855",
                "count": 1
            }
        }])
        print(f"[ALERT] Pushed CRITICAL alert #{i}")

    time.sleep(0.5)

print("[+] Done! Check Grafana now.")