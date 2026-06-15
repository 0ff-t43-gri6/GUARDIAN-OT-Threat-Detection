from scapy.all import sniff, IP, TCP, Raw
from influxdb import InfluxDBClient
from datetime import datetime
from collections import defaultdict
import threading
import time

WINDOWS_IP    = "192.168.29.226"  
INFLUX_PORT   = 8086
DATABASE      = "guardian"
INTERFACE     = "eth0"            # Kali network interface

# Authorized IPs — anything else = rogue device
AUTHORIZED_IPS = ["192.168.29.226"]

# Write function codes = suspicious
WRITE_FCS = [5, 6, 15, 16]

# Polling threshold — requests per minute
POLLING_THRESHOLD = 30

print("=" * 55)
print("  GUARDIAN — Traffic Capture Engine")
print("=" * 55)

try:
    db = InfluxDBClient(WINDOWS_IP, INFLUX_PORT)
    db.switch_database(DATABASE)
    print(f"[+] Connected to InfluxDB")
except Exception as e:
    print(f"[-] InfluxDB connection failed: {e}")
    exit(1)

# ============================================================
# STATE TRACKING
# ============================================================
request_counter  = defaultdict(list)  # IP → list of timestamps
seen_commands    = []                  # for replay detection
known_devices    = set(AUTHORIZED_IPS) # authorized device list

# ============================================================
# HELPER — Write Alert to InfluxDB
# ============================================================
def write_alert(rule, severity, description, mitre, src_ip):
    try:
        db.write_points([{
            "measurement": "alerts",
            "tags": {
                "severity": severity,
                "rule":     rule,
                "src_ip":   src_ip
            },
            "fields": {
                "description": description,
                "mitre":       mitre,
                "count":       1
            }
        }])
        print(f"   [{severity}] {rule} from {src_ip}")
        print(f"     → {description}")
        print(f"     → MITRE: {mitre}")
    except Exception as e:
        print(f"  [ERROR] Alert write failed: {e}")

# ============================================================
# HELPER — Write Traffic to InfluxDB
# ============================================================
def write_traffic(src_ip, function_code):
    try:
        db.write_points([{
            "measurement": "modbus_traffic",
            "tags": {
                "src_ip":        src_ip,
                "function_code": str(function_code)
            },
            "fields": {
                "count":   1,
                "unit_id": 1
            }
        }])
    except Exception as e:
        print(f"  [ERROR] Traffic write failed: {e}")

# ============================================================
# HELPER — Parse Modbus TCP Packet
# ============================================================
def parse_modbus(raw_bytes):
    if len(raw_bytes) < 8:
        return None
    try:
        return {
            "transaction_id": int.from_bytes(raw_bytes[0:2], 'big'),
            "protocol_id":    int.from_bytes(raw_bytes[2:4], 'big'),
            "length":         int.from_bytes(raw_bytes[4:6], 'big'),
            "unit_id":        raw_bytes[6],
            "function_code":  raw_bytes[7],
            "raw":            raw_bytes.hex(),
            "timestamp":      str(datetime.now())
        }
    except:
        return None

# ============================================================
# DETECTION RULES
# ============================================================

# Rule 1 — Unauthorized Write
def check_unauthorized_write(modbus, src_ip):
    if modbus["function_code"] in WRITE_FCS:
        write_alert(
            rule        = "UNAUTHORIZED_WRITE",
            severity    = "CRITICAL",
            description = f"Unauthorized Modbus write FC{modbus['function_code']} from {src_ip}",
            mitre       = "T0855 - Unauthorized Command Message",
            src_ip      = src_ip
        )

# Rule 2 — Rogue Device
def check_rogue_device(src_ip):
    if src_ip not in known_devices:
        known_devices.add(src_ip)
        write_alert(
            rule        = "ROGUE_DEVICE",
            severity    = "HIGH",
            description = f"Unknown device detected on OT network: {src_ip}",
            mitre       = "T0846 - Remote System Discovery",
            src_ip      = src_ip
        )

# Rule 3 — Excessive Polling
def check_excessive_polling(src_ip):
    now = datetime.now()
    request_counter[src_ip].append(now)

    # Keep only last 60 seconds
    request_counter[src_ip] = [
        t for t in request_counter[src_ip]
        if (now - t).seconds < 60
    ]

    if len(request_counter[src_ip]) > POLLING_THRESHOLD:
        write_alert(
            rule        = "EXCESSIVE_POLLING",
            severity    = "MEDIUM",
            description = f"{src_ip} sent {len(request_counter[src_ip])} requests/min — possible recon",
            mitre       = "T0840 - Network Connection Enumeration",
            src_ip      = src_ip
        )

# Rule 4 — Replay Attack
def check_replay(modbus, src_ip):
    raw = modbus["raw"]
    now = datetime.now()

    # Count same command in last 10 seconds
    recent = [
        c for c in seen_commands
        if c["raw"] == raw and
        (now - datetime.fromisoformat(c["timestamp"])).seconds < 10
    ]

    if len(recent) >= 3:
        write_alert(
            rule        = "REPLAY_ATTACK",
            severity    = "HIGH",
            description = f"Identical Modbus command replayed {len(recent)+1}x in 10s",
            mitre       = "T0856 - Spoof Reporting Message",
            src_ip      = src_ip
        )

    seen_commands.append(modbus)

    # Keep seen_commands list manageable
    if len(seen_commands) > 1000:
        seen_commands.pop(0)

# ============================================================
# MAIN PACKET HANDLER
# ============================================================
packet_count = 0

def packet_handler(pkt):
    global packet_count

    # Only process IP + TCP packets
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    dport  = pkt[TCP].dport
    sport  = pkt[TCP].sport

    # Only process Modbus TCP (port 502)
    if dport != 502 and sport != 502:
        return

    # Only process packets going TO the PLC (requests)
    if dport != 502:
        return

    # Must have payload
    if not pkt.haslayer(Raw):
        return

    # Parse Modbus
    modbus = parse_modbus(bytes(pkt[Raw]))
    if not modbus:
        return

    packet_count += 1
    fc = modbus["function_code"]

    print(f"\n[PKT #{packet_count}] {src_ip} → {dst_ip}:502")
    print(f"  Function Code: FC{fc} ({get_fc_name(fc)})")
    print(f"  Unit ID: {modbus['unit_id']}")
    print(f"  Time: {modbus['timestamp'][:19]}")

    # Log traffic to InfluxDB
    write_traffic(src_ip, fc)

    # Run detection rules
    check_rogue_device(src_ip)
    check_unauthorized_write(modbus, src_ip)
    check_excessive_polling(src_ip)
    check_replay(modbus, src_ip)

# ============================================================
# HELPER — Function Code Names
# ============================================================
def get_fc_name(fc):
    names = {
        1:  "Read Coils",
        2:  "Read Discrete Inputs",
        3:  "Read Holding Registers",
        4:  "Read Input Registers",
        5:  "Write Single Coil",
        6:  "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        43: "Read Device Identification"
    }
    return names.get(fc, "Unknown")

# ============================================================
# START CAPTURE
# ============================================================
print(f"\n[*] Starting packet capture on interface: {INTERFACE}")
print(f"[*] Monitoring Modbus TCP port 502")
print(f"[*] Authorized IPs: {AUTHORIZED_IPS}")
print(f"[*] Polling threshold: {POLLING_THRESHOLD} req/min")
print(f"\n[*] Waiting for Modbus traffic...")
print(f"    Run attack_simulation.py on Kali to generate traffic")
print("=" * 55)

try:
    sniff(
        iface=INTERFACE,
        filter="tcp port 502",
        prn=packet_handler,
        store=False
    )
except KeyboardInterrupt:
    print(f"\n[+] Capture stopped")
    print(f"[+] Total packets captured: {packet_count}")
except Exception as e:
    print(f"[-] Capture error: {e}")
    print(f"    Try: sudo python3 guardian_capture.py")
