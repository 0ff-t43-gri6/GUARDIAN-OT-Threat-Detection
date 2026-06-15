from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================
AUTHORIZED_IPS     = ["192.168.29.226"]
WRITE_FCS          = [5, 6, 15, 16]
POLLING_THRESHOLD  = 30
REPLAY_WINDOW_SECS = 10
REPLAY_THRESHOLD   = 3

# ============================================================
# OT ASSET REGISTRY
# Maps Modbus register addresses to physical OT assets
# This is the core of the Asset Impact Analyzer
# ============================================================
OT_ASSET_REGISTRY = {
    # Register range: (start, end): asset info
    (0, 9): {
        "asset_name":      "Temperature Controller — Zone A",
        "asset_type":      "PID Controller",
        "process":         "Heat Exchange System",
        "location":        "Plant Floor A — Unit 1",
        "normal_range":    (0, 8000),    # 0-80.00°C × 100
        "critical_range":  (8001, 9500), # 80-95°C — warning
        "danger_range":    (9501, 65535),# >95°C — danger
        "safety_risk":     "HIGH",
        "impact": {
            "read":  "Attacker monitoring temperature — recon phase",
            "write": "Temperature setpoint manipulated — "
                     "risk of overheating or process shutdown"
        },
        "consequences": [
            "Heat exchanger may overheat",
            "Automatic safety shutdown may trigger",
            "Product quality degradation",
            "Potential equipment damage"
        ],
        "recovery_time":   "2-4 hours",
        "immediate_action": "Verify temperature readings manually, "
                            "check physical thermostat"
    },

    (10, 19): {
        "asset_name":      "Pressure Control Valve — Line B",
        "asset_type":      "Control Valve",
        "process":         "Pipeline Pressure Management",
        "location":        "Plant Floor B — Pipeline Section 2",
        "normal_range":    (0, 12000),   # 0-120.00 kPa × 100
        "critical_range":  (12001, 15000),
        "danger_range":    (15001, 65535),
        "safety_risk":     "CRITICAL",
        "impact": {
            "read":  "Attacker reading pressure values — "
                     "mapping process parameters",
            "write": "Pressure setpoint manipulated — "
                     "risk of overpressure or pipeline rupture"
        },
        "consequences": [
            "Pipeline overpressure",
            "Safety relief valve activation",
            "Potential pipeline rupture",
            "Emergency plant shutdown"
        ],
        "recovery_time":   "4-8 hours",
        "immediate_action": "Check pressure gauges manually, "
                            "prepare for emergency shutdown"
    },

    (20, 29): {
        "asset_name":      "Motor Speed Drive — Pump Station A",
        "asset_type":      "Variable Frequency Drive (VFD)",
        "process":         "Water/Fluid Pumping System",
        "location":        "Pump Station A — Motor Room",
        "normal_range":    (0, 6000),    # 0-60.00 Hz × 100
        "critical_range":  (6001, 7000),
        "danger_range":    (7001, 65535),
        "safety_risk":     "HIGH",
        "impact": {
            "read":  "Attacker monitoring motor speed — "
                     "understanding pump capacity",
            "write": "Motor speed manipulated — "
                     "risk of pump cavitation or motor burnout"
        },
        "consequences": [
            "Pump cavitation damage",
            "Motor winding overheating",
            "Bearing failure",
            "Complete pump failure"
        ],
        "recovery_time":   "1-2 days",
        "immediate_action": "Switch to manual motor control, "
                            "check motor temperature physically"
    },

    (30, 39): {
        "asset_name":      "Safety Instrumented System — Emergency Stop",
        "asset_type":      "Safety PLC (SIL-2)",
        "process":         "Emergency Shutdown System",
        "location":        "Control Room — Safety Cabinet",
        "normal_range":    (0, 1),       # 0=normal, 1=armed
        "critical_range":  (2, 99),
        "danger_range":    (100, 65535),
        "safety_risk":     "CRITICAL",
        "impact": {
            "read":  "Attacker reading safety system status — "
                     "TRITON/TRISIS style reconnaissance",
            "write": "SAFETY SYSTEM BYPASS ATTEMPTED — "
                     "critical life safety risk"
        },
        "consequences": [
            "Safety system may be disabled",
            "Emergency shutdown bypassed",
            "Risk to human life",
            "Regulatory violation (IEC 61511)"
        ],
        "recovery_time":   "Full safety audit required — days/weeks",
        "immediate_action": "IMMEDIATELY notify safety officer, "
                            "consider manual plant shutdown"
    },

    (40, 49): {
        "asset_name":      "Valve Actuator — Feed Line C",
        "asset_type":      "Motorized Ball Valve",
        "process":         "Raw Material Feed Control",
        "location":        "Feed Station C — Valve Bank 3",
        "normal_range":    (0, 10000),   # 0-100.00% × 100
        "critical_range":  (10001, 11000),
        "danger_range":    (11001, 65535),
        "safety_risk":     "MEDIUM",
        "impact": {
            "read":  "Attacker monitoring valve position",
            "write": "Valve position manipulated — "
                     "process feed rate disrupted"
        },
        "consequences": [
            "Raw material over/under feed",
            "Product quality issues",
            "Downstream process disruption",
            "Batch loss"
        ],
        "recovery_time":   "30 minutes - 2 hours",
        "immediate_action": "Check valve position physically, "
                            "verify feed flow meter readings"
    },

    (50, 99): {
        "asset_name":      "HMI Data Exchange — Historian Tags",
        "asset_type":      "Data Register Block",
        "process":         "Process Data Logging",
        "location":        "Control Network — Historian Server",
        "normal_range":    (0, 65535),
        "critical_range":  (0, 0),
        "danger_range":    (0, 0),
        "safety_risk":     "LOW",
        "impact": {
            "read":  "Attacker reading historical process data — "
                     "intelligence gathering",
            "write": "Historical data manipulated — "
                     "audit trail compromised"
        },
        "consequences": [
            "Process data integrity compromised",
            "Audit trail manipulation",
            "False operational reports",
            "Compliance violations"
        ],
        "recovery_time":   "Database restore required",
        "immediate_action": "Preserve log files, "
                            "initiate forensic investigation"
    },

    (100, 199): {
        "asset_name":      " HONEYPOT — Fake Sensitive Registers",
        "asset_type":      "Deception Technology",
        "process":         "Security Monitoring",
        "location":        "Virtual — GUARDIAN Deception Layer",
        "normal_range":    (0, 0),
        "critical_range":  (0, 0),
        "danger_range":    (1, 65535),
        "safety_risk":     "N/A",
        "impact": {
            "read":  "CONFIRMED ATTACKER — honeypot register accessed",
            "write": "CONFIRMED ATTACKER — honeypot register written"
        },
        "consequences": [
            "Attacker confirmed on OT network",
            "Zero false positive detection",
            "Attack campaign identified"
        ],
        "recovery_time":   "N/A — detection only",
        "immediate_action": "Attacker confirmed — initiate "
                            "incident response immediately"
    }
}

# ============================================================
# ASSET IMPACT ANALYZER
# ============================================================
class AssetImpactAnalyzer:
    """
    Maps Modbus register attacks to physical OT assets
    and real-world process consequences.
    """

    def get_asset(self, register_address):
        """Find asset for a given register address"""
        for (start, end), asset in OT_ASSET_REGISTRY.items():
            if start <= register_address <= end:
                return asset
        return None

    def analyze_impact(self, register_address,
                       function_code, value=None):
        """
        Generate full impact analysis for an attack
        on a specific register
        """
        asset = self.get_asset(register_address)

        if not asset:
            return {
                "asset_name":       "Unknown Asset",
                "process":          "Unknown Process",
                "physical_impact":  "Unknown impact",
                "safety_risk":      "UNKNOWN",
                "consequences":     ["Impact unknown"],
                "recovery_time":    "Unknown",
                "immediate_action": "Investigate manually"
            }

        # Determine action type
        action = "write" if function_code in WRITE_FCS else "read"

        # Check value range if write
        value_risk = "NORMAL"
        if value and action == "write":
            danger_start, danger_end = asset["danger_range"]
            critical_start, critical_end = asset["critical_range"]
            if danger_start <= value <= danger_end and danger_start != 0:
                value_risk = "DANGER"
            elif critical_start <= value <= critical_end and critical_start != 0:
                value_risk = "CRITICAL"

        return {
            "asset_name":       asset["asset_name"],
            "asset_type":       asset["asset_type"],
            "process":          asset["process"],
            "location":         asset["location"],
            "physical_impact":  asset["impact"][action],
            "safety_risk":      asset["safety_risk"],
            "value_risk":       value_risk,
            "consequences":     asset["consequences"],
            "recovery_time":    asset["recovery_time"],
            "immediate_action": asset["immediate_action"]
        }

    def extract_register(self, raw_hex):
        """Extract register address from raw Modbus bytes"""
        try:
            if len(raw_hex) >= 12:
                return int(raw_hex[8:12], 16)
        except:
            pass
        return 0

    def extract_value(self, raw_hex):
        """Extract written value from raw Modbus bytes"""
        try:
            if len(raw_hex) >= 16:
                return int(raw_hex[12:16], 16)
        except:
            pass
        return None

    def format_impact_report(self, impact):
        """Format impact analysis for console display"""
        lines = [
            f"\n   ASSET IMPACT ANALYSIS:",
            f"     Asset:          {impact['asset_name']}",
            f"     Type:           {impact.get('asset_type', 'N/A')}",
            f"     Process:        {impact['process']}",
            f"     Location:       {impact.get('location', 'N/A')}",
            f"     Physical Impact:{impact['physical_impact']}",
            f"     Safety Risk:    {impact['safety_risk']}",
            f"     Recovery Time:  {impact['recovery_time']}",
            f"      Action:      {impact['immediate_action']}",
            f"     Consequences:"
        ]
        for c in impact["consequences"]:
            lines.append(f"       → {c}")
        return "\n".join(lines)


# ============================================================
# DETECTION ENGINE CLASS
# ============================================================
class GuardianDetector:

    def __init__(self):
        self.request_counter = defaultdict(list)
        self.seen_commands   = []
        self.known_devices   = set(AUTHORIZED_IPS)
        self.alert_count     = 0
        self.impact_analyzer = AssetImpactAnalyzer()
        print("[+] GuardianDetector: Initialized")
        print("[+] OT Asset Impact Analyzer: ENABLED")
        print(f"[+] Assets monitored: "
              f"{len(OT_ASSET_REGISTRY)} register ranges")
        print(f"[+] Authorized IPs: {AUTHORIZED_IPS}")

    # --------------------------------------------------------
    # RULE 1 — Unauthorized Write
    # --------------------------------------------------------
    def check_unauthorized_write(self, modbus, src_ip):
        fc = modbus["function_code"]
        if fc in WRITE_FCS:
            # Get register + value for impact analysis
            register = self.impact_analyzer.extract_register(
                modbus["raw"])
            value = self.impact_analyzer.extract_value(
                modbus["raw"])

            # Analyze physical impact
            impact = self.impact_analyzer.analyze_impact(
                register, fc, value)

            return self._raise_alert(
                rule        = "UNAUTHORIZED_WRITE",
                severity    = "CRITICAL",
                description = f"Unauthorized Modbus write "
                              f"FC{fc} from {src_ip}",
                mitre       = "T0855 - Unauthorized Command Message",
                src_ip      = src_ip,
                impact      = impact
            )
        return None

    # --------------------------------------------------------
    # RULE 2 — Rogue Device
    # --------------------------------------------------------
    def check_rogue_device(self, src_ip):
        if src_ip not in self.known_devices:
            self.known_devices.add(src_ip)
            return self._raise_alert(
                rule        = "ROGUE_DEVICE",
                severity    = "HIGH",
                description = f"Unknown device on OT network: "
                              f"{src_ip}",
                mitre       = "T0846 - Remote System Discovery",
                src_ip      = src_ip
            )
        return None

    # --------------------------------------------------------
    # RULE 3 — Excessive Polling
    # --------------------------------------------------------
    def check_excessive_polling(self, src_ip):
        now = datetime.now()
        self.request_counter[src_ip].append(now)

        self.request_counter[src_ip] = [
            t for t in self.request_counter[src_ip]
            if (now - t).seconds < 60
        ]

        count = len(self.request_counter[src_ip])
        if count > POLLING_THRESHOLD:
            return self._raise_alert(
                rule        = "EXCESSIVE_POLLING",
                severity    = "MEDIUM",
                description = f"{src_ip} sent {count} "
                              f"requests/min — possible recon",
                mitre       = "T0840 - Network Connection Enumeration",
                src_ip      = src_ip
            )
        return None

    # --------------------------------------------------------
    # RULE 4 — Replay Attack
    # --------------------------------------------------------
    def check_replay_attack(self, modbus, src_ip):
        raw = modbus["raw"]
        now = datetime.now()

        recent = [
            c for c in self.seen_commands
            if c["raw"] == raw and
            (now - datetime.fromisoformat(
                c["timestamp"])).seconds < REPLAY_WINDOW_SECS
        ]

        self.seen_commands.append(modbus)
        if len(self.seen_commands) > 1000:
            self.seen_commands.pop(0)

        if len(recent) >= REPLAY_THRESHOLD:
            # Get impact for replayed register
            register = self.impact_analyzer.extract_register(raw)
            impact   = self.impact_analyzer.analyze_impact(
                register, modbus["function_code"])

            return self._raise_alert(
                rule        = "REPLAY_ATTACK",
                severity    = "HIGH",
                description = f"Identical command replayed "
                              f"{len(recent)+1}x in "
                              f"{REPLAY_WINDOW_SECS}s",
                mitre       = "T0856 - Spoof Reporting Message",
                src_ip      = src_ip,
                impact      = impact
            )
        return None

    # --------------------------------------------------------
    # RULE 5 — Out of Range Value
    # --------------------------------------------------------
    def check_value_range(self, modbus, src_ip):
        raw = modbus["raw"]
        if len(raw) >= 12:
            try:
                register = self.impact_analyzer.extract_register(raw)
                value    = self.impact_analyzer.extract_value(raw)

                if value and (value > 9000 or value == 65535):
                    impact = self.impact_analyzer.analyze_impact(
                        register, modbus["function_code"], value)

                    return self._raise_alert(
                        rule        = "VALUE_INJECTION",
                        severity    = "CRITICAL",
                        description = f"Out-of-range value "
                                      f"{value} injected by {src_ip}",
                        mitre       = "T0855 - Unauthorized "
                                      "Command Message",
                        src_ip      = src_ip,
                        impact      = impact
                    )
            except:
                pass
        return None

    # --------------------------------------------------------
    # RUN ALL RULES
    # --------------------------------------------------------
    def analyze(self, modbus, src_ip):
        alerts = []

        r1 = self.check_rogue_device(src_ip)
        r2 = self.check_unauthorized_write(modbus, src_ip)
        r3 = self.check_excessive_polling(src_ip)
        r4 = self.check_replay_attack(modbus, src_ip)
        r5 = self.check_value_range(modbus, src_ip)

        for r in [r1, r2, r3, r4, r5]:
            if r:
                alerts.append(r)

        return alerts

    # --------------------------------------------------------
    # GET STATS
    # --------------------------------------------------------
    def get_stats(self):
        return {
            "total_alerts":  self.alert_count,
            "known_devices": list(self.known_devices),
            "tracked_ips":   list(self.request_counter.keys())
        }

    # --------------------------------------------------------
    # RAISE ALERT WITH IMPACT
    # --------------------------------------------------------
    def _raise_alert(self, rule, severity,
                     description, mitre, src_ip,
                     impact=None):
        self.alert_count += 1
        alert = {
            "timestamp":   str(datetime.now()),
            "rule":        rule,
            "severity":    severity,
            "description": description,
            "mitre":       mitre,
            "src_ip":      src_ip,
            "impact":      impact
        }

        print(f"\n   [{severity}] {rule}")
        print(f"     Source:  {src_ip}")
        print(f"     Details: {description}")
        print(f"     MITRE:   {mitre}")

        # Print impact analysis if available
        if impact:
            print(self.impact_analyzer.format_impact_report(impact))

        return alert


# ============================================================
# STANDALONE TEST
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  GUARDIAN — Detection Engine + Asset Impact Analyzer")
    print("=" * 60)

    detector = GuardianDetector()

    test_packets = [
        # Attack on Temperature Controller (register 5)
        {
            "modbus": {
                "function_code": 6,
                "raw": "00010000000601060005" + "9999",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Temperature Controller Attack"
        },
        # Attack on Safety System (register 35)
        {
            "modbus": {
                "function_code": 6,
                "raw": "000200000006010600230001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Safety System Attack"
        },
        # Attack on Motor Speed (register 25)
        {
            "modbus": {
                "function_code": 6,
                "raw": "00030000000601060019FFFF",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Motor Speed Attack"
        },
        # Honeypot register access (register 105)
        {
            "modbus": {
                "function_code": 3,
                "raw": "000400000006010300690001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Honeypot Register Access"
        },
        # Normal read — authorized (register 5)
        {
            "modbus": {
                "function_code": 3,
                "raw": "000500000006010300050001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.29.226",
            "label": "Normal SCADA Read"
        }
    ]
from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================
AUTHORIZED_IPS     = ["192.168.29.226"]
WRITE_FCS          = [5, 6, 15, 16]
POLLING_THRESHOLD  = 30
REPLAY_WINDOW_SECS = 10
REPLAY_THRESHOLD   = 3

# ============================================================
# OT ASSET REGISTRY
# Maps Modbus register addresses to physical OT assets
# This is the core of the Asset Impact Analyzer
# ============================================================
OT_ASSET_REGISTRY = {
    # Register range: (start, end): asset info
    (0, 9): {
        "asset_name":      "Temperature Controller — Zone A",
        "asset_type":      "PID Controller",
        "process":         "Heat Exchange System",
        "location":        "Plant Floor A — Unit 1",
        "normal_range":    (0, 8000),    # 0-80.00°C × 100
        "critical_range":  (8001, 9500), # 80-95°C — warning
        "danger_range":    (9501, 65535),# >95°C — danger
        "safety_risk":     "HIGH",
        "impact": {
            "read":  "Attacker monitoring temperature — recon phase",
            "write": "Temperature setpoint manipulated — "
                     "risk of overheating or process shutdown"
        },
        "consequences": [
            "Heat exchanger may overheat",
            "Automatic safety shutdown may trigger",
            "Product quality degradation",
            "Potential equipment damage"
        ],
        "recovery_time":   "2-4 hours",
        "immediate_action": "Verify temperature readings manually, "
                            "check physical thermostat"
    },

    (10, 19): {
        "asset_name":      "Pressure Control Valve — Line B",
        "asset_type":      "Control Valve",
        "process":         "Pipeline Pressure Management",
        "location":        "Plant Floor B — Pipeline Section 2",
        "normal_range":    (0, 12000),   # 0-120.00 kPa × 100
        "critical_range":  (12001, 15000),
        "danger_range":    (15001, 65535),
        "safety_risk":     "CRITICAL",
        "impact": {
            "read":  "Attacker reading pressure values — "
                     "mapping process parameters",
            "write": "Pressure setpoint manipulated — "
                     "risk of overpressure or pipeline rupture"
        },
        "consequences": [
            "Pipeline overpressure",
            "Safety relief valve activation",
            "Potential pipeline rupture",
            "Emergency plant shutdown"
        ],
        "recovery_time":   "4-8 hours",
        "immediate_action": "Check pressure gauges manually, "
                            "prepare for emergency shutdown"
    },

    (20, 29): {
        "asset_name":      "Motor Speed Drive — Pump Station A",
        "asset_type":      "Variable Frequency Drive (VFD)",
        "process":         "Water/Fluid Pumping System",
        "location":        "Pump Station A — Motor Room",
        "normal_range":    (0, 6000),    # 0-60.00 Hz × 100
        "critical_range":  (6001, 7000),
        "danger_range":    (7001, 65535),
        "safety_risk":     "HIGH",
        "impact": {
            "read":  "Attacker monitoring motor speed — "
                     "understanding pump capacity",
            "write": "Motor speed manipulated — "
                     "risk of pump cavitation or motor burnout"
        },
        "consequences": [
            "Pump cavitation damage",
            "Motor winding overheating",
            "Bearing failure",
            "Complete pump failure"
        ],
        "recovery_time":   "1-2 days",
        "immediate_action": "Switch to manual motor control, "
                            "check motor temperature physically"
    },

    (30, 39): {
        "asset_name":      "Safety Instrumented System — Emergency Stop",
        "asset_type":      "Safety PLC (SIL-2)",
        "process":         "Emergency Shutdown System",
        "location":        "Control Room — Safety Cabinet",
        "normal_range":    (0, 1),       # 0=normal, 1=armed
        "critical_range":  (2, 99),
        "danger_range":    (100, 65535),
        "safety_risk":     "CRITICAL",
        "impact": {
            "read":  "Attacker reading safety system status — "
                     "TRITON/TRISIS style reconnaissance",
            "write": "SAFETY SYSTEM BYPASS ATTEMPTED — "
                     "critical life safety risk"
        },
        "consequences": [
            "Safety system may be disabled",
            "Emergency shutdown bypassed",
            "Risk to human life",
            "Regulatory violation (IEC 61511)"
        ],
        "recovery_time":   "Full safety audit required — days/weeks",
        "immediate_action": "IMMEDIATELY notify safety officer, "
                            "consider manual plant shutdown"
    },

    (40, 49): {
        "asset_name":      "Valve Actuator — Feed Line C",
        "asset_type":      "Motorized Ball Valve",
        "process":         "Raw Material Feed Control",
        "location":        "Feed Station C — Valve Bank 3",
        "normal_range":    (0, 10000),   # 0-100.00% × 100
        "critical_range":  (10001, 11000),
        "danger_range":    (11001, 65535),
        "safety_risk":     "MEDIUM",
        "impact": {
            "read":  "Attacker monitoring valve position",
            "write": "Valve position manipulated — "
                     "process feed rate disrupted"
        },
        "consequences": [
            "Raw material over/under feed",
            "Product quality issues",
            "Downstream process disruption",
            "Batch loss"
        ],
        "recovery_time":   "30 minutes - 2 hours",
        "immediate_action": "Check valve position physically, "
                            "verify feed flow meter readings"
    },

    (50, 99): {
        "asset_name":      "HMI Data Exchange — Historian Tags",
        "asset_type":      "Data Register Block",
        "process":         "Process Data Logging",
        "location":        "Control Network — Historian Server",
        "normal_range":    (0, 65535),
        "critical_range":  (0, 0),
        "danger_range":    (0, 0),
        "safety_risk":     "LOW",
        "impact": {
            "read":  "Attacker reading historical process data — "
                     "intelligence gathering",
            "write": "Historical data manipulated — "
                     "audit trail compromised"
        },
        "consequences": [
            "Process data integrity compromised",
            "Audit trail manipulation",
            "False operational reports",
            "Compliance violations"
        ],
        "recovery_time":   "Database restore required",
        "immediate_action": "Preserve log files, "
                            "initiate forensic investigation"
    },

    (100, 199): {
        "asset_name":      " HONEYPOT — Fake Sensitive Registers",
        "asset_type":      "Deception Technology",
        "process":         "Security Monitoring",
        "location":        "Virtual — GUARDIAN Deception Layer",
        "normal_range":    (0, 0),
        "critical_range":  (0, 0),
        "danger_range":    (1, 65535),
        "safety_risk":     "N/A",
        "impact": {
            "read":  "CONFIRMED ATTACKER — honeypot register accessed",
            "write": "CONFIRMED ATTACKER — honeypot register written"
        },
        "consequences": [
            "Attacker confirmed on OT network",
            "Zero false positive detection",
            "Attack campaign identified"
        ],
        "recovery_time":   "N/A — detection only",
        "immediate_action": "Attacker confirmed — initiate "
                            "incident response immediately"
    }
}

# ============================================================
# ASSET IMPACT ANALYZER
# ============================================================
class AssetImpactAnalyzer:
    """
    Maps Modbus register attacks to physical OT assets
    and real-world process consequences.
    """

    def get_asset(self, register_address):
        """Find asset for a given register address"""
        for (start, end), asset in OT_ASSET_REGISTRY.items():
            if start <= register_address <= end:
                return asset
        return None

    def analyze_impact(self, register_address,
                       function_code, value=None):
        """
        Generate full impact analysis for an attack
        on a specific register
        """
        asset = self.get_asset(register_address)

        if not asset:
            return {
                "asset_name":       "Unknown Asset",
                "process":          "Unknown Process",
                "physical_impact":  "Unknown impact",
                "safety_risk":      "UNKNOWN",
                "consequences":     ["Impact unknown"],
                "recovery_time":    "Unknown",
                "immediate_action": "Investigate manually"
            }

        # Determine action type
        action = "write" if function_code in WRITE_FCS else "read"

        # Check value range if write
        value_risk = "NORMAL"
        if value and action == "write":
            danger_start, danger_end = asset["danger_range"]
            critical_start, critical_end = asset["critical_range"]
            if danger_start <= value <= danger_end and danger_start != 0:
                value_risk = "DANGER"
            elif critical_start <= value <= critical_end and critical_start != 0:
                value_risk = "CRITICAL"

        return {
            "asset_name":       asset["asset_name"],
            "asset_type":       asset["asset_type"],
            "process":          asset["process"],
            "location":         asset["location"],
            "physical_impact":  asset["impact"][action],
            "safety_risk":      asset["safety_risk"],
            "value_risk":       value_risk,
            "consequences":     asset["consequences"],
            "recovery_time":    asset["recovery_time"],
            "immediate_action": asset["immediate_action"]
        }

    def extract_register(self, raw_hex):
        """Extract register address from raw Modbus bytes"""
        try:
            if len(raw_hex) >= 12:
                return int(raw_hex[8:12], 16)
        except:
            pass
        return 0

    def extract_value(self, raw_hex):
        """Extract written value from raw Modbus bytes"""
        try:
            if len(raw_hex) >= 16:
                return int(raw_hex[12:16], 16)
        except:
            pass
        return None

    def format_impact_report(self, impact):
        """Format impact analysis for console display"""
        lines = [
            f"\n   ASSET IMPACT ANALYSIS:",
            f"     Asset:          {impact['asset_name']}",
            f"     Type:           {impact.get('asset_type', 'N/A')}",
            f"     Process:        {impact['process']}",
            f"     Location:       {impact.get('location', 'N/A')}",
            f"     Physical Impact:{impact['physical_impact']}",
            f"     Safety Risk:    {impact['safety_risk']}",
            f"     Recovery Time:  {impact['recovery_time']}",
            f"      Action:      {impact['immediate_action']}",
            f"     Consequences:"
        ]
        for c in impact["consequences"]:
            lines.append(f"       → {c}")
        return "\n".join(lines)


# ============================================================
# DETECTION ENGINE CLASS
# ============================================================
class GuardianDetector:

    def __init__(self):
        self.request_counter = defaultdict(list)
        self.seen_commands   = []
        self.known_devices   = set(AUTHORIZED_IPS)
        self.alert_count     = 0
        self.impact_analyzer = AssetImpactAnalyzer()
        print("[+] GuardianDetector: Initialized")
        print("[+] OT Asset Impact Analyzer: ENABLED")
        print(f"[+] Assets monitored: "
              f"{len(OT_ASSET_REGISTRY)} register ranges")
        print(f"[+] Authorized IPs: {AUTHORIZED_IPS}")

    # --------------------------------------------------------
    # RULE 1 — Unauthorized Write
    # --------------------------------------------------------
    def check_unauthorized_write(self, modbus, src_ip):
        fc = modbus["function_code"]
        if fc in WRITE_FCS:
            # Get register + value for impact analysis
            register = self.impact_analyzer.extract_register(
                modbus["raw"])
            value = self.impact_analyzer.extract_value(
                modbus["raw"])

            # Analyze physical impact
            impact = self.impact_analyzer.analyze_impact(
                register, fc, value)

            return self._raise_alert(
                rule        = "UNAUTHORIZED_WRITE",
                severity    = "CRITICAL",
                description = f"Unauthorized Modbus write "
                              f"FC{fc} from {src_ip}",
                mitre       = "T0855 - Unauthorized Command Message",
                src_ip      = src_ip,
                impact      = impact
            )
        return None

    # --------------------------------------------------------
    # RULE 2 — Rogue Device
    # --------------------------------------------------------
    def check_rogue_device(self, src_ip):
        if src_ip not in self.known_devices:
            self.known_devices.add(src_ip)
            return self._raise_alert(
                rule        = "ROGUE_DEVICE",
                severity    = "HIGH",
                description = f"Unknown device on OT network: "
                              f"{src_ip}",
                mitre       = "T0846 - Remote System Discovery",
                src_ip      = src_ip
            )
        return None

    # --------------------------------------------------------
    # RULE 3 — Excessive Polling
    # --------------------------------------------------------
    def check_excessive_polling(self, src_ip):
        now = datetime.now()
        self.request_counter[src_ip].append(now)

        self.request_counter[src_ip] = [
            t for t in self.request_counter[src_ip]
            if (now - t).seconds < 60
        ]

        count = len(self.request_counter[src_ip])
        if count > POLLING_THRESHOLD:
            return self._raise_alert(
                rule        = "EXCESSIVE_POLLING",
                severity    = "MEDIUM",
                description = f"{src_ip} sent {count} "
                              f"requests/min — possible recon",
                mitre       = "T0840 - Network Connection Enumeration",
                src_ip      = src_ip
            )
        return None

    # --------------------------------------------------------
    # RULE 4 — Replay Attack
    # --------------------------------------------------------
    def check_replay_attack(self, modbus, src_ip):
        raw = modbus["raw"]
        now = datetime.now()

        recent = [
            c for c in self.seen_commands
            if c["raw"] == raw and
            (now - datetime.fromisoformat(
                c["timestamp"])).seconds < REPLAY_WINDOW_SECS
        ]

        self.seen_commands.append(modbus)
        if len(self.seen_commands) > 1000:
            self.seen_commands.pop(0)

        if len(recent) >= REPLAY_THRESHOLD:
            # Get impact for replayed register
            register = self.impact_analyzer.extract_register(raw)
            impact   = self.impact_analyzer.analyze_impact(
                register, modbus["function_code"])

            return self._raise_alert(
                rule        = "REPLAY_ATTACK",
                severity    = "HIGH",
                description = f"Identical command replayed "
                              f"{len(recent)+1}x in "
                              f"{REPLAY_WINDOW_SECS}s",
                mitre       = "T0856 - Spoof Reporting Message",
                src_ip      = src_ip,
                impact      = impact
            )
        return None

    # --------------------------------------------------------
    # RULE 5 — Out of Range Value
    # --------------------------------------------------------
    def check_value_range(self, modbus, src_ip):
        raw = modbus["raw"]
        if len(raw) >= 12:
            try:
                register = self.impact_analyzer.extract_register(raw)
                value    = self.impact_analyzer.extract_value(raw)

                if value and (value > 9000 or value == 65535):
                    impact = self.impact_analyzer.analyze_impact(
                        register, modbus["function_code"], value)

                    return self._raise_alert(
                        rule        = "VALUE_INJECTION",
                        severity    = "CRITICAL",
                        description = f"Out-of-range value "
                                      f"{value} injected by {src_ip}",
                        mitre       = "T0855 - Unauthorized "
                                      "Command Message",
                        src_ip      = src_ip,
                        impact      = impact
                    )
            except:
                pass
        return None

    # --------------------------------------------------------
    # RUN ALL RULES
    # --------------------------------------------------------
    def analyze(self, modbus, src_ip):
        alerts = []

        r1 = self.check_rogue_device(src_ip)
        r2 = self.check_unauthorized_write(modbus, src_ip)
        r3 = self.check_excessive_polling(src_ip)
        r4 = self.check_replay_attack(modbus, src_ip)
        r5 = self.check_value_range(modbus, src_ip)

        for r in [r1, r2, r3, r4, r5]:
            if r:
                alerts.append(r)

        return alerts

    # --------------------------------------------------------
    # GET STATS
    # --------------------------------------------------------
    def get_stats(self):
        return {
            "total_alerts":  self.alert_count,
            "known_devices": list(self.known_devices),
            "tracked_ips":   list(self.request_counter.keys())
        }

    # --------------------------------------------------------
    # RAISE ALERT WITH IMPACT
    # --------------------------------------------------------
    def _raise_alert(self, rule, severity,
                     description, mitre, src_ip,
                     impact=None):
        self.alert_count += 1
        alert = {
            "timestamp":   str(datetime.now()),
            "rule":        rule,
            "severity":    severity,
            "description": description,
            "mitre":       mitre,
            "src_ip":      src_ip,
            "impact":      impact
        }

        print(f"\n   [{severity}] {rule}")
        print(f"     Source:  {src_ip}")
        print(f"     Details: {description}")
        print(f"     MITRE:   {mitre}")

        # Print impact analysis if available
        if impact:
            print(self.impact_analyzer.format_impact_report(impact))

        return alert


# ============================================================
# STANDALONE TEST
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  GUARDIAN — Detection Engine + Asset Impact Analyzer")
    print("=" * 60)

    detector = GuardianDetector()

    test_packets = [
        # Attack on Temperature Controller (register 5)
        {
            "modbus": {
                "function_code": 6,
                "raw": "00010000000601060005" + "9999",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Temperature Controller Attack"
        },
        # Attack on Safety System (register 35)
        {
            "modbus": {
                "function_code": 6,
                "raw": "000200000006010600230001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Safety System Attack"
        },
        # Attack on Motor Speed (register 25)
        {
            "modbus": {
                "function_code": 6,
                "raw": "00030000000601060019FFFF",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Motor Speed Attack"
        },
        # Honeypot register access (register 105)
        {
            "modbus": {
                "function_code": 3,
                "raw": "000400000006010300690001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.1.99",
            "label": "Honeypot Register Access"
        },
        # Normal read — authorized (register 5)
        {
            "modbus": {
                "function_code": 3,
                "raw": "000500000006010300050001",
                "timestamp": str(datetime.now())
            },
            "src_ip": "192.168.29.226",
            "label": "Normal SCADA Read"
        }
    ]

    all_alerts = []
    for i, pkt in enumerate(test_packets):
        print(f"\n{'─'*60}")
        print(f"[PKT #{i+1}] {pkt['label']}")
        print(f"  FC{pkt['modbus']['function_code']} "
              f"from {pkt['src_ip']}")
        alerts = detector.analyze(pkt["modbus"], pkt["src_ip"])
        all_alerts.extend(alerts)

    # Final summary
    print(f"\n{'='*60}")
    print(f"  DETECTION SUMMARY")
    print(f"{'='*60}")
    stats = detector.get_stats()
    print(f"  Total alerts:  {stats['total_alerts']}")
    print(f"\n  Alert breakdown:")
    for alert in all_alerts:
        impact_asset = alert.get("impact", {})
        asset_name   = impact_asset.get(
            "asset_name", "N/A") if impact_asset else "N/A"
        print(f"  [{alert['severity']}] {alert['rule']}")
        print(f"    → Asset: {asset_name}")
    print(f"{'='*60}")
