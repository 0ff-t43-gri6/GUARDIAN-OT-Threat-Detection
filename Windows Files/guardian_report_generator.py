from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle,
    Paragraph, Spacer, HRFlowable,
    PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from influxdb import InfluxDBClient
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================
INFLUX_HOST  = "localhost"
INFLUX_PORT  = 8086
DATABASE     = "guardian"
OUTPUT_FILE  = f"GUARDIAN_Report_{datetime.now().strftime('%Y-%m-%d')}.pdf"


# ============================================================
# COLORS
# ============================================================
DARK_RED     = colors.HexColor("#8B0000")
DARK_BLUE    = colors.HexColor("#1a1a2e")
MEDIUM_BLUE  = colors.HexColor("#16213e")
ACCENT_BLUE  = colors.HexColor("#0f3460")
CRITICAL_RED = colors.HexColor("#dc3545")
HIGH_ORANGE  = colors.HexColor("#fd7e14")
MED_YELLOW   = colors.HexColor("#ffc107")
LOW_GREEN    = colors.HexColor("#28a745")
WHITE        = colors.white
LIGHT_GRAY   = colors.HexColor("#f8f9fa")
DARK_GRAY    = colors.HexColor("#343a40")

# ============================================================
# FETCH DATA FROM INFLUXDB
# ============================================================
def fetch_data():
    print("[*] Connecting to InfluxDB...")
    try:
        db = InfluxDBClient(INFLUX_HOST, INFLUX_PORT)
        db.switch_database(DATABASE)
        print("[+] Connected successfully")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return None

    data = {}

    # Fetch recent alerts
    try:
        result = db.query(
            "SELECT * FROM alerts "
            "ORDER BY time DESC LIMIT 50"
        )
        data["alerts"] = list(result.get_points())
        print(f"[+] Fetched {len(data['alerts'])} alerts")
    except:
        data["alerts"] = []

    # Fetch alert summary by severity
    try:
        result = db.query(
            "SELECT count(count) FROM alerts "
            "GROUP BY severity"
        )
        data["severity_summary"] = {}
        for key, points in result.items():
            tags = key[1]  # tags dict
            sev = tags.get("severity", "UNKNOWN") if tags else "UNKNOWN"
            for item in points:
                count = item.get("count", 0)
                data["severity_summary"][sev] = count
        print(f"[+] Severity summary: {data['severity_summary']}")
    except:
        data["severity_summary"] = {}

    # Fetch top attackers
    try:
        result = db.query(
            "SELECT count(count) FROM alerts "
            "GROUP BY src_ip"
        )
        attackers = []
        for key, points in result.items():
            tags = key[1]
            ip = tags.get("src_ip", "unknown") if tags else "unknown"
            for item in points:
                attackers.append({
                    "ip": ip,
                    "count": item.get("count", 0)
                })
        data["attackers"] = sorted(
            attackers,
            key=lambda x: x["count"],
            reverse=True
        )[:5]
        print(f"[+] Top attackers: {data['attackers']}")
    except:
        data["attackers"] = []

    # Fetch rules triggered
    try:
        result = db.query(
            "SELECT count(count) FROM alerts "
            "GROUP BY rule"
        )
        data["rules"] = {}
        for key, points in result.items():
            tags = key[1]
            rule = tags.get("rule", "UNKNOWN") if tags else "unknown"
            for item in points:
                count = item.get("count", 0)
                data["rules"][rule] = count
    except:
        data["rules"] = {}

    # Fetch asset impacts
    try:
        result = db.query(
            "SELECT * FROM asset_impacts "
            "ORDER BY time DESC LIMIT 10"
        )
        data["assets"] = list(result.get_points())
        print(f"[+] Asset impacts: {len(data['assets'])}")
    except:
        data["assets"] = []

    # Fetch traffic stats
    try:
        result = db.query(
            "SELECT count(count) FROM modbus_traffic"
        )
        points = list(result.get_points())
        data["traffic_count"] = points[0].get(
            "count", 0) if points else 0
        print(f"[+] Traffic count: {data['traffic_count']}")
    except:
        data["traffic_count"] = 0

    return data

# ============================================================
# STYLES
# ============================================================
def get_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name        = "CoverTitle",
        fontSize    = 32,
        textColor   = WHITE,
        alignment   = TA_CENTER,
        spaceAfter  = 10,
        fontName    = "Helvetica-Bold"
    ))

    styles.add(ParagraphStyle(
        name        = "CoverSubtitle",
        fontSize    = 16,
        textColor   = colors.HexColor("#aaaaaa"),
        alignment   = TA_CENTER,
        spaceAfter  = 8,
        fontName    = "Helvetica"
    ))

    styles.add(ParagraphStyle(
        name        = "SectionTitle",
        fontSize    = 16,
        textColor   = DARK_BLUE,
        spaceBefore = 15,
        spaceAfter  = 8,
        fontName    = "Helvetica-Bold"
    ))

    styles.add(ParagraphStyle(
        name        = "SubTitle",
        fontSize    = 12,
        textColor   = ACCENT_BLUE,
        spaceBefore = 10,
        spaceAfter  = 5,
        fontName    = "Helvetica-Bold"
    ))

    styles.add(ParagraphStyle(
        name        = "BodyText2",
        fontSize    = 10,
        textColor   = DARK_GRAY,
        spaceAfter  = 6,
        fontName    = "Helvetica",
        leading     = 16
    ))

    styles.add(ParagraphStyle(
        name        = "CriticalText",
        fontSize    = 10,
        textColor   = CRITICAL_RED,
        fontName    = "Helvetica-Bold"
    ))

    styles.add(ParagraphStyle(
        name        = "Footer",
        fontSize    = 8,
        textColor   = colors.gray,
        alignment   = TA_CENTER
    ))

    return styles

# ============================================================
# SEVERITY COLOR
# ============================================================
def severity_color(severity):
    return {
        "CRITICAL": CRITICAL_RED,
        "HIGH":     HIGH_ORANGE,
        "MEDIUM":   MED_YELLOW,
        "LOW":      LOW_GREEN
    }.get(severity, colors.gray)

# ============================================================
# PAGE 1 — COVER PAGE
# ============================================================
def build_cover(styles, data):
    elements = []

    elements.append(Spacer(1, 1.5*inch))

    # Title box
    title_data = [[
        Paragraph("GUARDIAN", styles["CoverTitle"])
    ]]
    title_table = Table(title_data, colWidths=[6.5*inch])
    title_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), DARK_BLUE),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",  (0,0), (-1,-1), 20),
        ("BOTTOMPADDING",(0,0),(-1,-1), 20),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [10,10,10,10])
    ]))
    elements.append(title_table)
    elements.append(Spacer(1, 0.2*inch))

    # Subtitle
    elements.append(Paragraph(
        "OT Network Threat Detection Platform",
        styles["CoverSubtitle"]
    ))
    elements.append(Paragraph(
        "Security Assessment Report",
        styles["CoverSubtitle"]
    ))
    elements.append(Spacer(1, 0.5*inch))

    # Info table
    total = sum(data["severity_summary"].values()) \
            if data["severity_summary"] else 0
    critical = data["severity_summary"].get("CRITICAL", 0)

    info_data = [
        ["Report Date",    str(datetime.now().strftime(
                           "%B %d, %Y %H:%M"))],
        ["Assessment Type","OT/ICS Security Assessment"],
        ["Protocols Tested","Modbus TCP, OPC-UA, DNP3"],
        ["Total Alerts",   str(total)],
        ["Critical Alerts",str(critical)],
        ["Report Version", "v1.0"],
    ]

    info_table = Table(info_data, colWidths=[2.5*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), ACCENT_BLUE),
        ("BACKGROUND",   (1,0), (1,-1), LIGHT_GRAY),
        ("TEXTCOLOR",    (0,0), (0,-1), WHITE),
        ("TEXTCOLOR",    (1,0), (1,-1), DARK_GRAY),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",     (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",     (0,0), (-1,-1), 10),
        ("PADDING",      (0,0), (-1,-1), 10),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.white),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),
         [LIGHT_GRAY, colors.white])
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.5*inch))

    # Confidential notice
    conf_data = [[Paragraph(
        "⚠️ CONFIDENTIAL — For Authorized Personnel Only",
        styles["CriticalText"]
    )]]
    conf_table = Table(conf_data, colWidths=[6.5*inch])
    conf_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1),
         colors.HexColor("#fff3cd")),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("BOX",           (0,0), (-1,-1), 1, HIGH_ORANGE),
    ]))
    elements.append(conf_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 2 — EXECUTIVE SUMMARY
# ============================================================
def build_executive_summary(styles, data):
    elements = []

    elements.append(Paragraph(
        "1. Executive Summary", styles["SectionTitle"]))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    # Calculate stats
    total    = sum(data["severity_summary"].values()) \
               if data["severity_summary"] else 0
    critical = data["severity_summary"].get("CRITICAL", 0)
    high     = data["severity_summary"].get("HIGH", 0)
    medium   = data["severity_summary"].get("MEDIUM", 0)
    traffic  = data["traffic_count"]

    # Summary text
    elements.append(Paragraph(
        f"The GUARDIAN OT Threat Detection Platform conducted a "
        f"comprehensive security assessment of the industrial "
        f"control system network. During the assessment period, "
        f"GUARDIAN detected <b>{total} security events</b> across "
        f"multiple OT protocols including Modbus TCP and OPC-UA.",
        styles["BodyText2"]
    ))
    elements.append(Spacer(1, 0.1*inch))

    elements.append(Paragraph(
        f"The assessment revealed significant security gaps in the "
        f"OT network, including unauthorized write commands to PLC "
        f"registers, rogue device detection, replay attacks, and "
        f"out-of-range value injection. A total of "
        f"<b>{critical} CRITICAL</b> severity alerts were generated, "
        f"indicating immediate risk to plant operations and safety.",
        styles["BodyText2"]
    ))
    elements.append(Spacer(1, 0.2*inch))

    # Stats boxes
    stats_data = [[
        Paragraph(f"<b>{total}</b><br/>Total Alerts",
                  ParagraphStyle("s", fontSize=14,
                  alignment=TA_CENTER,
                  textColor=WHITE,
                  fontName="Helvetica-Bold")),
        Paragraph(f"<b>{critical}</b><br/>Critical",
                  ParagraphStyle("s", fontSize=14,
                  alignment=TA_CENTER,
                  textColor=WHITE,
                  fontName="Helvetica-Bold")),
        Paragraph(f"<b>{high}</b><br/>High",
                  ParagraphStyle("s", fontSize=14,
                  alignment=TA_CENTER,
                  textColor=WHITE,
                  fontName="Helvetica-Bold")),
        Paragraph(f"<b>{medium}</b><br/>Medium",
                  ParagraphStyle("s", fontSize=14,
                  alignment=TA_CENTER,
                  textColor=WHITE,
                  fontName="Helvetica-Bold")),
        Paragraph(f"<b>{traffic}</b><br/>Packets",
                  ParagraphStyle("s", fontSize=14,
                  alignment=TA_CENTER,
                  textColor=WHITE,
                  fontName="Helvetica-Bold")),
    ]]

    stats_table = Table(
        stats_data,
        colWidths=[1.3*inch]*5
    )
    stats_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,0), ACCENT_BLUE),
        ("BACKGROUND",    (1,0), (1,0), CRITICAL_RED),
        ("BACKGROUND",    (2,0), (2,0), HIGH_ORANGE),
        ("BACKGROUND",    (3,0), (3,0), MED_YELLOW),
        ("BACKGROUND",    (4,0), (4,0), LOW_GREEN),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 15),
        ("BOTTOMPADDING", (0,0), (-1,-1), 15),
        ("ROUNDEDCORNERS",(0,0), (-1,-1), [5,5,5,5])
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.2*inch))

    # Key findings
    elements.append(Paragraph(
        "Key Findings:", styles["SubTitle"]))

    findings = [
        ["🔴", "CRITICAL",
         "Modbus TCP has no authentication — "
         "any device can write to PLC registers"],
        ["🔴", "CRITICAL",
         "Safety system registers accessible "
         "without authorization"],
        ["🟠", "HIGH",
         "Replay attacks possible — no sequence "
         "number validation in Modbus"],
        ["🟠", "HIGH",
         "Rogue devices can join OT network "
         "without detection"],
        ["🟡", "MEDIUM",
         "Excessive polling detected — "
         "attacker mapping process parameters"],
        ["🟢", "LOW",
         "OPC-UA anonymous access enabled — "
         "process data exposed"],
    ]

    findings_table = Table(
        findings,
        colWidths=[0.3*inch, 1*inch, 5.2*inch]
    )
    findings_table.setStyle(TableStyle([
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,0), (-1,-1),
         [LIGHT_GRAY, colors.white]),
        ("FONTNAME",      (1,0), (1,-1), "Helvetica-Bold"),
    ]))
    elements.append(findings_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 3 — ALERT STATISTICS
# ============================================================
def build_alert_statistics(styles, data):
    elements = []

    elements.append(Paragraph(
        "2. Alert Statistics", styles["SectionTitle"]))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    # Severity breakdown
    elements.append(Paragraph(
        "2.1 Alerts by Severity", styles["SubTitle"]))

    sev_data = [["Severity", "Count", "Percentage", "Risk Level"]]
    total = sum(data["severity_summary"].values()) \
            if data["severity_summary"] else 1

    for sev, count in sorted(
        data["severity_summary"].items(),
        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(
            x[0]) if x[0] in
            ["CRITICAL","HIGH","MEDIUM","LOW"] else 99
    ):
        pct  = f"{(count/total*100):.1f}%"
        risk = {"CRITICAL": "Immediate Action Required",
                "HIGH":     "Action Required Within 24hrs",
                "MEDIUM":   "Action Required Within Week",
                "LOW":      "Monitor and Review"}.get(sev, "N/A")
        sev_data.append([sev, str(count), pct, risk])

    sev_table = Table(
        sev_data,
        colWidths=[1.5*inch, 1*inch, 1.5*inch, 3*inch]
    )
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("PADDING",       (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 0.2*inch))

    # Rules triggered
    elements.append(Paragraph(
        "2.2 Detection Rules Triggered", styles["SubTitle"]))

    rules_data = [["Rule", "Count", "Severity", "MITRE TTP"]]
    mitre_map = {
        "UNAUTHORIZED_WRITE": ("CRITICAL", "T0855"),
        "ROGUE_DEVICE":       ("HIGH",     "T0846"),
        "REPLAY_ATTACK":      ("HIGH",     "T0856"),
        "EXCESSIVE_POLLING":  ("MEDIUM",   "T0840"),
        "VALUE_INJECTION":    ("CRITICAL", "T0855"),
        "HONEYPOT_TRIGGERED": ("CRITICAL", "T0843"),
    }

    for rule, count in sorted(
        data["rules"].items(),
        key=lambda x: x[1],
        reverse=True
    ):
        sev, mitre = mitre_map.get(rule, ("MEDIUM", "N/A"))
        rules_data.append([rule, str(count), sev, mitre])

    rules_table = Table(
        rules_data,
        colWidths=[2.5*inch, 0.8*inch, 1.2*inch, 2*inch]
    )
    rules_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("PADDING",       (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(rules_table)
    elements.append(Spacer(1, 0.2*inch))

    # Top attackers
    elements.append(Paragraph(
        "2.3 Top Attacking IPs", styles["SubTitle"]))

    att_data = [["Rank", "IP Address",
                 "Alert Count", "Threat Level"]]
    for i, att in enumerate(data["attackers"], 1):
        count = att["count"]
        threat = "CRITICAL" if count > 20 else \
                 "HIGH" if count > 10 else "MEDIUM"
        att_data.append([
            str(i), att["ip"], str(count), threat
        ])

    att_table = Table(
        att_data,
        colWidths=[0.8*inch, 2.5*inch, 1.5*inch, 1.7*inch]
    )
    att_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("PADDING",       (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(att_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 4 — ATTACK TIMELINE
# ============================================================
def build_attack_timeline(styles, data):
    elements = []

    elements.append(Paragraph(
        "3. Attack Timeline", styles["SectionTitle"]))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    elements.append(Paragraph(
        "Chronological record of all detected security events:",
        styles["BodyText2"]
    ))

    timeline_data = [[
        "Timestamp", "Severity",
        "Rule", "Source IP", "MITRE"
    ]]

    for alert in data["alerts"][:20]:
        timestamp = alert.get("time", "")[:19]
        severity  = alert.get("severity", "N/A")
        rule      = alert.get("rule", "N/A")
        src_ip    = alert.get("src_ip", "N/A")
        mitre     = alert.get("mitre", "N/A")[:15]

        timeline_data.append([
            timestamp, severity, rule, src_ip, mitre
        ])

    timeline_table = Table(
        timeline_data,
        colWidths=[1.6*inch, 0.9*inch,
                   1.8*inch, 1.3*inch, 0.9*inch]
    )

    # Build style with severity colors
    ts = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 5),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ])

    # Color severity cells
    for i, alert in enumerate(data["alerts"][:20], 1):
        sev = alert.get("severity", "")
        col = severity_color(sev)
        ts.add("TEXTCOLOR", (1,i), (1,i), col)
        ts.add("FONTNAME",  (1,i), (1,i), "Helvetica-Bold")

    timeline_table.setStyle(ts)
    elements.append(timeline_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 5 — ASSET IMPACT ANALYSIS
# ============================================================
def build_asset_impact(styles, data):
    elements = []

    elements.append(Paragraph(
        "4. OT Asset Impact Analysis", styles["SectionTitle"]))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    elements.append(Paragraph(
        "GUARDIAN's Asset Impact Analyzer maps every attack "
        "to physical OT assets and real-world consequences:",
        styles["BodyText2"]
    ))

    asset_data = [[
        "Asset", "Attack Type",
        "Safety Risk", "Risk Score", "Recovery Time"
    ]]

    for asset in data["assets"]:
        asset_data.append([
            asset.get("asset_name", "N/A")[:25],
            asset.get("attack_type", "N/A"),
            asset.get("safety_risk", "N/A"),
            str(asset.get("risk_score", "N/A")),
            asset.get("recovery_time", "N/A")
        ])

    asset_table = Table(
        asset_data,
        colWidths=[2*inch, 1.5*inch,
                   1*inch, 0.8*inch, 1.2*inch]
    )
    asset_ts = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ])

    # Color safety risk cells
    for i, asset in enumerate(data["assets"], 1):
        risk = asset.get("safety_risk", "")
        col  = severity_color(risk)
        asset_ts.add("TEXTCOLOR", (2,i), (2,i), col)
        asset_ts.add("FONTNAME",  (2,i), (2,i), "Helvetica-Bold")

    asset_table.setStyle(asset_ts)
    elements.append(asset_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 6 — MITRE ATT&CK MAPPING
# ============================================================
def build_mitre_mapping(styles, data):
    elements = []

    elements.append(Paragraph(
        "5. MITRE ATT&CK for ICS Mapping",
        styles["SectionTitle"]
    ))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    elements.append(Paragraph(
        "All detected attacks mapped to MITRE ATT&CK for ICS "
        "framework techniques:",
        styles["BodyText2"]
    ))

    mitre_data = [[
        "Detection Rule", "Tactic",
        "Technique ID", "Technique Name", "Severity"
    ]]

    mitre_full = [
        ["UNAUTHORIZED_WRITE",
         "Impair Process Control",
         "T0855",
         "Unauthorized Command Message",
         "CRITICAL"],
        ["ROGUE_DEVICE",
         "Initial Access",
         "T0846",
         "Remote System Discovery",
         "HIGH"],
        ["REPLAY_ATTACK",
         "Evasion",
         "T0856",
         "Spoof Reporting Message",
         "HIGH"],
        ["EXCESSIVE_POLLING",
         "Discovery",
         "T0840",
         "Network Connection Enumeration",
         "MEDIUM"],
        ["VALUE_INJECTION",
         "Impair Process Control",
         "T0855",
         "Unauthorized Command Message",
         "CRITICAL"],
        ["HONEYPOT_TRIGGERED",
         "Collection",
         "T0843",
         "Program Download",
         "CRITICAL"],
    ]

    mitre_data.extend(mitre_full)

    mitre_table = Table(
        mitre_data,
        colWidths=[1.5*inch, 1.5*inch,
                   0.8*inch, 2*inch, 0.8*inch]
    )

    mitre_ts = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ])

    # Color severity
    for i, row in enumerate(mitre_full, 1):
        col = severity_color(row[4])
        mitre_ts.add("TEXTCOLOR", (4,i), (4,i), col)
        mitre_ts.add("FONTNAME",  (4,i), (4,i), "Helvetica-Bold")

    mitre_table.setStyle(mitre_ts)
    elements.append(mitre_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# PAGE 7 — REMEDIATION ROADMAP
# ============================================================
def build_remediation(styles, data):
    elements = []

    elements.append(Paragraph(
        "6. Remediation Roadmap", styles["SectionTitle"]))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10))

    # Immediate actions
    elements.append(Paragraph(
        "6.1 Immediate Actions (0-7 days)",
        styles["SubTitle"]
    ))

    immediate = [
        ["#", "Action", "Priority", "Effort"],
        ["1", "Implement Modbus TCP authentication "
              "using vendor-specific security modules",
         "CRITICAL", "Medium"],
        ["2", "Enable OPC-UA security mode "
              "— disable anonymous access",
         "CRITICAL", "Low"],
        ["3", "Deploy network segmentation "
              "— isolate OT from IT network",
         "CRITICAL", "High"],
        ["4", "Implement IP whitelisting "
              "on all Modbus devices",
         "HIGH", "Low"],
        ["5", "Enable audit logging "
              "on all PLC and SCADA systems",
         "HIGH", "Low"],
    ]

    imm_table = Table(
        immediate,
        colWidths=[0.3*inch, 4*inch, 1*inch, 1*inch]
    )
    imm_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), CRITICAL_RED),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(imm_table)
    elements.append(Spacer(1, 0.2*inch))

    # Short term
    elements.append(Paragraph(
        "6.2 Short Term (7-30 days)",
        styles["SubTitle"]
    ))

    short_term = [
        ["#", "Action", "Priority", "Effort"],
        ["1", "Deploy IDS/IPS solution "
              "for OT network monitoring",
         "HIGH", "High"],
        ["2", "Implement Modbus sequence "
              "number validation",
         "HIGH", "Medium"],
        ["3", "Deploy honeypot registers "
              "for early attacker detection",
         "HIGH", "Low"],
        ["4", "Conduct OT security awareness "
              "training for operators",
         "MEDIUM", "Medium"],
        ["5", "Implement automated backup "
              "for all PLC programs",
         "MEDIUM", "Low"],
    ]

    st_table = Table(
        short_term,
        colWidths=[0.3*inch, 4*inch, 1*inch, 1*inch]
    )
    st_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), HIGH_ORANGE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(st_table)
    elements.append(Spacer(1, 0.2*inch))

    # Long term
    elements.append(Paragraph(
        "6.3 Long Term (30-90 days)",
        styles["SubTitle"]
    ))

    long_term = [
        ["#", "Action", "Priority", "Effort"],
        ["1", "Implement IEC 62443 compliance "
              "framework across OT network",
         "HIGH", "Very High"],
        ["2", "Deploy encrypted communications "
              "for all OT protocols",
         "HIGH", "High"],
        ["3", "Implement Security Information "
              "and Event Management (SIEM)",
         "MEDIUM", "High"],
        ["4", "Conduct annual OT penetration "
              "testing exercise",
         "MEDIUM", "High"],
        ["5", "Develop and test OT incident "
              "response playbook",
         "MEDIUM", "Medium"],
    ]

    lt_table = Table(
        long_term,
        colWidths=[0.3*inch, 4*inch, 1*inch, 1*inch]
    )
    lt_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LOW_GREEN),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS",(0,1), (-1,-1),
         [LIGHT_GRAY, colors.white]),
    ]))
    elements.append(lt_table)
    elements.append(PageBreak())

    return elements

# ============================================================
# BUILD COMPLETE PDF
# ============================================================
def build_report():
    print("=" * 55)
    print("  GUARDIAN — PDF Report Generator")
    print("=" * 55)

    # Fetch data
    data = fetch_data()
    if not data:
        print("[-] Could not fetch data — using sample data")
        data = {
            "alerts":           [],
            "severity_summary": {
                "CRITICAL": 75,
                "HIGH":     13,
                "MEDIUM":   10
            },
            "attackers": [
                {"ip": "192.168.1.99", "count": 35},
                {"ip": "192.168.1.77", "count": 3}
            ],
            "rules": {
                "UNAUTHORIZED_WRITE": 65,
                "ROGUE_DEVICE":       11,
                "EXCESSIVE_POLLING":  10,
                "VALUE_INJECTION":    10,
                "REPLAY_ATTACK":       2
            },
            "assets":        [],
            "traffic_count": 150
        }

    # Build PDF
    doc = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles   = get_styles()
    elements = []

    print("\n[*] Building report sections...")

    # Build all sections
    elements += build_cover(styles, data)
    print("[+] Cover page done")

    elements += build_executive_summary(styles, data)
    print("[+] Executive summary done")

    elements += build_alert_statistics(styles, data)
    print("[+] Alert statistics done")

    elements += build_attack_timeline(styles, data)
    print("[+] Attack timeline done")

    elements += build_asset_impact(styles, data)
    print("[+] Asset impact done")

    elements += build_mitre_mapping(styles, data)
    print("[+] MITRE mapping done")

    elements += build_remediation(styles, data)
    print("[+] Remediation roadmap done")

    # Generate PDF
    print("\n[*] Generating PDF...")
    doc.build(elements)

    print(f"\n{'='*55}")
    print(f"   Report generated successfully!")
    print(f"   File: {OUTPUT_FILE}")
    print(f"   Pages: 7")
    print(f"   Location: {OUTPUT_FILE}")
    print(f"{'='*55}")


if __name__ == "__main__":
    build_report()