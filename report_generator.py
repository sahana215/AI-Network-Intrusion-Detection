
import io
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# COMMON DATA HELPERS
# --------------------------------------------------

def normalize_column_name(name):
    """Normalize column names for flexible matching."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def get_field(row, candidates, default="Not Available"):
    """
    Retrieve a DataFrame row value using multiple possible
    column names, ignoring spaces, underscores and capitalization.
    """
    normalized = {
        normalize_column_name(column): column
        for column in row.index
    }

    for candidate in candidates:
        key = normalize_column_name(candidate)

        if key in normalized:
            value = row[normalized[key]]

            if value is not None and not pd.isna(value):
                value = str(value).strip()

                if value and value.lower() not in ("nan", "none", "null"):
                    return value

    return default


def safe_paragraph(value, style):
    """Safely format dynamic values inside ReportLab Paragraph."""
    return Paragraph(escape(str(value)), style)


# --------------------------------------------------
# CSV REPORT
# --------------------------------------------------

def generate_csv_report(results_dataframe):
    """Export incident results as CSV bytes and save a copy."""

    csv_bytes = results_dataframe.to_csv(
        index=False
    ).encode("utf-8")

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    file_path = (
        REPORTS_DIR /
        f"blackbox_incident_report_{timestamp_str}.csv"
    )

    try:
        results_dataframe.to_csv(file_path, index=False)
    except Exception as error:
        print(f"CSV save error: {error}")

    return csv_bytes, str(file_path)


# --------------------------------------------------
# PDF SECURITY REPORT
# --------------------------------------------------

def generate_pdf_report(
    summary_metrics,
    attack_breakdown_df=None,
    critical_alerts_df=None,
    executive_notes=""
):
    """
    Generate a professional BLACKBOX SOC security report.

    Returns:
        bytes: Generated PDF document.
    """

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # --------------------------------------------------
    # COLOR PALETTE
    # --------------------------------------------------

    COLOR_RED = colors.HexColor("#ed174c")
    COLOR_DARK = colors.HexColor("#09090c")
    COLOR_TEXT = colors.HexColor("#222226")
    COLOR_MUTED = colors.HexColor("#6c6c7d")
    COLOR_LIGHT = colors.HexColor("#f4f4f7")

    # --------------------------------------------------
    # TEXT STYLES
    # --------------------------------------------------

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=COLOR_RED,
        alignment=TA_LEFT
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=COLOR_MUTED
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_RED,
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=COLOR_TEXT,
        wordWrap="CJK"
    )

    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=colors.white
    )

    footer_style = ParagraphStyle(
        "FooterNotice",
        parent=subtitle_style,
        alignment=TA_CENTER,
        fontSize=7
    )

    story = []

    # --------------------------------------------------
    # 1. HEADER
    # --------------------------------------------------

    now_str = datetime.now(timezone.utc).strftime(
        "%B %d, %Y - %H:%M:%S UTC"
    )

    header_right_style = ParagraphStyle(
        "HeaderRight",
        parent=subtitle_style,
        alignment=TA_RIGHT
    )

    header_data = [[
        Paragraph(
            "<b>BLACKBOX</b> | NIDS Threat Report",
            title_style
        ),
        Paragraph(
            f"<b>CLASSIFIED: SOC USE ONLY</b><br/>{now_str}",
            header_right_style
        )
    ]]

    header_table = Table(
        header_data,
        colWidths=[340, 200]
    )

    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4)
    ]))

    story.append(header_table)

    story.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=COLOR_RED,
            spaceBefore=4,
            spaceAfter=14
        )
    )

    # --------------------------------------------------
    # 2. EXECUTIVE THREAT ASSESSMENT
    # --------------------------------------------------

    story.append(
        Paragraph(
            "1. EXECUTIVE THREAT ASSESSMENT",
            section_heading
        )
    )

    total = int(summary_metrics.get("total_flows", 0) or 0)
    attacks = int(summary_metrics.get("attacks", 0) or 0)
    anomalies = int(summary_metrics.get("anomalies", 0) or 0)
    critical = int(summary_metrics.get("critical_alerts", 0) or 0)
    high = int(summary_metrics.get("high_alerts", 0) or 0)

    if critical > 0:
        threat_level = "CRITICAL"
    elif attacks > 0 or high > 0:
        threat_level = "ELEVATED"
    else:
        threat_level = "NOMINAL"

    exec_text = (
        "This security intelligence report was automatically "
        "compiled by the BLACKBOX Hybrid AI Intrusion Detection Engine. "
        f"During this inspection period, a total of "
        f"<b>{total:,}</b> network communication flows were analyzed. "
        f"The AI detection system flagged <b>{attacks:,}</b> "
        f"attack-correlated flows and <b>{anomalies:,}</b> "
        f"behavioral anomalies, resulting in <b>{critical:,}</b> "
        f"Critical-tier alerts and <b>{high:,}</b> High-tier alerts. "
        f"Overall network threat posture is rated: "
        f"<b>{threat_level}</b>."
    )

    story.append(
        Paragraph(exec_text, body_style)
    )

    if executive_notes:
        story.append(Spacer(1, 6))

        story.append(
            Paragraph(
                f"<b>Analyst Remarks:</b> "
                f"{escape(str(executive_notes))}",
                body_style
            )
        )

    story.append(Spacer(1, 10))

    # --------------------------------------------------
    # KPI TABLE
    # --------------------------------------------------

    kpi_data = [
        [
            "Total Network Flows",
            "Attack Flows Detected",
            "Behavioral Anomalies",
            "Critical Alerts",
            "Threat Posture"
        ],
        [
            f"{total:,}",
            f"{attacks:,}",
            f"{anomalies:,}",
            f"{critical:,}",
            threat_level
        ]
    ]

    kpi_table = Table(
        kpi_data,
        colWidths=[108, 108, 108, 108, 108]
    )

    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),

        ("ALIGN", (0, 0), (-1, -1), "CENTER"),

        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 11),

        (
            "TEXTCOLOR",
            (4, 1),
            (4, 1),
            COLOR_RED if threat_level in ("CRITICAL", "ELEVATED")
            else colors.green
        ),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d0d8")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # --------------------------------------------------
    # 3. ATTACK CLASSIFICATION BREAKDOWN
    # --------------------------------------------------

    if (
        attack_breakdown_df is not None
        and not attack_breakdown_df.empty
    ):

        story.append(
            Paragraph(
                "2. ATTACK CLASSIFICATION BREAKDOWN",
                section_heading
            )
        )

        table_rows = [[
            "Attack Category / Class",
            "Incident Count",
            "Severity Rating",
            "Percentage"
        ]]

        if "Count" in attack_breakdown_df.columns:
            total_count = max(
                pd.to_numeric(
                    attack_breakdown_df["Count"],
                    errors="coerce"
                ).fillna(0).sum(),
                1
            )

            for _, row in attack_breakdown_df.head(10).iterrows():

                count = pd.to_numeric(
                    row.get("Count", 0),
                    errors="coerce"
                )

                count = 0 if pd.isna(count) else int(count)

                percentage = (count / total_count) * 100

                category = get_field(
                    row,
                    ["Category", "Attack_Category", "attack_category"]
                )

                severity = get_field(
                    row,
                    ["Severity", "Risk_Level", "severity"],
                    default="Not Classified"
                )

                table_rows.append([
                    safe_paragraph(category, body_style),
                    f"{count:,}",
                    safe_paragraph(severity, body_style),
                    f"{percentage:.1f}%"
                ])

        attack_table = Table(
            table_rows,
            colWidths=[160, 120, 120, 140],
            repeatRows=1
        )

        attack_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a121c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#ff456c")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),

            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0ea")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))

        story.append(attack_table)
        story.append(Spacer(1, 14))

    # --------------------------------------------------
    # 4. ACTIONABLE SECURITY INCIDENTS
    # --------------------------------------------------

    if (
        critical_alerts_df is not None
        and not critical_alerts_df.empty
    ):

        story.append(
            Paragraph(
                "3. ACTIONABLE SECURITY INCIDENTS & ALERTS",
                section_heading
            )
        )

        alert_rows = [[
            safe_paragraph("Source IP", table_header_style),
            safe_paragraph("Target IP : Port", table_header_style),
            safe_paragraph("Category", table_header_style),
            safe_paragraph("Risk", table_header_style),
            safe_paragraph("Detection Reason", table_header_style)
        ]]

        for _, row in critical_alerts_df.head(10).iterrows():

            # Source IP: support multiple common column names.
            src = get_field(
                row,
                [
                    "Source IP",
                    "source_ip",
                    "src_ip",
                    "Src IP",
                    "src",
                    "Source Address",
                    "source_address",
                    "srcip"
                ]
            )

            # Destination IP.
            dst_ip = get_field(
                row,
                [
                    "Destination IP",
                    "destination_ip",
                    "dst_ip",
                    "Dst IP",
                    "dst",
                    "Destination Address",
                    "destination_address",
                    "dstip"
                ]
            )

            # Destination port.
            dst_port = get_field(
                row,
                [
                    "Destination Port",
                    "destination_port",
                    "dst_port",
                    "Dst Port",
                    "dport",
                    "dest_port"
                ]
            )

            # Category.
            category = get_field(
                row,
                [
                    "Attack_Category",
                    "attack_category",
                    "Category",
                    "Attack Category",
                    "predicted_attack",
                    "prediction"
                ],
                default="Suspicious"
            )

            # Risk.
            risk = get_field(
                row,
                [
                    "Risk_Level",
                    "risk_level",
                    "severity",
                    "Severity",
                    "risk"
                ],
                default="Not Classified"
            )

            # Detection reason.
            reason = get_field(
                row,
                [
                    "Detection_Reason",
                    "detection_reason",
                    "Detection Reason",
                    "reason",
                    "alert_reason",
                    "explanation"
                ],
                default="No detection reason provided"
            )

            destination = f"{dst_ip}:{dst_port}"

            alert_rows.append([
                safe_paragraph(src, body_style),
                safe_paragraph(destination, body_style),
                safe_paragraph(category, body_style),
                safe_paragraph(risk, body_bold),
                safe_paragraph(reason, body_style)
            ])

        alerts_table = Table(
            alert_rows,
            colWidths=[95, 105, 95, 55, 190],
            repeatRows=1,
            splitByRow=1
        )

        alerts_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b1118")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#ff315c")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),

            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dcdce6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))

        story.append(alerts_table)
        story.append(Spacer(1, 14))

    # --------------------------------------------------
    # 5. INCIDENT RESPONSE RECOMMENDATIONS
    # --------------------------------------------------

    story.append(
        Paragraph(
            "4. RECOMMENDED INCIDENT RESPONSE ACTIONS",
            section_heading
        )
    )

    recommendations = [
        (
            "<b>1. Host Isolation:</b> "
            "Quarantine internal hosts exhibiting repeated "
            "port scanning or brute-force behavior."
        ),
        (
            "<b>2. Egress Filtering:</b> "
            "Block outbound communication to flagged external "
            "C2 or high-confidence malicious IPs."
        ),
        (
            "<b>3. Firewall Hardening:</b> "
            "Restrict unauthenticated exposure of management "
            "ports (SSH, RDP, SMB, MySQL) to trusted subnets."
        ),
        (
            "<b>4. Credential Auditing:</b> "
            "Force immediate password resets and enable MFA "
            "for accounts linked to authentication anomalies."
        ),
        (
            "<b>5. Continuous Threat Intelligence:</b> "
            "Re-evaluate external threat intelligence feeds "
            "and IP reputations periodically."
        )
    ]

    for recommendation in recommendations:
        story.append(
            Paragraph(recommendation, body_style)
        )
        story.append(Spacer(1, 4))

    # --------------------------------------------------
    # 6. FOOTER
    # --------------------------------------------------

    story.append(Spacer(1, 15))

    story.append(
        HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#a0a0b0"),
            spaceBefore=6,
            spaceAfter=8
        )
    )

    story.append(
        Paragraph(
            "CONFIDENTIAL & PROPRIETARY — BLACKBOX NETWORK "
            "DEFENSE SYSTEM. Generated for authorized Security "
            "Operations Center personnel only.",
            footer_style
        )
    )

    # --------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------

    doc.build(story)

    pdf_data = buffer.getvalue()
    buffer.close()

    return pdf_data
