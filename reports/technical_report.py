import json

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


# ---------------------------------
# LOAD SECURITY RESULT
# ---------------------------------

with open("data/security_result.json", "r") as file:
    result = json.load(file)


# ---------------------------------
# PDF SETTINGS
# ---------------------------------

output_file = "reports/IPsec_Technical_Report.pdf"

document = SimpleDocTemplate(
    output_file,
    pagesize=A4
)

styles = getSampleStyleSheet()

title_style = styles["Title"]
title_style.alignment = TA_CENTER

story = []


# ---------------------------------
# TITLE
# ---------------------------------

story.append(
    Paragraph(
        "IPsec VPN Technical Security Report",
        title_style
    )
)

story.append(Spacer(1, 20))


# ---------------------------------
# ANALYSIS SUMMARY
# ---------------------------------

story.append(
    Paragraph(
        "1. Analysis Summary",
        styles["Heading2"]
    )
)

summary_data = [
    ["Capture ID", result["capture_id"]],
    ["Security Score", f'{result["security_score"]} / 100'],
    ["Risk Level", result["risk_level"]]
]

summary_table = Table(
    summary_data,
    colWidths=[160, 290]
)

summary_table.setStyle(
    TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 8)
    ])
)

story.append(summary_table)

story.append(Spacer(1, 20))


# ---------------------------------
# VPN CONFIGURATION
# ---------------------------------

story.append(
    Paragraph(
        "2. VPN Security Configuration",
        styles["Heading2"]
    )
)

security = result.get("security_parameters", {})

configuration_data = [
    ["Parameter", "Value"],

    ["Encryption",
     security.get("encryption", "Not Available")],

    ["Perfect Forward Secrecy",
     str(security.get("pfs", "Not Available"))],

    ["Diffie-Hellman Group",
     str(security.get("dh_group", "Not Available"))],

    ["Key Lifetime",
     str(security.get("key_lifetime", "Not Available"))],

    ["Replay Protection",
     str(security.get("replay_protection", "Not Available"))],

    ["Metadata Exposure",
     str(security.get("metadata_exposure", "Not Available"))]
]

configuration_table = Table(
    configuration_data,
    colWidths=[220, 230]
)

configuration_table.setStyle(
    TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(configuration_table)

story.append(Spacer(1, 20))


# ---------------------------------
# TRAFFIC ANALYSIS
# ---------------------------------

story.append(
    Paragraph(
        "3. Traffic Analysis",
        styles["Heading2"]
    )
)

traffic = result.get("traffic_features", {})

traffic_data = [
    ["Feature", "Value"],

    ["Packet Count",
     str(traffic.get("packet_count", "Not Available"))],

    ["Average Packet Size",
     str(traffic.get("avg_packet_size", "Not Available"))],

    ["Flow Duration",
     str(traffic.get("flow_duration", "Not Available"))]
]

traffic_table = Table(
    traffic_data,
    colWidths=[220, 230]
)

traffic_table.setStyle(
    TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(traffic_table)

story.append(Spacer(1, 20))


# ---------------------------------
# AI TRAFFIC CLASSIFICATION
# ---------------------------------

story.append(
    Paragraph(
        "4. AI Traffic Classification",
        styles["Heading2"]
    )
)

ai_prediction = result.get("ai_prediction", {})

ai_data = [
    ["Prediction", ai_prediction.get("traffic_type", "Not Available")],
    ["Confidence",
     str(ai_prediction.get("confidence", "Not Available"))]
]

ai_table = Table(
    ai_data,
    colWidths=[160, 290]
)

ai_table.setStyle(
    TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(ai_table)

story.append(Spacer(1, 20))


# ---------------------------------
# SECURITY FINDINGS
# ---------------------------------

story.append(
    Paragraph(
        "5. Detailed Security Findings",
        styles["Heading2"]
    )
)

finding_data = [
    ["Parameter", "Status", "Details"]
]

for finding in result["findings"]:

    finding_data.append([
        finding["parameter"],
        finding["status"],
        finding["message"]
    ])


finding_table = Table(
    finding_data,
    colWidths=[120, 90, 240]
)

finding_table.setStyle(
    TableStyle([
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6)
    ])
)

story.append(finding_table)

story.append(Spacer(1, 20))


# ---------------------------------
# RECOMMENDATIONS
# ---------------------------------

story.append(
    Paragraph(
        "6. Security Recommendations",
        styles["Heading2"]
    )
)

if result["recommendations"]:

    for recommendation in result["recommendations"]:

        story.append(
            Paragraph(
                "• " + recommendation,
                styles["BodyText"]
            )
        )

        story.append(Spacer(1, 6))

else:

    story.append(
        Paragraph(
            "No major security recommendations.",
            styles["BodyText"]
        )
    )


# ---------------------------------
# BUILD PDF
# ---------------------------------

document.build(story)

print("Technical report generated successfully.")
print("File:", output_file)