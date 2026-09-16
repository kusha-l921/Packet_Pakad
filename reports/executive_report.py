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

output_file = "reports/IPsec_Executive_Report.pdf"

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
        "IPsec VPN Security Assessment Report",
        title_style
    )
)

story.append(Spacer(1, 20))


# ---------------------------------
# EXECUTIVE SUMMARY
# ---------------------------------

story.append(
    Paragraph(
        "<b>Executive Summary</b>",
        styles["Heading2"]
    )
)

story.append(
    Paragraph(
        "This report provides a high-level assessment of the "
        "security configuration observed in the analyzed IPsec VPN traffic.",
        styles["BodyText"]
    )
)

story.append(Spacer(1, 15))


# ---------------------------------
# SECURITY SCORE
# ---------------------------------

summary_data = [
    ["Capture ID", result["capture_id"]],
    ["Security Score", f'{result["security_score"]} / 100'],
    ["Risk Level", result["risk_level"]]
]

summary_table = Table(summary_data, colWidths=[150, 300])

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
# SECURITY FINDINGS
# ---------------------------------

story.append(
    Paragraph(
        "Security Findings",
        styles["Heading2"]
    )
)

finding_data = [
    ["Parameter", "Status", "Finding"]
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
        "Security Recommendations",
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

print("Executive report generated successfully.")
print("File:", output_file)