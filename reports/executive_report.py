import json
import os

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


# ==========================================
# PATHS
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "latest_analysis.json"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "IPsec_Executive_Report.pdf"
)


# ==========================================
# GENERATE EXECUTIVE REPORT
# ==========================================

def generate_executive_report(analysis=None):

    # --------------------------------------
    # Load latest analysis if not provided
    # --------------------------------------

    if analysis is None:

        with open(
            DATA_FILE,
            "r"
        ) as file:

            analysis = json.load(file)


    # --------------------------------------
    # Extract data
    # --------------------------------------

    security = analysis.get(
        "security",
        {}
    )

    capture_id = analysis.get(
        "capture_id",
        "Unknown"
    )

    security_score = security.get(
        "security_score",
        0
    )

    risk_level = security.get(
        "risk_level",
        "UNKNOWN"
    )

    findings = security.get(
        "findings",
        []
    )

    recommendations = security.get(
        "recommendations",
        []
    )


    # --------------------------------------
    # PDF
    # --------------------------------------

    document = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]

    title_style.alignment = TA_CENTER

    story = []


    # --------------------------------------
    # TITLE
    # --------------------------------------

    story.append(
        Paragraph(
            "IPsec VPN Security Assessment Report",
            title_style
        )
    )

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------

    story.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            "This report provides a high-level assessment "
            "of the security configuration observed in the "
            "analyzed IPsec VPN traffic.",
            styles["BodyText"]
        )
    )

    story.append(
        Spacer(1, 15)
    )


    # --------------------------------------
    # SECURITY SUMMARY
    # --------------------------------------

    summary_data = [
        [
            "Capture ID",
            str(capture_id)
        ],
        [
            "Security Score",
            f"{security_score} / 100"
        ],
        [
            "Risk Level",
            str(risk_level)
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[150, 300]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                1,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(summary_table)

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # SECURITY FINDINGS
    # --------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            styles["Heading2"]
        )
    )

    finding_data = [
        [
            "Parameter",
            "Status",
            "Finding"
        ]
    ]

    for finding in findings:

        if isinstance(finding, dict):

            parameter = finding.get(
                "parameter",
                "Unknown"
            )

            status = finding.get(
                "status",
                "UNKNOWN"
            )

            message = finding.get(
                "message",
                ""
            )

        else:

            parameter = "Security Finding"

            status = "INFO"

            message = str(finding)

        finding_data.append(
            [
                str(parameter),
                str(status),
                str(message)
            ]
        )


    if len(finding_data) == 1:

        finding_data.append(
            [
                "None",
                "INFO",
                "No security findings were reported."
            ]
        )


    finding_table = Table(
        finding_data,
        colWidths=[120, 90, 240]
    )

    finding_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                1,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(finding_table)

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------

    story.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading2"]
        )
    )

    if recommendations:

        for recommendation in recommendations:

            if isinstance(
                recommendation,
                dict
            ):

                message = recommendation.get(
                    "message",
                    ""
                )

            else:

                message = str(
                    recommendation
                )

            story.append(
                Paragraph(
                    "• " + str(message),
                    styles["BodyText"]
                )
            )

            story.append(
                Spacer(1, 6)
            )

    else:

        story.append(
            Paragraph(
                "No major security recommendations.",
                styles["BodyText"]
            )
        )


    # --------------------------------------
    # BUILD PDF
    # --------------------------------------

    document.build(story)

    return OUTPUT_FILE


# ==========================================
# DIRECT EXECUTION
# ==========================================

if __name__ == "__main__":

    output = generate_executive_report()

    print(
        "Executive report generated successfully."
    )

    print(
        "File:",
        output
    )