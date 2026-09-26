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
    "IPsec_Technical_Report.pdf"
)


# ==========================================
# GENERATE TECHNICAL REPORT
# ==========================================

def generate_technical_report(analysis=None):

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

    security_parameters = analysis.get(
        "security_parameters",
        {}
    )

    traffic = analysis.get(
        "traffic_features",
        {}
    )

    ai_prediction = analysis.get(
        "ai_prediction",
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
            "IPsec VPN Technical Security Report",
            title_style
        )
    )

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # 1. ANALYSIS SUMMARY
    # --------------------------------------

    story.append(
        Paragraph(
            "1. Analysis Summary",
            styles["Heading2"]
        )
    )

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
        colWidths=[160, 290]
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
    # 2. VPN SECURITY CONFIGURATION
    # --------------------------------------

    story.append(
        Paragraph(
            "2. VPN Security Configuration",
            styles["Heading2"]
        )
    )

    configuration_data = [
        [
            "Parameter",
            "Value"
        ],
        [
            "Encryption",
            str(
                security_parameters.get(
                    "encryption",
                    "Unknown"
                )
            )
        ],
        [
            "Perfect Forward Secrecy",
            str(
                security_parameters.get(
                    "pfs",
                    "Unknown"
                )
            )
        ],
        [
            "Diffie-Hellman Group",
            str(
                security_parameters.get(
                    "dh_group",
                    "Unknown"
                )
            )
        ],
        [
            "Key Lifetime",
            str(
                security_parameters.get(
                    "key_lifetime",
                    "Unknown"
                )
            )
        ],
        [
            "Replay Protection",
            str(
                security_parameters.get(
                    "replay_protection",
                    "Unknown"
                )
            )
        ],
        [
            "Metadata Exposure",
            str(
                security_parameters.get(
                    "metadata_exposure",
                    "Unknown"
                )
            )
        ]
    ]

    configuration_table = Table(
        configuration_data,
        colWidths=[220, 230]
    )

    configuration_table.setStyle(
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
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(configuration_table)

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # 3. TRAFFIC ANALYSIS
    # --------------------------------------

    story.append(
        Paragraph(
            "3. Traffic Analysis",
            styles["Heading2"]
        )
    )

    traffic_data = [
        [
            "Feature",
            "Value"
        ],
        [
            "Packet Count",
            str(
                traffic.get(
                    "packet_count",
                    "Unknown"
                )
            )
        ],
        [
            "Total Bytes",
            str(
                traffic.get(
                    "total_bytes",
                    "Unknown"
                )
            )
        ],
        [
            "Average Packet Size",
            str(
                traffic.get(
                    "avg_packet_size",
                    "Unknown"
                )
            )
        ],
        [
            "Flow Duration",
            str(
                traffic.get(
                    "flow_duration",
                    "Unknown"
                )
            )
        ],
        [
            "Flow Count",
            str(
                traffic.get(
                    "flow_count",
                    "Unknown"
                )
            )
        ],
        [
            "Packets Per Second",
            str(
                traffic.get(
                    "packets_per_second",
                    "Unknown"
                )
            )
        ],
        [
            "Bytes Per Second",
            str(
                traffic.get(
                    "bytes_per_second",
                    "Unknown"
                )
            )
        ]
    ]

    traffic_table = Table(
        traffic_data,
        colWidths=[220, 230]
    )

    traffic_table.setStyle(
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
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(traffic_table)

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # 4. AI TRAFFIC CLASSIFICATION
    # --------------------------------------

    story.append(
        Paragraph(
            "4. AI Traffic Classification",
            styles["Heading2"]
        )
    )

    confidence = ai_prediction.get(
        "confidence",
        0
    )

    if isinstance(
        confidence,
        (int, float)
    ):

        if 0 <= confidence <= 1:

            confidence_display = (
                f"{confidence * 100:.0f}%"
            )

        else:

            confidence_display = str(
                confidence
            )

    else:

        confidence_display = str(
            confidence
        )


    ai_data = [
        [
            "Prediction",
            str(
                ai_prediction.get(
                    "traffic_type",
                    "Unknown"
                )
            )
        ],
        [
            "Confidence",
            confidence_display
        ],
        [
            "Model",
            str(
                ai_prediction.get(
                    "model",
                    "Unknown"
                )
            )
        ]
    ]

    ai_table = Table(
        ai_data,
        colWidths=[160, 290]
    )

    ai_table.setStyle(
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
                7
            )
        ])
    )

    story.append(ai_table)

    story.append(
        Spacer(1, 20)
    )


    # --------------------------------------
    # 5. DETAILED SECURITY FINDINGS
    # --------------------------------------

    story.append(
        Paragraph(
            "5. Detailed Security Findings",
            styles["Heading2"]
        )
    )

    finding_data = [
        [
            "Parameter",
            "Status",
            "Details"
        ]
    ]

    for finding in findings:

        if isinstance(
            finding,
            dict
        ):

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

            message = str(
                finding
            )

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
    # 6. SECURITY RECOMMENDATIONS
    # --------------------------------------

    story.append(
        Paragraph(
            "6. Security Recommendations",
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

    output = generate_technical_report()

    print(
        "Technical report generated successfully."
    )

    print(
        "File:",
        output
    )