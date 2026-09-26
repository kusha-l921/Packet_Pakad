from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

import os
import json
import shutil

from backend.parser.pcap_parser import parse_pcap
from security_engine.assessment import analyze_security

from reports.executive_report import (
    generate_executive_report
)

from reports.technical_report import (
    generate_technical_report
)


# ==========================================
# TUNNELGUARD API
# ==========================================

app = FastAPI(
    title="TUNNELGUARD API",
    description="AI-Powered IPsec VPN Security Analyzer",
    version="1.0.0",
)


# ==========================================
# CORS
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# DIRECTORIES
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

UPLOAD_DIR = os.path.join(
    DATA_DIR,
    "uploads"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports"
)


os.makedirs(
    UPLOAD_DIR,
    exist_ok=True
)

os.makedirs(
    REPORT_DIR,
    exist_ok=True
)


# ==========================================
# HOME
# ==========================================

@app.get("/")
def home():

    return {
        "message": "TUNNELGUARD API is running",
        "status": "online",
        "version": "1.0.0"
    }


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ==========================================
# ANALYZE PCAP
# ==========================================

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...)
):

    # --------------------------------------
    # Validate file
    # --------------------------------------

    if not file.filename:

        return {
            "error": "No file selected"
        }


    filename = file.filename

    extension = os.path.splitext(
        filename
    )[1].lower()


    allowed_extensions = [
        ".pcap",
        ".pcapng",
        ".cap"
    ]


    if extension not in allowed_extensions:

        return {
            "error": (
                "Invalid file type. "
                "Please upload a PCAP file."
            )
        }


    # --------------------------------------
    # Save uploaded PCAP
    # --------------------------------------

    safe_filename = os.path.basename(
        filename
    )

    upload_path = os.path.join(
        UPLOAD_DIR,
        safe_filename
    )


    try:

        with open(
            upload_path,
            "wb"
        ) as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )

    except Exception as error:

        return {
            "error": (
                "Could not save uploaded file",
                str(error)
            )
        }


    # --------------------------------------
    # Parse PCAP
    # --------------------------------------

    try:

        analysis_data = parse_pcap(
            upload_path
        )

    except Exception as error:

        return {
            "error": (
                "PCAP parsing failed",
                str(error)
            )
        }


    # --------------------------------------
    # Capture ID
    # --------------------------------------

    analysis_data[
        "capture_id"
    ] = safe_filename


    # --------------------------------------
    # Security Assessment
    # --------------------------------------

    try:

        security_result = analyze_security(
            analysis_data
        )

    except Exception as error:

        security_result = {

            "security_score": 0,

            "risk_level": "HIGH",

            "score_details": {
                "earned_points": 0,
                "available_points": 0
            },

            "findings": [

                {
                    "parameter": "Security Engine",
                    "status": "ERROR",
                    "message": str(error)
                }

            ],

            "recommendations": [

                {
                    "parameter": "Security Engine",
                    "status": "ACTION",
                    "message": (
                        "Security assessment "
                        "could not be completed."
                    )
                }

            ]

        }


    # --------------------------------------
    # Attach Security Result
    # --------------------------------------

    analysis_data[
        "security"
    ] = security_result


    # --------------------------------------
    # Save Latest Analysis
    # --------------------------------------

    result_path = os.path.join(
        DATA_DIR,
        "latest_analysis.json"
    )


    try:

        with open(
            result_path,
            "w"
        ) as result_file:

            json.dump(
                analysis_data,
                result_file,
                indent=2
            )

    except Exception as error:

        print(
            "Could not save analysis:",
            error
        )


    # --------------------------------------
    # GENERATE REPORTS AUTOMATICALLY
    # --------------------------------------

    try:

        generate_executive_report(
            analysis_data
        )

        generate_technical_report(
            analysis_data
        )

        print(
            "PDF reports generated successfully."
        )

    except Exception as error:

        print(
            "Could not generate reports:",
            error
        )


    # --------------------------------------
    # Return Result
    # --------------------------------------

    return analysis_data


# ==========================================
# LATEST ANALYSIS
# ==========================================

@app.get("/analysis/latest")
def latest_analysis():

    result_path = os.path.join(
        DATA_DIR,
        "latest_analysis.json"
    )


    if not os.path.exists(
        result_path
    ):

        return {
            "message": "No analysis available"
        }


    with open(
        result_path,
        "r"
    ) as file:

        return json.load(file)


# ==========================================
# EXECUTIVE REPORT
# ==========================================

@app.get("/reports/executive")
def executive_report():

    report_path = os.path.join(
        REPORT_DIR,
        "IPsec_Executive_Report.pdf"
    )


    if not os.path.exists(
        report_path
    ):

        return {
            "error": "Executive report not found"
        }


    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename="TUNNELGUARD_Executive_Report.pdf"
    )


# ==========================================
# TECHNICAL REPORT
# ==========================================

@app.get("/reports/technical")
def technical_report():

    report_path = os.path.join(
        REPORT_DIR,
        "IPsec_Technical_Report.pdf"
    )


    if not os.path.exists(
        report_path
    ):

        return {
            "error": "Technical report not found"
        }


    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename="TUNNELGUARD_Technical_Report.pdf"
    )