from typing import Any, Dict


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def analyze_security(analysis_data: Dict[str, Any]) -> Dict[str, Any]:

    security = analysis_data.get(
        "security_parameters",
        {}
    )

    findings = []
    recommendations = []

    score = 0
    max_score = 0

    # =========================================================
    # ENCRYPTION
    # =========================================================

    encryption = security.get(
        "encryption",
        "Unknown"
    )

    if encryption != "Unknown":

        max_score += 25

        if encryption in {
            "AES-256",
            "AES-GCM",
            "ChaCha20-Poly1305",
        }:

            score += 25

            findings.append({
                "parameter": "Encryption",
                "status": "GOOD",
                "message": (
                    f"{encryption} strong encryption "
                    "is being used."
                ),
            })

        elif encryption == "AES-128":

            score += 20

            findings.append({
                "parameter": "Encryption",
                "status": "GOOD",
                "message": (
                    "AES-128 encryption is being used."
                ),
            })

            recommendations.append({
                "parameter": "Encryption",
                "status": "INFO",
                "message": (
                    "Consider AES-256 or an approved "
                    "AEAD cipher where supported."
                ),
            })

        else:

            findings.append({
                "parameter": "Encryption",
                "status": "WARNING",
                "message": (
                    f"Encryption detected: {encryption}."
                ),
            })

            recommendations.append({
                "parameter": "Encryption",
                "status": "ACTION",
                "message": (
                    "Use a modern strong encryption algorithm."
                ),
            })

    else:

        findings.append({
            "parameter": "Encryption",
            "status": "UNKNOWN",
            "message": (
                "Encryption could not be determined "
                "from the captured traffic."
            ),
        })

        recommendations.append({
            "parameter": "Encryption",
            "status": "INFO",
            "message": (
                "Capture the IKE negotiation containing "
                "the Security Association proposal."
            ),
        })

    # =========================================================
    # PFS
    # =========================================================

    pfs = security.get(
        "pfs",
        "Unknown"
    )

    if isinstance(pfs, bool):

        max_score += 15

        if pfs:

            score += 15

            findings.append({
                "parameter": "PFS",
                "status": "GOOD",
                "message": (
                    "Perfect Forward Secrecy is enabled."
                ),
            })

        else:

            findings.append({
                "parameter": "PFS",
                "status": "HIGH_RISK",
                "message": (
                    "Perfect Forward Secrecy is disabled."
                ),
            })

            recommendations.append({
                "parameter": "PFS",
                "status": "ACTION",
                "message": (
                    "Enable Perfect Forward Secrecy "
                    "for Child SA negotiations."
                ),
            })

    else:

        findings.append({
            "parameter": "PFS",
            "status": "UNKNOWN",
            "message": (
                "PFS status could not be determined "
                "from the captured traffic."
            ),
        })

    # =========================================================
    # DH GROUP
    # =========================================================

    dh_group = security.get(
        "dh_group",
        "Unknown"
    )

    if _is_number(dh_group):

        max_score += 20

        if dh_group >= 14:

            score += 20

            findings.append({
                "parameter": "DH Group",
                "status": "GOOD",
                "message": (
                    f"DH Group {dh_group} provides "
                    "an acceptable key exchange strength."
                ),
            })

        else:

            findings.append({
                "parameter": "DH Group",
                "status": "HIGH_RISK",
                "message": (
                    f"DH Group {dh_group} is considered "
                    "weak for the configured security policy."
                ),
            })

            recommendations.append({
                "parameter": "DH Group",
                "status": "ACTION",
                "message": (
                    "Use a stronger approved "
                    "Diffie-Hellman group."
                ),
            })

    else:

        findings.append({
            "parameter": "DH Group",
            "status": "UNKNOWN",
            "message": (
                "DH group could not be determined "
                "from the captured traffic."
            ),
        })

    # =========================================================
    # KEY LIFETIME
    # =========================================================

    key_lifetime = security.get(
        "key_lifetime",
        "Unknown"
    )

    if _is_number(key_lifetime):

        max_score += 15

        if key_lifetime <= 28800:

            score += 15

            findings.append({
                "parameter": "Key Lifetime",
                "status": "GOOD",
                "message": (
                    f"Key lifetime is "
                    f"{key_lifetime} seconds."
                ),
            })

        else:

            score += 8

            findings.append({
                "parameter": "Key Lifetime",
                "status": "WARNING",
                "message": (
                    f"Key lifetime is "
                    f"{key_lifetime} seconds."
                ),
            })

            recommendations.append({
                "parameter": "Key Lifetime",
                "status": "ACTION",
                "message": (
                    "Consider using a shorter key lifetime "
                    "according to the organization's policy."
                ),
            })

    else:

        findings.append({
            "parameter": "Key Lifetime",
            "status": "UNKNOWN",
            "message": (
                "Key lifetime was not observed "
                "in the captured traffic."
            ),
        })

    # =========================================================
    # REPLAY PROTECTION
    # =========================================================

    replay_protection = security.get(
        "replay_protection",
        "Unknown"
    )

    if isinstance(replay_protection, bool):

        max_score += 15

        if replay_protection:

            score += 15

            findings.append({
                "parameter": "Replay Protection",
                "status": "GOOD",
                "message": (
                    "Replay protection is enabled."
                ),
            })

        else:

            findings.append({
                "parameter": "Replay Protection",
                "status": "HIGH_RISK",
                "message": (
                    "Replay protection is disabled."
                ),
            })

            recommendations.append({
                "parameter": "Replay Protection",
                "status": "ACTION",
                "message": (
                    "Enable replay protection for IPsec traffic."
                ),
            })

    else:

        findings.append({
            "parameter": "Replay Protection",
            "status": "UNKNOWN",
            "message": (
                "Replay protection status could not "
                "be determined from the capture."
            ),
        })

    # =========================================================
    # METADATA EXPOSURE
    # =========================================================

    metadata_exposure = security.get(
        "metadata_exposure",
        "Unknown"
    )

    if isinstance(metadata_exposure, bool):

        max_score += 10

        if not metadata_exposure:

            score += 10

            findings.append({
                "parameter": "Metadata Exposure",
                "status": "GOOD",
                "message": (
                    "No significant metadata exposure detected."
                ),
            })

        else:

            findings.append({
                "parameter": "Metadata Exposure",
                "status": "WARNING",
                "message": (
                    "VPN traffic metadata may be observable."
                ),
            })

            recommendations.append({
                "parameter": "Metadata Exposure",
                "status": "INFO",
                "message": (
                    "Review exposed traffic metadata such as "
                    "packet timing, sizes, endpoints and flow patterns."
                ),
            })

    # =========================================================
    # FINAL SCORE
    # =========================================================

    if max_score == 0:

        security_score = 0
        risk_level = "UNKNOWN"

    else:

        security_score = round(
            (score / max_score) * 100
        )

        if security_score >= 80:

            risk_level = "LOW"

        elif security_score >= 60:

            risk_level = "MEDIUM"

        else:

            risk_level = "HIGH"

    return {
        "security_score": security_score,
        "risk_level": risk_level,
        "score_details": {
            "earned_points": score,
            "available_points": max_score,
        },
        "findings": findings,
        "recommendations": recommendations,
    }
