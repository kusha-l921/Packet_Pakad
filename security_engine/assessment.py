import json


# -----------------------------
# SECURITY ASSESSMENT FUNCTION
# -----------------------------

def analyze_security(data):

    security = data.get("security_parameters", {})

    findings = []
    recommendations = []

    # -----------------------------
    # ENCRYPTION
    # -----------------------------

    encryption = security.get("encryption", "")

    if encryption == "AES-256":
        findings.append({
            "parameter": "Encryption",
            "status": "GOOD",
            "message": "AES-256 strong encryption is being used."
        })
        encryption_score = 25

    else:
        findings.append({
            "parameter": "Encryption",
            "status": "WARNING",
            "message": f"{encryption} encryption is weaker than AES-256."
        })
        recommendations.append(
            "Use strong AES-256 encryption for better security."
        )
        encryption_score = 0

    # -----------------------------
    # PERFECT FORWARD SECRECY
    # -----------------------------

    pfs = security.get("pfs", False)

    if pfs:
        findings.append({
            "parameter": "PFS",
            "status": "GOOD",
            "message": "Perfect Forward Secrecy is enabled."
        })
        pfs_score = 15

    else:
        findings.append({
            "parameter": "PFS",
            "status": "HIGH_RISK",
            "message": "Perfect Forward Secrecy is disabled."
        })
        recommendations.append(
            "Enable Perfect Forward Secrecy (PFS) to protect past sessions."
        )
        pfs_score = 0

    # -----------------------------
    # DIFFIE-HELLMAN GROUP
    # -----------------------------

    dh_group = security.get("dh_group", 0)

    if dh_group >= 14:
        findings.append({
            "parameter": "DH Group",
            "status": "GOOD",
            "message": f"DH Group {dh_group} provides an acceptable key exchange strength."
        })
        dh_score = 20

    else:
        findings.append({
            "parameter": "DH Group",
            "status": "HIGH_RISK",
            "message": f"DH Group {dh_group} is weak."
        })
        recommendations.append(
            "Use a stronger Diffie-Hellman group for secure key exchange."
        )
        dh_score = 0

    # -----------------------------
    # KEY LIFETIME
    # -----------------------------

    key_lifetime = security.get("key_lifetime", 0)

    if key_lifetime <= 28800:
        findings.append({
            "parameter": "Key Lifetime",
            "status": "GOOD",
            "message": f"Key lifetime is {key_lifetime} seconds."
        })
        key_lifetime_score = 15

    else:
        findings.append({
            "parameter": "Key Lifetime",
            "status": "WARNING",
            "message": f"Key lifetime is {key_lifetime} seconds, which is relatively long."
        })
        recommendations.append(
            "Reduce the key lifetime to limit the exposure period of encryption keys."
        )
        key_lifetime_score = 0

    # -----------------------------
    # REPLAY PROTECTION
    # -----------------------------

    replay_protection = security.get(
        "replay_protection",
        False
    )

    if replay_protection:
        findings.append({
            "parameter": "Replay Protection",
            "status": "GOOD",
            "message": "Replay protection is enabled."
        })
        replay_score = 15

    else:
        findings.append({
            "parameter": "Replay Protection",
            "status": "HIGH_RISK",
            "message": "Replay protection is disabled."
        })
        recommendations.append(
            "Enable replay protection to prevent replay attacks."
        )
        replay_score = 0

    # -----------------------------
    # METADATA EXPOSURE
    # -----------------------------

    metadata_exposure = security.get(
        "metadata_exposure",
        False
    )

    if not metadata_exposure:
        findings.append({
            "parameter": "Metadata Exposure",
            "status": "GOOD",
            "message": "No significant metadata exposure detected."
        })
        metadata_score = 10

    else:
        findings.append({
            "parameter": "Metadata Exposure",
            "status": "HIGH_RISK",
            "message": "Sensitive metadata exposure detected."
        })
        recommendations.append(
            "Reduce sensitive metadata exposure in the VPN traffic."
        )
        metadata_score = 0

    # -----------------------------
    # SECURITY SCORE
    # -----------------------------

    security_score = (
        encryption_score
        + pfs_score
        + dh_score
        + key_lifetime_score
        + replay_score
        + metadata_score
    )

    # -----------------------------
    # RISK LEVEL
    # -----------------------------

    if security_score >= 80:
        risk_level = "LOW"

    elif security_score >= 60:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    # -----------------------------
    # FINAL RESULT
    # -----------------------------

    result = {
        "capture_id": data.get("capture_id", "N/A"),

        "protocol_analysis": data.get(
            "protocol_analysis",
            {}
        ),

        "security_parameters": data.get(
            "security_parameters",
            {}
        ),

        "traffic_features": data.get(
            "traffic_features",
            {}
        ),

        "ai_prediction": data.get(
            "ai_prediction",
            {}
        ),

        "security_score": security_score,

        "risk_level": risk_level,

        "findings": findings,

        "recommendations": recommendations
    }

    return result


# -----------------------------
# RUN AS SCRIPT
# -----------------------------

if __name__ == "__main__":

    with open(
        "data/mock_analysis.json",
        "r"
    ) as file:

        data = json.load(file)

    result = analyze_security(data)

    with open(
        "data/security_result.json",
        "w"
    ) as file:

        json.dump(
            result,
            file,
            indent=4
        )

    print("Security assessment completed.")
    print(
        "Security Score:",
        result["security_score"]
    )
    print(
        "Risk Level:",
        result["risk_level"]
    )