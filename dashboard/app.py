import streamlit as st
import json

# -----------------------------
# PAGE SETTINGS
# -----------------------------

st.set_page_config(
    page_title="IPsec VPN Security Analyzer",
    page_icon="🔐",
    layout="wide"
)

# -----------------------------
# LOAD SECURITY RESULT
# -----------------------------

with open("data/security_result.json", "r") as file:
    result = json.load(file)

# -----------------------------
# TITLE
# -----------------------------

st.title("🔐 IPsec VPN Security Analyzer")
st.write("Security Assessment Dashboard")

st.divider()

# -----------------------------
# SECURITY SCORE
# -----------------------------

col1, col2 = st.columns(2)

with col1:
    st.metric(
        "Security Score",
        f'{result["security_score"]} / 100'
    )

with col2:
    st.metric(
        "Risk Level",
        result["risk_level"]
    )

st.divider()

# -----------------------------
# VPN CONFIGURATION
# -----------------------------

st.header("🔐 VPN Configuration")

security = result.get("security_parameters", {})
protocol = result.get("protocol_analysis", {})

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "IKE Version",
        protocol.get("ike_version", "N/A")
    )

with col2:
    st.metric(
        "Encryption",
        security.get("encryption", "N/A")
    )

with col3:
    st.metric(
        "VPN Mode",
        protocol.get("mode", "N/A")
    )

with col4:
    st.metric(
        "DH Group",
        security.get("dh_group", "N/A")
    )

col1, col2, col3, col4 = st.columns(4)

with col1:
    esp_status = protocol.get("esp_detected", False)

    st.metric(
        "ESP Detected",
        "Yes" if esp_status else "No"
    )

with col2:
    st.metric(
        "PFS",
        "Enabled" if security.get("pfs", False) else "Disabled"
    )

with col3:
    st.metric(
        "Replay Protection",
        "Enabled"
        if security.get("replay_protection", False)
        else "Disabled"
    )

with col4:
    st.metric(
        "Key Lifetime",
        f'{security.get("key_lifetime", "N/A")} sec'
    )

st.divider()

# -----------------------------
# TRAFFIC ANALYSIS
# -----------------------------

st.header("📊 Traffic Analysis")

traffic = result.get("traffic_features", {})

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Packet Count",
        f'{traffic.get("packet_count", "N/A"):,}'
        if isinstance(traffic.get("packet_count"), int)
        else traffic.get("packet_count", "N/A")
    )

with col2:
    st.metric(
        "Average Packet Size",
        f'{traffic.get("avg_packet_size", "N/A")} bytes'
    )

with col3:
    st.metric(
        "Flow Duration",
        f'{traffic.get("flow_duration", "N/A")} sec'
    )

st.divider()

# -----------------------------
# AI TRAFFIC CLASSIFICATION
# -----------------------------

st.header("🤖 AI Traffic Classification")

ai_prediction = result.get("ai_prediction", {})

traffic_type = ai_prediction.get(
    "traffic_type",
    "N/A"
)

confidence = ai_prediction.get(
    "confidence",
    0
)

col1, col2 = st.columns(2)

with col1:
    st.metric(
        "Predicted Traffic Type",
        traffic_type
    )

with col2:
    st.metric(
        "AI Confidence",
        f"{confidence * 100:.1f}%"
    )

if confidence >= 0.80:
    st.success(
        f"🤖 AI classification confidence is high: "
        f"{confidence * 100:.1f}%"
    )

elif confidence >= 0.50:
    st.warning(
        f"🤖 AI classification confidence is moderate: "
        f"{confidence * 100:.1f}%"
    )

else:
    st.error(
        f"🤖 AI classification confidence is low: "
        f"{confidence * 100:.1f}%"
    )

st.divider()

# -----------------------------
# SECURITY FINDINGS
# -----------------------------

st.header("🔍 Security Findings")

for finding in result["findings"]:

    parameter = finding["parameter"]
    status = finding["status"]
    message = finding["message"]

    if status == "GOOD":

        st.success(
            f"✅ {parameter}: {message}"
        )

    elif status == "WARNING":

        st.warning(
            f"⚠️ {parameter}: {message}"
        )

    else:

        st.error(
            f"🔴 {parameter}: {message}"
        )

st.divider()

# -----------------------------
# RECOMMENDATIONS
# -----------------------------

st.header("💡 Recommendations")

if result["recommendations"]:

    for recommendation in result["recommendations"]:

        st.warning(
            f"• {recommendation}"
        )

else:

    st.success(
        "✅ No major security recommendations."
    )

st.divider()

# -----------------------------
# THREAT MATRIX
# -----------------------------

st.header("🛡️ Threat Matrix")

st.write(
    "Overview of identified security risks in the IPsec VPN configuration."
)

for finding in result["findings"]:

    parameter = finding["parameter"]
    status = finding["status"]

    if status == "GOOD":
        risk = "Low"

    elif status == "WARNING":
        risk = "Medium"

    else:
        risk = "High"

    if status == "GOOD":

        st.success(
            f"🟢 {parameter}  |  Status: {status}  |  Risk: {risk}"
        )

    elif status == "WARNING":

        st.warning(
            f"🟡 {parameter}  |  Status: {status}  |  Risk: {risk}"
        )

    else:

        st.error(
            f"🔴 {parameter}  |  Status: {status}  |  Risk: {risk}"
        )

st.divider()

# -----------------------------
# CAPTURE INFORMATION
# -----------------------------

st.header("📁 Capture Information")

st.write(
    f"**Capture ID:** {result.get('capture_id', 'N/A')}"
)

st.write(
    f"**IPsec Detected:** "
    f"{'Yes' if protocol.get('ipsec_detected', False) else 'No'}"
)

st.write(
    f"**Metadata Exposure:** "
    f"{'Yes' if security.get('metadata_exposure', False) else 'No'}"
)

st.divider()

st.caption(
    "IPsec VPN Security Analyzer • Security Assessment & "
    "Traffic Intelligence Dashboard"
)