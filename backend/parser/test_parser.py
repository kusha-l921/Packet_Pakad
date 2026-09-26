import json
import os
import sys

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

sys.path.insert(0, PROJECT_ROOT)

from backend.parser.pcap_parser import parse_pcap


# ---------------------------------------------------------
# PCAP FILE SELECTION
# ---------------------------------------------------------

if len(sys.argv) > 1:
    pcap_filename = sys.argv[1]
else:
    pcap_filename = "normal_traffic.pcap"


PCAP_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "uploads",
    pcap_filename
)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

print("=" * 60)
print("TUNNELGUARD - PCAP PARSER TEST")
print("=" * 60)

print()
print("Project:")
print(PROJECT_ROOT)

print()
print("PCAP:")
print(PCAP_PATH)

print()


# ---------------------------------------------------------
# CHECK FILE
# ---------------------------------------------------------

if not os.path.exists(PCAP_PATH):

    print("❌ PCAP FILE NOT FOUND")

    print()
    print("Expected location:")
    print(PCAP_PATH)

    print()

    print("Available PCAP files:")

    upload_dir = os.path.join(
        PROJECT_ROOT,
        "data",
        "uploads"
    )

    if os.path.exists(upload_dir):

        files = os.listdir(upload_dir)

        pcap_files = [
            file
            for file in files
            if file.lower().endswith(
                (".pcap", ".pcapng", ".cap")
            )
        ]

        if pcap_files:

            for file in pcap_files:
                print(" -", file)

        else:
            print(" - No PCAP files found")

    print()

    sys.exit(1)


print("✅ PCAP file found")


# ---------------------------------------------------------
# PARSE PCAP
# ---------------------------------------------------------

print()

try:

    result = parse_pcap(PCAP_PATH)

except Exception as error:

    print("❌ PCAP parsing failed")

    print()
    print(error)

    sys.exit(1)


# ---------------------------------------------------------
# PROTOCOL ANALYSIS
# ---------------------------------------------------------

print("-" * 60)
print("PROTOCOL ANALYSIS")
print("-" * 60)

print(
    json.dumps(
        result.get(
            "protocol_analysis",
            {}
        ),
        indent=2
    )
)


# ---------------------------------------------------------
# TRAFFIC FEATURES
# ---------------------------------------------------------

print()
print("-" * 60)
print("TRAFFIC FEATURES")
print("-" * 60)

print(
    json.dumps(
        result.get(
            "traffic_features",
            {}
        ),
        indent=2
    )
)


# ---------------------------------------------------------
# SECURITY PARAMETERS
# ---------------------------------------------------------

print()
print("-" * 60)
print("SECURITY PARAMETERS")
print("-" * 60)

print(
    json.dumps(
        result.get(
            "security_parameters",
            {}
        ),
        indent=2
    )
)


# ---------------------------------------------------------
# AI PREDICTION
# ---------------------------------------------------------

print()
print("-" * 60)
print("AI PREDICTION")
print("-" * 60)

print(
    json.dumps(
        result.get(
            "ai_prediction",
            {}
        ),
        indent=2
    )
)


# ---------------------------------------------------------
# COMPLETE RESULT
# ---------------------------------------------------------

print()
print("-" * 60)
print("COMPLETE PARSER RESULT")
print("-" * 60)

print(
    json.dumps(
        result,
        indent=2
    )
)


# ---------------------------------------------------------
# SUCCESS
# ---------------------------------------------------------

print()
print("=" * 60)
print("✅ PCAP PARSER TEST COMPLETE")
print("=" * 60)