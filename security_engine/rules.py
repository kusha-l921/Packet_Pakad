import json
import sys
import os

# Allow Python to find assessment.py
sys.path.append(os.path.dirname(__file__))

from assessment import analyze_security


# Read input JSON
with open("data/mock_analysis.json", "r") as file:
    data = json.load(file)


# Run security analysis
result = analyze_security(data)


# Save result
with open("data/security_result.json", "w") as file:
    json.dump(result, file, indent=4)


# Display result
print("IPsec Security Analysis")
print("-----------------------")

print("Security Score:", result["security_score"], "/ 100")
print("Risk Level:", result["risk_level"])

print("\nSecurity Findings")
print("-----------------")

for finding in result["findings"]:
    print(
        finding["parameter"] + ": " +
        finding["status"] + " - " +
        finding["message"]
    )

print("\nRecommendations")
print("----------------")

if result["recommendations"]:
    for recommendation in result["recommendations"]:
        print("-", recommendation)
else:
    print("No major security recommendations.")

print("\nResult saved to: data/security_result.json")