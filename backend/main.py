from fastapi import FastAPI
from security_engine.assessment import analyze_security

app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "IPsec VPN Security Analyzer API is running"
    }


@app.post("/analyze")
def analyze(data: dict):

    result = analyze_security(data)

    return result