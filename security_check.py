import re

DETECTION_RULES = [
    {
        "name": "ssn",
        "category": "PII",
        "severity" : "high", 
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "classification": "restricted"
    },
    {
        "name": "potential api key",
        "category": "credentials",
        "severity" : "high", 
        "pattern": (
                r"\b(?:sk-[A-Za-z0-9_-]{16,}"
                r"|AKIA[A-Z0-9]{16})\b"
            ),
        "classification": "restricted"
    },
    {
            "name": "password assignment",
            "category": "credentials",
            "severity" : "high", 
            "pattern": (
                r"\bpassword\s*[:=]\s*"
                r"\S+"
            ),
            "classification": "restricted"
    },
    {
        "name": "confidential business data",
        "category": "business information",
        "severity" : "medium", 
        "pattern": (
            r"\b(?:confidential|"
            r"proprietary|internal only)\b"
        ),
        "classification": "confidential"
    }
]