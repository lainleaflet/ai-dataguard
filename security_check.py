import re

DETECTION_RULES = [ #regex rules to detect sensitive info in user inputs :)
    {
        "name": "ssn",
        "category": "PII",
        "severity" : "high", 
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b", #regex for ssn! look for 3 digits, a dash, 2 digits, a dash, then 4 digits.
        "classification": "restricted"
    },

    {
        "name": "potential api key",
        "category": "credentials",
        "severity" : "high", 
        "pattern": (
                r"\b(?:sk-[A-Za-z0-9_-]{16,}" 
                r"|AKIA[A-Z0-9]{16})\b" # specifically for common AWS access keys
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

def scan_prompt(prompt): #scans input and matches it with regex rules :)
    issues = []
    for rule in DETECTION_RULES:
        matches = re.finditer(rule["pattern"], prompt, flags=re.IGNORECASE) #re.finditer() returns an iterator type. 

        for match in matches: #for each iterator...
            issues.append({ # we append each issue. when we do this, the iterator is converted to a string. 
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "classification": rule["classification"],
                "matched_text": match.group(),
                "start": match.start(),
                "end": match.end(),
            })

    return issues

def classify_prompt(issues):
    if not issues:
        return "public";

    classifications = [ # creating an array of classifications from our gathered issues :)
        issue["classification"] for issue in issues 
    ]

    if "restricted" in classifications: #so if there is even a single restricted or confidential element, we will classify the entire thing as such. 
        return "restricted"
    if "confidential" in classifications:
        return "confidential"
    return "public";

def evaluate_prompt(classification):
    if classification == "restricted":
        print("prompt contains restricted information.")
        return "block";
    elif classification == "confidential":
        print("prompt contains confidential information.")
        return "redact";

    return "allow"; 

def redact_prompt(prompt, issues):
    redacted_prompt = prompt;
    for issue in issues:
        start = issue["start"]
        end = issue["end"]
        redacted_prompt = redacted_prompt[:start] + "[REDACTED: " + issue["name"] + "]" + redacted_prompt[end:];
    return redacted_prompt;

def analyze_prompt(prompt):
    issues = scan_prompt(prompt)
    classification = classify_prompt(issues)
    action = evaluate_prompt(classification)

    #at the moment we're redacting every prompt until i can figure out how to block prompts. 
    redacted_prompt = redact_prompt(prompt, issues)
    return {
        "prompt": prompt,
        "action": action,
        "redacted_prompt": redacted_prompt,
        "issues": issues,
        "classification": classification 
    }


