import os
import json
import random

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_data")
db_path = os.path.join(DATA_DIR, "vulnerability_db.json")

def get_compliance(cve):
    # Deterministically generate compliance mapping based on CVE ID
    random.seed(cve)
    owasp_top_10 = ["A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures", "A03:2021-Injection", "A04:2021-Insecure Design", "A05:2021-Security Misconfiguration", "A06:2021-Vulnerable and Outdated Components", "A07:2021-Identification and Authentication Failures", "A08:2021-Software and Data Integrity Failures", "A09:2021-Security Logging and Monitoring Failures", "A10:2021-Server-Side Request Forgery"]
    
    nist = ["NIST SP 800-53: SI-2", "NIST SP 800-53: SA-11", "NIST SP 800-53: SC-28", "NIST SP 800-53: AC-3"]
    
    openssf = ["OpenSSF: Dependency Management", "OpenSSF: Vulnerability Reporting", "OpenSSF: Security Policies"]
    
    # Injection/Log4Shell gets specific mapping
    if "2021-44228" in cve:
        return {
            "OWASP": "A06:2021-Vulnerable and Outdated Components",
            "NIST": "NIST SP 800-53: SI-2 Flaw Remediation",
            "OpenSSF": "OpenSSF: Dependency Management"
        }
    
    return {
        "OWASP": random.choice(owasp_top_10),
        "NIST": random.choice(nist),
        "OpenSSF": random.choice(openssf)
    }

try:
    with open(db_path, "r") as f:
        data = json.load(f)
        
    for entry in data:
        if "compliance" not in entry:
            entry["compliance"] = get_compliance(entry["cve_id"])
            
    with open(db_path, "w") as f:
        json.dump(data, f, indent=2)
    print("Successfully mapped compliance data to vulnerability DB.")
except Exception as e:
    print(f"Error: {e}")
