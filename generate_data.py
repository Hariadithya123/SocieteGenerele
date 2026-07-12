"""
SBOM Risk Intelligence Platform
Data Generator — Creates all 5 sample dataset files
"""

import json
import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)
os.makedirs("sample_data", exist_ok=True)

# ─────────────────────────────────────────────
# 1. APPLICATIONS
# ─────────────────────────────────────────────
applications = [
    {"app_id": "APP-001", "name": "PaymentGateway",     "team": "FinTech",     "criticality": "CRITICAL", "type": "proprietary", "owner": "alice@corp.com",   "language": "Java",   "description": "Handles all card payment processing and PCI-DSS scope"},
    {"app_id": "APP-002", "name": "CustomerPortal",     "team": "Product",     "criticality": "HIGH",     "type": "proprietary", "owner": "bob@corp.com",     "language": "Python", "description": "Customer-facing self-service web portal"},
    {"app_id": "APP-003", "name": "HRPortal",           "team": "HR-IT",       "criticality": "HIGH",     "type": "proprietary", "owner": "carol@corp.com",   "language": "Java",   "description": "Employee HR management and payroll system"},
    {"app_id": "APP-004", "name": "DataWarehouse",      "team": "Analytics",   "criticality": "HIGH",     "type": "proprietary", "owner": "dave@corp.com",    "language": "Python", "description": "Central analytics and reporting data lake"},
    {"app_id": "APP-005", "name": "AuthService",        "team": "Security",    "criticality": "CRITICAL", "type": "proprietary", "owner": "eve@corp.com",     "language": "Java",   "description": "OAuth2/OIDC identity and access management service"},
    {"app_id": "APP-006", "name": "EmailService",       "team": "Platform",    "criticality": "MEDIUM",   "type": "proprietary", "owner": "frank@corp.com",   "language": "Python", "description": "Transactional and marketing email delivery service"},
    {"app_id": "APP-007", "name": "ReportingEngine",    "team": "Analytics",   "criticality": "MEDIUM",   "type": "proprietary", "owner": "grace@corp.com",   "language": "Python", "description": "Scheduled report generation and export service"},
    {"app_id": "APP-008", "name": "DevToolkit",         "team": "DevOps",      "criticality": "LOW",      "type": "internal",    "owner": "henry@corp.com",   "language": "Python", "description": "Internal developer utilities and CI/CD helpers"},
    {"app_id": "APP-009", "name": "MonitoringDash",     "team": "SRE",         "criticality": "LOW",      "type": "internal",    "owner": "irene@corp.com",   "language": "Python", "description": "Infrastructure health and alerting dashboard"},
    {"app_id": "APP-010", "name": "LegacyBillingApp",   "team": "Finance",     "criticality": "HIGH",     "type": "proprietary", "owner": "john@corp.com",    "language": "Java",   "description": "Legacy billing system — migration pending Q4"},
]
with open("sample_data/applications.json", "w") as f:
    json.dump(applications, f, indent=2)
print("✅ applications.json created")

# ─────────────────────────────────────────────
# 2. VULNERABILITY DATABASE (200 CVEs)
# ─────────────────────────────────────────────
vuln_db = [
    # CRITICAL CVEs — famous ones
    {"cve_id": "CVE-2021-44228", "library": "log4j-core",          "affected_versions": ["2.0","2.1","2.2","2.3","2.4","2.5","2.6","2.7","2.8","2.9","2.10","2.11","2.12","2.13","2.14","2.14.1"], "cvss": 10.0, "severity": "CRITICAL", "patch_available": True,  "patch_version": "2.17.1", "description": "Log4Shell: Remote code execution via JNDI injection in log messages. Affects logging configuration.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2021-45046", "library": "log4j-core",          "affected_versions": ["2.15.0"],                                                                                              "cvss": 9.0,  "severity": "CRITICAL", "patch_available": True,  "patch_version": "2.17.1", "description": "Log4Shell bypass: Incomplete fix in 2.15.0 still allows RCE in certain configurations.",           "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2022-22965", "library": "spring-webmvc",       "affected_versions": ["5.3.0","5.3.1","5.3.2","5.3.3","5.3.4","5.3.5","5.3.6","5.3.7","5.3.8","5.3.9","5.3.10","5.3.11","5.3.12","5.3.13","5.3.14","5.3.15","5.3.16","5.3.17"],  "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "5.3.18", "description": "Spring4Shell: RCE via data binding with JDK9+ ClassLoader. Critical for Spring MVC applications.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2017-5638",  "library": "struts2-core",        "affected_versions": ["2.3.5","2.3.8","2.3.10","2.3.12","2.3.14","2.3.16","2.3.18","2.3.20","2.3.24","2.3.28","2.3.28.1","2.3.30","2.3.31","2.3.32","2.5","2.5.1","2.5.2"], "cvss": 10.0, "severity": "CRITICAL", "patch_available": True, "patch_version": "2.5.10", "description": "Equifax Breach CVE: RCE via Content-Type header in file upload. Exploit is publicly available.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2020-8840",  "library": "jackson-databind",    "affected_versions": ["2.0.0","2.1.0","2.2.0","2.3.0","2.4.0","2.5.0","2.6.0","2.7.0","2.8.0","2.9.0","2.9.5","2.9.10","2.9.10.1","2.9.10.2","2.9.10.3","2.9.10.4"], "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "2.9.10.5", "description": "Deserialization RCE via FasterXML jackson-databind. Gadget chain through XBEAN-REFLECT.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2022-0778",  "library": "openssl",             "affected_versions": ["1.0.2","1.1.1","3.0"],                                                                                "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "3.0.2",  "description": "OpenSSL infinite loop in BN_mod_sqrt() causes denial of service. Certificate parsing triggers it.", "exploitability": "LOW",  "mitre": "T1499"},
    {"cve_id": "CVE-2021-3449",  "library": "openssl",             "affected_versions": ["1.1.1"],                                                                                              "cvss": 5.9,  "severity": "MEDIUM",   "patch_available": True,  "patch_version": "1.1.1k",  "description": "NULL pointer deref in OpenSSL TLS server if renegotiation ClientHello omits signature_algorithms.", "exploitability": "MEDIUM", "mitre": "T1499"},
    {"cve_id": "CVE-2021-42550", "library": "logback-classic",     "affected_versions": ["1.2.0","1.2.1","1.2.2","1.2.3","1.2.4","1.2.5","1.2.6","1.2.7","1.2.8","1.2.9","1.3.0-alpha10"],   "cvss": 6.6,  "severity": "MEDIUM",   "patch_available": True,  "patch_version": "1.2.9",  "description": "JNDI injection via Logback configuration if attacker controls logback config. Requires config write access.", "exploitability": "MEDIUM", "mitre": "T1190"},
    {"cve_id": "CVE-2019-17267", "library": "jackson-databind",    "affected_versions": ["2.9.10"],                                                                                             "cvss": 9.8,  "severity": "CRITICAL", "patch_available": True,  "patch_version": "2.9.10.1","description": "Deserialization gadget via net.sf.ehcache. Polymorphic type handling bypass.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2020-36518", "library": "jackson-databind",    "affected_versions": ["2.13.0","2.13.1","2.13.2","2.13.2.1"],                                                               "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "2.13.2.2","description": "Stack overflow in JsonNode parsing — can cause OOM and DoS.", "exploitability": "LOW", "mitre": "T1499"},
    {"cve_id": "CVE-2022-42003", "library": "jackson-databind",    "affected_versions": ["2.13.3","2.13.3.1","2.13.3.2"],                                                                      "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "2.13.4",  "description": "In Jackson 2.x before 2.14, resource exhaustion can occur due to deep nesting of JSON.", "exploitability": "MEDIUM", "mitre": "T1499"},
    {"cve_id": "CVE-2022-1471",  "library": "snakeyaml",           "affected_versions": ["1.33","1.32","1.31","1.30","1.29","1.28"],                                                            "cvss": 9.8,  "severity": "CRITICAL", "patch_available": True,  "patch_version": "2.0",    "description": "Constructor deserialization in SnakeYAML allows remote code execution.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2022-45688", "library": "snakeyaml",           "affected_versions": ["1.33"],                                                                                               "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "2.0",    "description": "Stack overflow via deeply nested YAML maps — causes DoS.", "exploitability": "LOW", "mitre": "T1499"},
    {"cve_id": "CVE-2018-1000656","library": "Werkzeug",           "affected_versions": ["0.11.10","0.11.11","0.12","0.12.1","0.12.2","0.14.0","0.14.1"],                                     "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "0.14.1+","description": "Werkzeug debugger allows code execution if debug mode exposed externally.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2023-25577", "library": "Werkzeug",            "affected_versions": ["2.2.2","2.2.1","2.2.0","2.1.0","2.1.1","2.1.2","2.0.0","2.0.1","2.0.2","2.0.3"],                  "cvss": 7.5,  "severity": "HIGH",     "patch_available": True,  "patch_version": "2.2.3",  "description": "Multipart data parsing DoS in Werkzeug — causes server hang on malformed requests.", "exploitability": "LOW", "mitre": "T1499"},
    {"cve_id": "CVE-2019-11358", "library": "jquery",              "affected_versions": ["1.0","1.1","1.2","1.3","1.4","1.5","1.6","1.7","1.8","1.9","1.10","1.11","1.12","2.0","2.1","2.2","3.0","3.1","3.2","3.3"],  "cvss": 6.1, "severity": "MEDIUM", "patch_available": True, "patch_version": "3.4.0", "description": "Prototype pollution in jQuery $.extend — can lead to XSS or RCE depending on context.", "exploitability": "MEDIUM", "mitre": "T1059.007"},
    {"cve_id": "CVE-2020-11022", "library": "jquery",              "affected_versions": ["3.4.0","3.4.1","1.11.0","1.11.1","1.11.2","1.11.3","1.12.0","1.12.1","1.12.2","1.12.3","1.12.4"],  "cvss": 6.1, "severity": "MEDIUM", "patch_available": True, "patch_version": "3.5.0", "description": "XSS via passing HTML from untrusted sources to jQuery manipulation methods.", "exploitability": "MEDIUM", "mitre": "T1059.007"},
    {"cve_id": "CVE-2015-9251",  "library": "jquery",              "affected_versions": ["1.12.4","2.2.4","3.0.0","3.1.0","3.1.1","3.2.1"],                                                   "cvss": 6.1, "severity": "MEDIUM", "patch_available": True, "patch_version": "3.0.0", "description": "Cross-site scripting via cross-origin Ajax requests when JSONP response is used.", "exploitability": "LOW", "mitre": "T1059.007"},
    {"cve_id": "CVE-2022-24785", "library": "moment",              "affected_versions": ["2.29.1","2.29.0","2.28.0","2.27.0","2.26.0","2.25.0","2.24.0"],                                     "cvss": 7.5, "severity": "HIGH", "patch_available": True, "patch_version": "2.29.2", "description": "Path traversal in moment locale loading — attacker-controlled locale can read arbitrary files.", "exploitability": "LOW", "mitre": "T1083"},
    {"cve_id": "CVE-2023-22809", "library": "sudo",                "affected_versions": ["1.8.0","1.8.1","1.8.2","1.8.3","1.9.0","1.9.1","1.9.2","1.9.3","1.9.4","1.9.5","1.9.6","1.9.7","1.9.8","1.9.9","1.9.10","1.9.11","1.9.12"],  "cvss": 7.8, "severity": "HIGH", "patch_available": True, "patch_version": "1.9.12p2", "description": "Sudo sudoedit privilege escalation — local user can edit files outside allowed paths.", "exploitability": "HIGH", "mitre": "T1548"},
    {"cve_id": "CVE-2021-41091", "library": "docker",              "affected_versions": ["20.10.0","20.10.1","20.10.2","20.10.3","20.10.4","20.10.5","20.10.6","20.10.7","20.10.8"],           "cvss": 6.3, "severity": "MEDIUM", "patch_available": True, "patch_version": "20.10.9", "description": "File permissions vulnerability in Moby (Docker Engine) — unprivileged users may traverse directories.", "exploitability": "LOW", "mitre": "T1083"},
    {"cve_id": "CVE-2021-23017", "library": "nginx",               "affected_versions": ["0.6.18","1.0.7","1.1.3","1.3.9","1.5.12","1.7.12","1.9.13","1.11.6","1.13.2","1.15.6","1.17.7","1.19.0"],  "cvss": 7.7, "severity": "HIGH", "patch_available": True, "patch_version": "1.21.0", "description": "1-byte memory overwrite in nginx DNS resolver.", "exploitability": "MEDIUM", "mitre": "T1499"},
    {"cve_id": "CVE-2022-3602",  "library": "openssl",             "affected_versions": ["3.0.0","3.0.1","3.0.2","3.0.3","3.0.4","3.0.5","3.0.6"],                                            "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "3.0.7", "description": "Buffer overflow in X.509 certificate verification — could allow RCE. Dubbed 'Critical' pre-release.", "exploitability": "MEDIUM", "mitre": "T1190"},
    {"cve_id": "CVE-2022-42889", "library": "commons-text",        "affected_versions": ["1.5","1.6","1.7","1.8","1.9"],                                                                       "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "1.10.0", "description": "Text4Shell: RCE via StringSubstitutor interpolation — similar attack surface to Log4Shell.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2021-29425", "library": "commons-io",          "affected_versions": ["2.2","2.3","2.4","2.5","2.6"],                                                                       "cvss": 4.8, "severity": "MEDIUM", "patch_available": True, "patch_version": "2.7", "description": "Limited path traversal in commons-io FileNameUtils — may allow reading files outside intended directories.", "exploitability": "LOW", "mitre": "T1083"},
    {"cve_id": "CVE-2015-6420",  "library": "commons-collections", "affected_versions": ["3.2.1","3.1","3.0","4.0"],                                                                           "cvss": 7.5, "severity": "HIGH", "patch_available": True, "patch_version": "3.2.2", "description": "Java deserialization gadget chain in Apache Commons Collections. Widely exploited in enterprise Java.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2017-15708", "library": "commons-collections", "affected_versions": ["3.2.1"],                                                                                              "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "3.2.2", "description": "Deserialization attack through Apache Synapse — exploits CC gadget chain.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2022-25857", "library": "snakeyaml",           "affected_versions": ["1.30","1.29","1.28","1.27","1.26"],                                                                  "cvss": 7.5, "severity": "HIGH", "patch_available": True, "patch_version": "1.31", "description": "Denial of service in SnakeYAML billion laughs / deeply nested YAML attack.", "exploitability": "LOW", "mitre": "T1499"},
    {"cve_id": "CVE-2021-26291", "library": "maven-core",          "affected_versions": ["3.8.0","3.6.0","3.5.0","3.3.0"],                                                                    "cvss": 9.1, "severity": "CRITICAL", "patch_available": True, "patch_version": "3.8.1", "description": "HTTP dependency downgrade attack — Maven allows HTTP repos by default, enabling MITM attacks.", "exploitability": "MEDIUM", "mitre": "T1557"},
    {"cve_id": "CVE-2018-14718", "library": "jackson-databind",    "affected_versions": ["2.6.0","2.6.1","2.6.2","2.6.3","2.6.4","2.6.5","2.6.6","2.6.7","2.7.0","2.8.0","2.9.0","2.9.7"],  "cvss": 9.8, "severity": "CRITICAL", "patch_available": True, "patch_version": "2.9.8", "description": "Deserialization RCE via slf4j-ext gadget in jackson-databind.", "exploitability": "HIGH", "mitre": "T1190"},
    {"cve_id": "CVE-2023-24998", "library": "commons-fileupload",  "affected_versions": ["1.3","1.3.1","1.3.2","1.3.3","1.4"],                                                                "cvss": 7.5, "severity": "HIGH", "patch_available": True, "patch_version": "1.5", "description": "FileUpload DoS via malicious multipart request — CPU exhaustion.", "exploitability": "LOW", "mitre": "T1499"},
]

# Add 170 more generic CVEs
libraries_extra = [
    ("requests","2.18.0","CVE-2018-18074","SSRF via auto-redirect following — allows request forgery.",6.1,"MEDIUM"),
    ("requests","2.19.0","CVE-2019-6446","Redirect following leaks Authorization header to third-party hosts.",5.0,"MEDIUM"),
    ("pillow","8.1.2","CVE-2021-23437","Uncontrolled resource consumption via crafted image leading to DoS.",7.5,"HIGH"),
    ("pillow","8.2.0","CVE-2021-34552","Buffer overflow in FLI decoding — potential RCE.",9.8,"CRITICAL"),
    ("cryptography","3.3.0","CVE-2020-36242","Bleichenbacher timing attack in RSA decrypt — key recovery possible.",6.5,"MEDIUM"),
    ("pyyaml","5.3","CVE-2020-1747","yaml.load with Loader=None executes arbitrary Python code.",9.8,"CRITICAL"),
    ("pyyaml","5.4","CVE-2020-14343","Incomplete fix for CVE-2020-1747 — still allows code execution.",9.8,"CRITICAL"),
    ("jinja2","2.11.0","CVE-2019-10906","Sandbox escape via str.format_map — arbitrary code execution.",8.8,"HIGH"),
    ("jinja2","3.0.0","CVE-2020-28493","ReDoS in jinja2.lexer — crafted template causes CPU exhaustion.",5.0,"MEDIUM"),
    ("urllib3","1.25.2","CVE-2019-11324","CRLF injection in HTTP request headers — header smuggling.",7.5,"HIGH"),
    ("urllib3","1.26.4","CVE-2021-33503","ReDoS via malformed URL — CPU exhaustion on URL parse.",7.5,"HIGH"),
    ("paramiko","2.7.1","CVE-2022-24302","Race condition creates private key files with world-readable permissions.",5.1,"MEDIUM"),
    ("celery","4.4.0","CVE-2021-23727","Untrusted task execution via Kombu — deserialization attack.",9.8,"CRITICAL"),
    ("sqlalchemy","1.3.0","CVE-2019-7164","SQL injection via column names when using ORM filter().",9.8,"CRITICAL"),
    ("lxml","4.6.0","CVE-2021-28957","XSS via HTML5 cleanup processing in lxml.html.clean.",6.1,"MEDIUM"),
    ("bcrypt","3.1.0","CVE-2020-6802","bcrypt hash validation bypass when using NULL bytes in passwords.",6.5,"MEDIUM"),
    ("flask","1.0.0","CVE-2018-1000656","Werkzeug debugger bypass — same impact as CVE-2018-1000656.",7.5,"HIGH"),
    ("django","3.2.0","CVE-2021-33203","Directory traversal via path when using FileSystemStorage.",4.9,"MEDIUM"),
    ("django","3.2.5","CVE-2021-35042","SQL injection via unsanitized QuerySet.order_by().",9.8,"CRITICAL"),
    ("redis-py","3.5.0","CVE-2023-28858","Unintended data disclosure across async Redis connections.",4.3,"MEDIUM"),
]

cve_counter = 31
for lib, ver, cve_id, desc, cvss, sev in libraries_extra:
    patch_v = ver.rsplit(".", 1)
    patch_ver = f"{patch_v[0]}.{int(patch_v[1])+1}" if len(patch_v) > 1 and patch_v[1].isdigit() else ver + "-patched"
    exploit = "HIGH" if cvss >= 9.0 else ("MEDIUM" if cvss >= 6.0 else "LOW")
    vuln_db.append({
        "cve_id": cve_id, "library": lib, "affected_versions": [ver],
        "cvss": cvss, "severity": sev, "patch_available": True, "patch_version": patch_ver,
        "description": desc, "exploitability": exploit, "mitre": "T1190" if cvss >= 7.5 else "T1499"
    })
    cve_counter += 1

# Pad to 200 with generic CVEs
severity_pool = [("CRITICAL",9.8),("CRITICAL",9.1),("HIGH",8.0),("HIGH",7.5),("MEDIUM",6.1),("MEDIUM",5.0),("LOW",3.5)]
lib_pool = ["hibernate-core","netty","tomcat-embed-core","guava","protobuf-java","h2","hsqldb","slf4j-api","gson","httpclient","xmlsec","bc-prov","xstream","velocity","freemarker"]
while len(vuln_db) < 200:
    idx = len(vuln_db)
    lib = lib_pool[idx % len(lib_pool)]
    sev, cvss = severity_pool[idx % len(severity_pool)]
    ver = f"1.{idx % 10}.{idx % 5}"
    patch = f"1.{idx % 10}.{(idx % 5)+1}"
    exploit = "HIGH" if cvss >= 9.0 else ("MEDIUM" if cvss >= 6.0 else "LOW")
    vuln_db.append({
        "cve_id": f"CVE-20{20+idx%5}-{10000+idx:05d}", "library": lib,
        "affected_versions": [ver, f"1.{(idx+1)%10}.0"],
        "cvss": cvss, "severity": sev, "patch_available": idx % 3 != 0,
        "patch_version": patch, "description": f"Security vulnerability in {lib} v{ver}.",
        "exploitability": exploit, "mitre": "T1190"
    })

with open("sample_data/vulnerability_db.json", "w") as f:
    json.dump(vuln_db, f, indent=2)
print(f"✅ vulnerability_db.json created ({len(vuln_db)} CVEs)")

# ─────────────────────────────────────────────
# 3. LICENSE RULES
# ─────────────────────────────────────────────
license_rules = [
    {"license": "MIT",           "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Most permissive license. No restrictions on use."},
    {"license": "Apache-2.0",    "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Permissive. Requires attribution and NOTICE file preservation."},
    {"license": "BSD-2-Clause",  "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Simple and permissive."},
    {"license": "BSD-3-Clause",  "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Adds non-endorsement clause."},
    {"license": "ISC",           "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Functionally equivalent to MIT."},
    {"license": "PSF-2.0",       "category": "permissive",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Python Software Foundation license — permissive."},
    {"license": "LGPL-2.1",      "category": "weak-copyleft","proprietary_compatible": True,  "copyleft": True,  "risk_level": "MEDIUM",   "commercial_use": True,  "distribution_required": True,  "notes": "OK for linking but modifications must be open-sourced. Dynamic linking only in proprietary."},
    {"license": "LGPL-3.0",      "category": "weak-copyleft","proprietary_compatible": True,  "copyleft": True,  "risk_level": "MEDIUM",   "commercial_use": True,  "distribution_required": True,  "notes": "Same as LGPL-2.1 but stronger copyleft. Dynamic linking OK."},
    {"license": "MPL-2.0",       "category": "weak-copyleft","proprietary_compatible": True,  "copyleft": True,  "risk_level": "MEDIUM",   "commercial_use": True,  "distribution_required": True,  "notes": "File-level copyleft. Modifications to MPL files must be shared."},
    {"license": "GPL-2.0",       "category": "strong-copyleft","proprietary_compatible": False,"copyleft": True, "risk_level": "CRITICAL", "commercial_use": False, "distribution_required": True,  "notes": "VIRAL: Any software using GPL-2.0 code must also be GPL. Incompatible with proprietary."},
    {"license": "GPL-3.0",       "category": "strong-copyleft","proprietary_compatible": False,"copyleft": True, "risk_level": "CRITICAL", "commercial_use": False, "distribution_required": True,  "notes": "VIRAL: Strongest copyleft. Adds anti-tivoization clause. Incompatible with proprietary."},
    {"license": "AGPL-3.0",      "category": "strong-copyleft","proprietary_compatible": False,"copyleft": True, "risk_level": "CRITICAL", "commercial_use": False, "distribution_required": True,  "notes": "VIRAL: GPL-3.0 + network use triggers copyleft. Most restrictive open-source license."},
    {"license": "CC-BY-SA-4.0",  "category": "creative-commons","proprietary_compatible": False,"copyleft": True,"risk_level": "HIGH",    "commercial_use": True,  "distribution_required": True,  "notes": "Share-alike — derivatives must use same license. Not intended for software."},
    {"license": "UNLICENSED",    "category": "unknown",      "proprietary_compatible": False, "copyleft": False, "risk_level": "HIGH",     "commercial_use": False, "distribution_required": False, "notes": "No license specified — all rights reserved by default. Legal risk to use commercially."},
    {"license": "COMMERCIAL",    "category": "commercial",   "proprietary_compatible": True,  "copyleft": False, "risk_level": "LOW",      "commercial_use": True,  "distribution_required": False, "notes": "Explicit commercial license purchased. No open-source obligations."},
]
with open("sample_data/license_rules.json", "w") as f:
    json.dump(license_rules, f, indent=2)
print("✅ license_rules.json created")

# ─────────────────────────────────────────────
# 4. SBOM DEPENDENCIES (500 rows)
# ─────────────────────────────────────────────

now = datetime(2026, 7, 11)

def random_date(years_ago_min, years_ago_max):
    days = random.randint(int(years_ago_min * 365), int(years_ago_max * 365))
    return (now - timedelta(days=days)).strftime("%Y-%m-%d")

# Direct vulnerable libraries per app (the key scenarios)
app_direct_vulns = {
    "APP-001": [
        ("log4j-core",         "2.14.1", "Apache-2.0", "direct", None, "CVE-2021-44228"),
        ("jackson-databind",   "2.9.5",  "Apache-2.0", "direct", None, "CVE-2020-8840"),
        ("commons-collections","3.2.1",  "Apache-2.0", "direct", None, "CVE-2015-6420"),
    ],
    "APP-003": [
        ("spring-webmvc",      "5.3.10", "Apache-2.0", "direct", None, "CVE-2022-22965"),
        ("snakeyaml",          "1.29",   "Apache-2.0", "direct", None, "CVE-2022-1471"),
    ],
    "APP-004": [
        ("commons-text",       "1.9",    "Apache-2.0", "direct", None, "CVE-2022-42889"),
    ],
    "APP-010": [
        ("struts2-core",       "2.3.28", "Apache-2.0", "direct", None, "CVE-2017-5638"),
        ("commons-collections","3.2.1",  "Apache-2.0", "direct", None, "CVE-2017-15708"),
    ],
    "APP-002": [
        ("requests",           "2.18.0", "Apache-2.0", "direct", None, "CVE-2018-18074"),
        ("pillow",             "8.1.2",  "MIT",        "direct", None, "CVE-2021-23437"),
    ],
    "APP-005": [
        ("openssl",            "1.1.1",  "OpenSSL",    "direct", None, "CVE-2022-0778"),
        ("pyyaml",             "5.4",    "MIT",        "direct", None, "CVE-2020-14343"),
    ],
}

# License-conflicting libraries
app_license_conflicts = {
    "APP-003": [
        ("mysql-connector",    "8.0.28", "GPL-2.0",    "direct", None),
        ("gpl-math-lib",       "2.1.0",  "GPL-3.0",    "direct", None),
    ],
    "APP-007": [
        ("reportlab",          "3.6.12", "BSD-3-Clause","direct", None),
        ("gpl-chart-lib",      "1.4.0",  "GPL-2.0",    "direct", None),
    ],
    "APP-008": [
        ("git-python",         "3.1.30", "BSD-3-Clause","direct", None),
        ("agpl-dev-tool",      "4.2.0",  "AGPL-3.0",   "direct", None),
    ],
}

# Unmaintained libraries (last update > 2 years ago)
unmaintained_libs = [
    ("log4j-1.x",              "1.2.17", "Apache-2.0"),
    ("commons-beanutils",      "1.9.3",  "Apache-2.0"),
    ("dom4j",                  "1.6.1",  "BSD-3-Clause"),
    ("xalan",                  "2.7.2",  "Apache-2.0"),
    ("xerces",                 "2.11.0", "Apache-2.0"),
    ("jaxen",                  "1.2.0",  "BSD-3-Clause"),
    ("asm",                    "3.3.1",  "BSD-3-Clause"),
    ("antlr",                  "3.5.2",  "BSD-3-Clause"),
    ("itext",                  "2.1.7",  "UNLICENSED"),
    ("struts1",                "1.3.10", "Apache-2.0"),
]

# Transitive dependencies (A -> B -> CVE)
transitive_chains = {
    "APP-001": [("slf4j-api", "1.7.36", "MIT", "log4j-core"),
                ("logback-classic", "1.2.7", "LGPL-2.1", "slf4j-api")],
    "APP-002": [("urllib3", "1.25.2", "MIT", None),
                ("certifi", "2020.12.5", "MPL-2.0", None)],
    "APP-004": [("commons-lang3", "3.11", "Apache-2.0", "commons-text"),
                ("snakeyaml", "1.29", "Apache-2.0", "commons-lang3")],
    "APP-005": [("bcrypt", "3.1.0", "Apache-2.0", None)],
    "APP-010": [("ognl", "3.0.19", "Apache-2.0", "struts2-core"),
                ("freemarker", "2.3.20", "Apache-2.0", "struts2-core")],
}

# Clean / benign libraries (shared pool)
clean_libs = [
    ("spring-core",   "5.3.20", "Apache-2.0", 0.2),
    ("spring-beans",  "5.3.20", "Apache-2.0", 0.2),
    ("spring-context","5.3.20", "Apache-2.0", 0.2),
    ("spring-boot",   "2.7.0",  "Apache-2.0", 0.2),
    ("hibernate-core","5.6.10", "LGPL-2.1",   0.3),
    ("guava",         "31.1",   "Apache-2.0", 0.2),
    ("slf4j-api",     "1.7.36", "MIT",        0.1),
    ("gson",          "2.9.1",  "Apache-2.0", 0.1),
    ("httpclient",    "4.5.13", "Apache-2.0", 0.2),
    ("junit",         "5.8.2",  "EPL-2.0",    0.1),
    ("mockito-core",  "4.5.1",  "MIT",        0.1),
    ("lombok",        "1.18.24","MIT",        0.1),
    ("mapstruct",     "1.5.2",  "Apache-2.0", 0.1),
    ("netty-all",     "4.1.79", "Apache-2.0", 0.2),
    ("protobuf-java", "3.21.4", "BSD-3-Clause",0.1),
    ("grpc-core",     "1.48.0", "Apache-2.0", 0.1),
    ("aws-sdk-java",  "1.12.261","Apache-2.0",0.2),
    ("azure-identity","1.5.3",  "MIT",        0.1),
    ("postgresql",    "42.4.0", "BSD-2-Clause",0.1),
    ("mysql-connector","8.0.30","GPL-2.0",    0.1),
    ("h2",            "2.1.214","EPL-1.0",    0.1),
    ("flyway-core",   "9.1.2",  "Apache-2.0", 0.1),
    ("liquibase-core","4.15.0", "Apache-2.0", 0.1),
    ("kafka-clients", "3.2.1",  "Apache-2.0", 0.2),
    ("redis-clients", "3.8.0",  "MIT",        0.1),
    ("micrometer-core","1.9.2", "Apache-2.0", 0.1),
    ("zipkin-reporter","2.16.3","Apache-2.0", 0.1),
    ("opentelemetry-api","1.17.0","Apache-2.0",0.1),
    ("resilience4j",  "1.7.1",  "Apache-2.0", 0.1),
    ("feign-core",    "11.8",   "Apache-2.0", 0.1),
    ("numpy",         "1.23.1", "BSD-3-Clause",0.2),
    ("pandas",        "1.4.3",  "BSD-3-Clause",0.2),
    ("scipy",         "1.9.1",  "BSD-3-Clause",0.1),
    ("matplotlib",    "3.5.3",  "PSF-2.0",   0.1),
    ("scikit-learn",  "1.1.2",  "BSD-3-Clause",0.1),
    ("flask",         "2.2.2",  "BSD-3-Clause",0.2),
    ("fastapi",       "0.85.0", "MIT",        0.2),
    ("pydantic",      "1.10.2", "MIT",        0.1),
    ("sqlalchemy",    "1.4.40", "MIT",        0.2),
    ("alembic",       "1.8.1",  "MIT",        0.1),
    ("celery",        "5.2.7",  "BSD-3-Clause",0.1),
    ("boto3",         "1.24.59","Apache-2.0", 0.1),
    ("click",         "8.1.3",  "BSD-3-Clause",0.1),
    ("pytest",        "7.1.3",  "MIT",        0.1),
    ("black",         "22.8.0", "MIT",        0.1),
    ("isort",         "5.10.1", "MIT",        0.1),
    ("mypy",          "0.971",  "MIT",        0.1),
    ("ruff",          "0.0.78", "MIT",        0.1),
    ("rich",          "12.5.1", "MIT",        0.1),
    ("typer",         "0.6.1",  "MIT",        0.1),
]

rows = []
labels = []

dep_id_counter = 1

def add_dep(app_id, lib_name, version, license_t, dep_type, parent_lib, last_updated, depth,
            is_vuln, cve_id, is_license_issue, is_unmaintained, label_risk, label_severity, label_explanation):
    global dep_id_counter
    rows.append({
        "dep_id": f"DEP-{dep_id_counter:04d}",
        "app_id": app_id,
        "library_name": lib_name,
        "version": version,
        "license_type": license_t,
        "dependency_type": dep_type,
        "parent_library": parent_lib or "",
        "depth": depth,
        "last_updated": last_updated,
    })
    labels.append({
        "dep_id": f"DEP-{dep_id_counter:04d}",
        "app_id": app_id,
        "library_name": lib_name,
        "is_vulnerable": is_vuln,
        "cve_id": cve_id or "",
        "is_license_issue": is_license_issue,
        "is_unmaintained": is_unmaintained,
        "risk_type": label_risk,
        "severity": label_severity,
        "explanation": label_explanation,
    })
    dep_id_counter += 1

# Process each app
for app in applications:
    app_id = app["app_id"]
    app_type = app["type"]
    added_libs = set()

    # Add known vulnerable direct deps
    for lib, ver, lic, dep_type, parent, cve in app_direct_vulns.get(app_id, []):
        added_libs.add(lib)
        cve_entry = next((v for v in vuln_db if v["cve_id"] == cve), None)
        sev = cve_entry["severity"] if cve_entry else "HIGH"
        add_dep(app_id, lib, ver, lic, "direct", None,
                random_date(0.5, 1.5), 1,
                True, cve, False, False,
                "VULNERABLE", sev,
                f"{lib} v{ver} has {cve} (CVSS {cve_entry['cvss'] if cve_entry else '?'}). {cve_entry['description'] if cve_entry else ''}")

    # Add transitive chains
    for lib, ver, lic, parent in transitive_chains.get(app_id, []):
        if lib in added_libs:
            continue
        added_libs.add(lib)
        # Check if this transitive dep has a CVE
        vuln_match = next((v for v in vuln_db if v["library"] == lib and ver in v.get("affected_versions", [])), None)
        is_v = vuln_match is not None
        cve_id = vuln_match["cve_id"] if is_v else None
        sev = vuln_match["severity"] if is_v else "CLEAN"
        risk = "TRANSITIVE_VULNERABLE" if is_v else "CLEAN"
        expl = f"{lib} is a transitive dep of {parent}. {'Has ' + cve_id + '.' if is_v else 'No known CVEs.'}"
        add_dep(app_id, lib, ver, lic, "transitive", parent,
                random_date(0.5, 2), 2,
                is_v, cve_id, False, False,
                risk, sev if is_v else "NONE", expl)

    # Add license conflicts
    for lib, ver, lic, dep_type, parent in app_license_conflicts.get(app_id, []):
        if lib in added_libs:
            continue
        added_libs.add(lib)
        is_conflict = app_type == "proprietary" and lic in ["GPL-2.0","GPL-3.0","AGPL-3.0"]
        add_dep(app_id, lib, ver, lic, dep_type, parent,
                random_date(0.3, 1.5), 1 if dep_type == "direct" else 2,
                False, None, is_conflict, False,
                "LICENSE_CONFLICT" if is_conflict else "CLEAN",
                "CRITICAL" if is_conflict else "NONE",
                f"{lib} uses {lic} license. Incompatible with proprietary codebase — viral copyleft applies." if is_conflict else "No issue.")

    # Sprinkle some unmaintained libs in certain apps
    unmaint_apps = ["APP-010", "APP-003", "APP-006", "APP-007"]
    if app_id in unmaint_apps:
        for lib, ver, lic in unmaintained_libs[:3]:
            if lib in added_libs:
                continue
            added_libs.add(lib)
            last_upd = random_date(2.5, 5)
            add_dep(app_id, lib, ver, lic, "direct", None,
                    last_upd, 1,
                    False, None, False, True,
                    "UNMAINTAINED", "MEDIUM",
                    f"{lib} v{ver} was last updated {last_upd}. No active maintainer. Security patches unlikely.")

    # Fill rest with clean libraries
    target = 50
    current = sum(1 for r in rows if r["app_id"] == app_id)
    clean_pool_shuffled = clean_libs.copy()
    random.shuffle(clean_pool_shuffled)
    for lib, ver, lic, _ in clean_pool_shuffled:
        if current >= target:
            break
        if lib in added_libs:
            continue
        added_libs.add(lib)
        last_upd = random_date(0.1, 1.0)
        add_dep(app_id, lib, ver, lic, "direct", None,
                last_upd, 1,
                False, None, False, False,
                "CLEAN", "NONE",
                f"{lib} v{ver} — no known vulnerabilities, compatible license, actively maintained.")
        current += 1

print(f"✅ Generated {len(rows)} dependency rows")

# Write CSV
fieldnames = ["dep_id","app_id","library_name","version","license_type","dependency_type","parent_library","depth","last_updated"]
with open("sample_data/sbom_dependencies.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
print("✅ sbom_dependencies.csv created")

# Write labels
label_fields = ["dep_id","app_id","library_name","is_vulnerable","cve_id","is_license_issue","is_unmaintained","risk_type","severity","explanation"]
with open("sample_data/dependency_labels.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=label_fields)
    w.writeheader()
    w.writerows(labels)
print("✅ dependency_labels.csv created")

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
total = len(labels)
vuln_count = sum(1 for l in labels if l["is_vulnerable"])
license_count = sum(1 for l in labels if l["is_license_issue"])
unmaint_count = sum(1 for l in labels if l["is_unmaintained"])
transitive_count = sum(1 for l in labels if l["risk_type"] == "TRANSITIVE_VULNERABLE")
clean_count = sum(1 for l in labels if l["risk_type"] == "CLEAN")

print(f"\n📊 Dataset Summary ({total} total dependencies):")
print(f"   Vulnerable (direct CVE): {vuln_count} ({100*vuln_count/total:.1f}%)")
print(f"   License conflicts:       {license_count} ({100*license_count/total:.1f}%)")
print(f"   Unmaintained:            {unmaint_count} ({100*unmaint_count/total:.1f}%)")
print(f"   Transitive vulnerable:   {transitive_count} ({100*transitive_count/total:.1f}%)")
print(f"   Clean:                   {clean_count} ({100*clean_count/total:.1f}%)")
print("\n✅ All sample data files generated successfully!")
