
// Pass data to JS
const ALL_SCORES = [{"app_id": "APP-003", "app_name": "HRPortal", "compliance": [{"control": "A10:2021-Server-Side Request Forgery", "detail": "Critical/High CVE (CVE-2022-1471) violates A10:2021-Server-Side Request Forgery.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2022-1471) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Vulnerability Reporting", "detail": "Critical/High CVE (CVE-2022-1471) violates OpenSSF: Vulnerability Reporting.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "2 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}, {"control": "Scorecard / Maintained", "detail": "3 unmaintained dependencies \u2014 security patches unlikely.", "framework": "OpenSSF", "name": "Project Maintenance Risk", "status": "WARN"}, {"control": "SC-2", "detail": "Unmaintained third-party dependencies indicate supplier risk.", "framework": "NIST CSF", "name": "Supplier Assessment", "status": "WARN"}], "critical_cves": 2, "criticality": "HIGH", "cve_summary": [{"contribution": 9.8, "cve_id": "CVE-2022-1471", "cvss": 9.8, "depth": 1, "library": "snakeyaml", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 9.8, "cve_id": "CVE-2022-22965", "cvss": 9.8, "depth": 1, "library": "spring-webmvc", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 7.5, "cve_id": "CVE-2022-25857", "cvss": 7.5, "depth": 1, "library": "snakeyaml", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Employee HR management and payroll system", "explain_risk": ["Technical Risk Components: Vulnerabilities (73.0 * 60%) + License (79.8 * 25%) + Maintenance (93.6 * 15%) = 77.8", "Business Impact Multipliers: Criticality HIGH (1.25x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 77.8 * 1.25 * 1.2 * 1.25 = 145.8 (Normalized to 99.3/100)", "Security Health Deduction: Technical Risk (-77.8) + Deep Dependency Penalty (-0.8) + Maintenance Penalty (-6) = 15.5/100"], "health_score": 15.5, "high_cves": 1, "internet_exposure": true, "lic_score": 79.8, "license_conflicts": 2, "maint_score": 93.6, "owner": "carol@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 99.3, "team": "HR-IT", "technical_risk": 77.8, "total_cves": 4, "unmaintained_libs": 3, "vuln_score": 73.0}, {"app_id": "APP-010", "app_name": "LegacyBillingApp", "compliance": [{"control": "A09:2021-Security Logging and Monitoring Failures", "detail": "Critical/High CVE (CVE-2017-5638) violates A09:2021-Security Logging and Monitoring Failures.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SC-28", "detail": "Critical/High CVE (CVE-2017-5638) violates NIST SP 800-53: SC-28.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Vulnerability Reporting", "detail": "Critical/High CVE (CVE-2017-5638) violates OpenSSF: Vulnerability Reporting.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "1 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}, {"control": "Scorecard / Maintained", "detail": "3 unmaintained dependencies \u2014 security patches unlikely.", "framework": "OpenSSF", "name": "Project Maintenance Risk", "status": "WARN"}, {"control": "SC-2", "detail": "Unmaintained third-party dependencies indicate supplier risk.", "framework": "NIST CSF", "name": "Supplier Assessment", "status": "WARN"}], "critical_cves": 2, "criticality": "HIGH", "cve_summary": [{"contribution": 10.0, "cve_id": "CVE-2017-5638", "cvss": 10.0, "depth": 1, "library": "struts2-core", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 9.8, "cve_id": "CVE-2017-15708", "cvss": 9.8, "depth": 1, "library": "commons-collections", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 7.5, "cve_id": "CVE-2015-6420", "cvss": 7.5, "depth": 1, "library": "commons-collections", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Legacy billing system \u2014 migration pending Q4", "explain_risk": ["Technical Risk Components: Vulnerabilities (73.2 * 60%) + License (55.1 * 25%) + Maintenance (93.6 * 15%) = 71.7", "Business Impact Multipliers: Criticality HIGH (1.25x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 71.7 * 1.25 * 1.2 * 1.25 = 134.5 (Normalized to 98.7/100)", "Security Health Deduction: Technical Risk (-71.7) + Deep Dependency Penalty (-0.8) + Maintenance Penalty (-6) = 21.5/100"], "health_score": 21.5, "high_cves": 1, "internet_exposure": true, "lic_score": 55.1, "license_conflicts": 1, "maint_score": 93.6, "owner": "john@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 98.7, "team": "Finance", "technical_risk": 71.7, "total_cves": 4, "unmaintained_libs": 3, "vuln_score": 73.2}, {"app_id": "APP-005", "app_name": "AuthService", "compliance": [{"control": "A06:2021-Vulnerable and Outdated Components", "detail": "Critical/High CVE (CVE-2020-14343) violates A06:2021-Vulnerable and Outdated Components.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SC-28", "detail": "Critical/High CVE (CVE-2020-14343) violates NIST SP 800-53: SC-28.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Security Policies", "detail": "Critical/High CVE (CVE-2020-14343) violates OpenSSF: Security Policies.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "1 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}], "critical_cves": 1, "criticality": "CRITICAL", "cve_summary": [{"contribution": 9.8, "cve_id": "CVE-2020-14343", "cvss": 9.8, "depth": 1, "library": "pyyaml", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 7.5, "cve_id": "CVE-2022-0778", "cvss": 7.5, "depth": 1, "library": "openssl", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}, {"contribution": 6.5, "cve_id": "CVE-2020-6802", "cvss": 6.5, "depth": 1, "library": "bcrypt", "patch_available": true, "severity": "MEDIUM"}, {"contribution": 5.9, "cve_id": "CVE-2021-3449", "cvss": 5.9, "depth": 1, "library": "openssl", "patch_available": true, "severity": "MEDIUM"}], "description": "OAuth2/OIDC identity and access management service", "explain_risk": ["Technical Risk Components: Vulnerabilities (75.6 * 60%) + License (55.1 * 25%) + Maintenance (0.0 * 15%) = 59.2", "Business Impact Multipliers: Criticality CRITICAL (1.5x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 59.2 * 1.5 * 1.2 * 1.25 = 133.1 (Normalized to 98.6/100)", "Security Health Deduction: Technical Risk (-59.2) + Deep Dependency Penalty (-0.6) + Maintenance Penalty (-0) = 40.2/100"], "health_score": 40.2, "high_cves": 1, "internet_exposure": true, "lic_score": 55.1, "license_conflicts": 1, "maint_score": 0.0, "owner": "eve@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 98.6, "team": "Security", "technical_risk": 59.2, "total_cves": 5, "unmaintained_libs": 0, "vuln_score": 75.6}, {"app_id": "APP-001", "app_name": "PaymentGateway", "compliance": [{"control": "A10:2021-Server-Side Request Forgery", "detail": "Critical/High CVE (CVE-2017-15708) violates A10:2021-Server-Side Request Forgery.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SI-2", "detail": "Critical/High CVE (CVE-2017-15708) violates NIST SP 800-53: SI-2.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Vulnerability Reporting", "detail": "Critical/High CVE (CVE-2017-15708) violates OpenSSF: Vulnerability Reporting.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "1 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}], "critical_cves": 2, "criticality": "CRITICAL", "cve_summary": [{"contribution": 9.8, "cve_id": "CVE-2017-15708", "cvss": 9.8, "depth": 1, "library": "commons-collections", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 9.8, "cve_id": "CVE-2020-8840", "cvss": 9.8, "depth": 1, "library": "jackson-databind", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 7.5, "cve_id": "CVE-2015-6420", "cvss": 7.5, "depth": 1, "library": "commons-collections", "patch_available": true, "severity": "HIGH"}, {"contribution": 4.62, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 3, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Handles all card payment processing and PCI-DSS scope", "explain_risk": ["Technical Risk Components: Vulnerabilities (71.9 * 60%) + License (55.1 * 25%) + Maintenance (0.0 * 15%) = 56.9", "Business Impact Multipliers: Criticality CRITICAL (1.5x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 56.9 * 1.5 * 1.2 * 1.25 = 128.0 (Normalized to 98.2/100)", "Security Health Deduction: Technical Risk (-56.9) + Deep Dependency Penalty (-1.5) + Maintenance Penalty (-0) = 41.6/100"], "health_score": 41.6, "high_cves": 1, "internet_exposure": true, "lic_score": 55.1, "license_conflicts": 1, "maint_score": 0.0, "owner": "alice@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 98.2, "team": "FinTech", "technical_risk": 56.9, "total_cves": 4, "unmaintained_libs": 0, "vuln_score": 71.9}, {"app_id": "APP-004", "app_name": "DataWarehouse", "compliance": [{"control": "A10:2021-Server-Side Request Forgery", "detail": "Critical/High CVE (CVE-2022-1471) violates A10:2021-Server-Side Request Forgery.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2022-1471) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Vulnerability Reporting", "detail": "Critical/High CVE (CVE-2022-1471) violates OpenSSF: Vulnerability Reporting.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "1 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}], "critical_cves": 2, "criticality": "HIGH", "cve_summary": [{"contribution": 6.86, "cve_id": "CVE-2022-1471", "cvss": 9.8, "depth": 3, "library": "snakeyaml", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 9.8, "cve_id": "CVE-2022-42889", "cvss": 9.8, "depth": 1, "library": "commons-text", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 5.25, "cve_id": "CVE-2022-25857", "cvss": 7.5, "depth": 3, "library": "snakeyaml", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Central analytics and reporting data lake", "explain_risk": ["Technical Risk Components: Vulnerabilities (66.7 * 60%) + License (55.1 * 25%) + Maintenance (0.0 * 15%) = 53.8", "Business Impact Multipliers: Criticality HIGH (1.25x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 53.8 * 1.25 * 1.2 * 1.25 = 100.9 (Normalized to 93.0/100)", "Security Health Deduction: Technical Risk (-53.8) + Deep Dependency Penalty (-3.8) + Maintenance Penalty (-0) = 42.4/100"], "health_score": 42.4, "high_cves": 1, "internet_exposure": true, "lic_score": 55.1, "license_conflicts": 1, "maint_score": 0.0, "owner": "dave@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 93.0, "team": "Analytics", "technical_risk": 53.8, "total_cves": 4, "unmaintained_libs": 0, "vuln_score": 66.7}, {"app_id": "APP-002", "app_name": "CustomerPortal", "compliance": [{"control": "A09:2021-Security Logging and Monitoring Failures", "detail": "Critical/High CVE (CVE-2021-23437) violates A09:2021-Security Logging and Monitoring Failures.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2021-23437) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Dependency Management", "detail": "Critical/High CVE (CVE-2021-23437) violates OpenSSF: Dependency Management.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "1 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}], "critical_cves": 0, "criticality": "HIGH", "cve_summary": [{"contribution": 7.5, "cve_id": "CVE-2021-23437", "cvss": 7.5, "depth": 1, "library": "pillow", "patch_available": true, "severity": "HIGH"}, {"contribution": 7.5, "cve_id": "CVE-2019-11324", "cvss": 7.5, "depth": 1, "library": "urllib3", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}, {"contribution": 6.1, "cve_id": "CVE-2018-18074", "cvss": 6.1, "depth": 1, "library": "requests", "patch_available": true, "severity": "MEDIUM"}], "description": "Customer-facing self-service web portal", "explain_risk": ["Technical Risk Components: Vulnerabilities (65.6 * 60%) + License (55.1 * 25%) + Maintenance (0.0 * 15%) = 53.2", "Business Impact Multipliers: Criticality HIGH (1.25x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 53.2 * 1.25 * 1.2 * 1.25 = 99.7 (Normalized to 92.5/100)", "Security Health Deduction: Technical Risk (-53.2) + Deep Dependency Penalty (-0.8) + Maintenance Penalty (-0) = 46.1/100"], "health_score": 46.1, "high_cves": 2, "internet_exposure": true, "lic_score": 55.1, "license_conflicts": 1, "maint_score": 0.0, "owner": "bob@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 92.5, "team": "Product", "technical_risk": 53.2, "total_cves": 4, "unmaintained_libs": 0, "vuln_score": 65.6}, {"app_id": "APP-007", "app_name": "ReportingEngine", "compliance": [{"control": "A03:2021-Injection", "detail": "Critical/High CVE (CVE-2021-42550) violates A03:2021-Injection.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2021-42550) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Dependency Management", "detail": "Critical/High CVE (CVE-2021-42550) violates OpenSSF: Dependency Management.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "2 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}, {"control": "Scorecard / Maintained", "detail": "3 unmaintained dependencies \u2014 security patches unlikely.", "framework": "OpenSSF", "name": "Project Maintenance Risk", "status": "WARN"}, {"control": "SC-2", "detail": "Unmaintained third-party dependencies indicate supplier risk.", "framework": "NIST CSF", "name": "Supplier Assessment", "status": "WARN"}], "critical_cves": 0, "criticality": "MEDIUM", "cve_summary": [{"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Scheduled report generation and export service", "explain_risk": ["Technical Risk Components: Vulnerabilities (20.1 * 60%) + License (79.8 * 25%) + Maintenance (93.6 * 15%) = 46.0", "Business Impact Multipliers: Criticality MEDIUM (1.0x) * Internet Facing (1.0x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 46.0 * 1.0 * 1.0 * 1.25 = 57.6 (Normalized to 57.6/100)", "Security Health Deduction: Technical Risk (-46.0) + Deep Dependency Penalty (-3.0) + Maintenance Penalty (-6) = 45.0/100"], "health_score": 45.0, "high_cves": 0, "internet_exposure": false, "lic_score": 79.8, "license_conflicts": 2, "maint_score": 93.6, "owner": "grace@corp.com", "risk_band": "HIGH", "risk_color": "#ff8c00", "risk_score": 57.6, "team": "Analytics", "technical_risk": 46.0, "total_cves": 1, "unmaintained_libs": 3, "vuln_score": 20.1}, {"app_id": "APP-006", "app_name": "EmailService", "compliance": [{"control": "A03:2021-Injection", "detail": "Critical/High CVE (CVE-2021-42550) violates A03:2021-Injection.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2021-42550) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Dependency Management", "detail": "Critical/High CVE (CVE-2021-42550) violates OpenSSF: Dependency Management.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "Scorecard / Maintained", "detail": "3 unmaintained dependencies \u2014 security patches unlikely.", "framework": "OpenSSF", "name": "Project Maintenance Risk", "status": "WARN"}, {"control": "SC-2", "detail": "Unmaintained third-party dependencies indicate supplier risk.", "framework": "NIST CSF", "name": "Supplier Assessment", "status": "WARN"}], "critical_cves": 0, "criticality": "MEDIUM", "cve_summary": [{"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Transactional and marketing email delivery service", "explain_risk": ["Technical Risk Components: Vulnerabilities (20.1 * 60%) + License (0.0 * 25%) + Maintenance (93.6 * 15%) = 26.1", "Business Impact Multipliers: Criticality MEDIUM (1.0x) * Internet Facing (1.0x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 26.1 * 1.0 * 1.0 * 1.25 = 32.6 (Normalized to 32.6/100)", "Security Health Deduction: Technical Risk (-26.1) + Deep Dependency Penalty (-3.0) + Maintenance Penalty (-6) = 64.9/100"], "health_score": 64.9, "high_cves": 0, "internet_exposure": false, "lic_score": 0.0, "license_conflicts": 0, "maint_score": 93.6, "owner": "frank@corp.com", "risk_band": "MEDIUM", "risk_color": "#ffd700", "risk_score": 32.6, "team": "Platform", "technical_risk": 26.1, "total_cves": 1, "unmaintained_libs": 3, "vuln_score": 20.1}, {"app_id": "APP-008", "app_name": "DevToolkit", "compliance": [{"control": "A03:2021-Injection", "detail": "Critical/High CVE (CVE-2021-42550) violates A03:2021-Injection.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2021-42550) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Dependency Management", "detail": "Critical/High CVE (CVE-2021-42550) violates OpenSSF: Dependency Management.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}], "critical_cves": 0, "criticality": "LOW", "cve_summary": [{"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Internal developer utilities and CI/CD helpers", "explain_risk": ["Technical Risk Components: Vulnerabilities (20.1 * 60%) + License (0.0 * 25%) + Maintenance (0.0 * 15%) = 12.1", "Business Impact Multipliers: Criticality LOW (0.7x) * Internet Facing (1.0x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 12.1 * 0.7 * 1.0 * 1.25 = 10.6 (Normalized to 10.6/100)", "Security Health Deduction: Technical Risk (-12.1) + Deep Dependency Penalty (-3.0) + Maintenance Penalty (-0) = 84.9/100"], "health_score": 84.9, "high_cves": 0, "internet_exposure": false, "lic_score": 0.0, "license_conflicts": 0, "maint_score": 0.0, "owner": "henry@corp.com", "risk_band": "LOW", "risk_color": "#23d160", "risk_score": 10.6, "team": "DevOps", "technical_risk": 12.1, "total_cves": 1, "unmaintained_libs": 0, "vuln_score": 20.1}, {"app_id": "APP-009", "app_name": "MonitoringDash", "compliance": [{"control": "A03:2021-Injection", "detail": "Critical/High CVE (CVE-2021-42550) violates A03:2021-Injection.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2021-42550) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Dependency Management", "detail": "Critical/High CVE (CVE-2021-42550) violates OpenSSF: Dependency Management.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}], "critical_cves": 0, "criticality": "LOW", "cve_summary": [{"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Infrastructure health and alerting dashboard", "explain_risk": ["Technical Risk Components: Vulnerabilities (20.1 * 60%) + License (0.0 * 25%) + Maintenance (0.0 * 15%) = 12.1", "Business Impact Multipliers: Criticality LOW (0.7x) * Internet Facing (1.0x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 12.1 * 0.7 * 1.0 * 1.25 = 10.6 (Normalized to 10.6/100)", "Security Health Deduction: Technical Risk (-12.1) + Deep Dependency Penalty (-3.0) + Maintenance Penalty (-0) = 84.9/100"], "health_score": 84.9, "high_cves": 0, "internet_exposure": false, "lic_score": 0.0, "license_conflicts": 0, "maint_score": 0.0, "owner": "irene@corp.com", "risk_band": "LOW", "risk_color": "#23d160", "risk_score": 10.6, "team": "SRE", "technical_risk": 12.1, "total_cves": 1, "unmaintained_libs": 0, "vuln_score": 20.1}];
const PORTFOLIO  = {"avg_risk_score": 69.2, "critical_apps": 6, "critical_cves": 9, "high_apps": 1, "low_apps": 2, "medium_apps": 1, "portfolio_health": "CRITICAL", "total_apps": 10, "total_license_conflicts": 9, "total_unique_cves": 29, "total_unmaintained": 12, "worst_app": {"app_id": "APP-003", "app_name": "HRPortal", "compliance": [{"control": "A10:2021-Server-Side Request Forgery", "detail": "Critical/High CVE (CVE-2022-1471) violates A10:2021-Server-Side Request Forgery.", "framework": "OWASP", "name": "Vulnerability mapped to OWASP", "status": "FAIL"}, {"control": "NIST SP 800-53: SA-11", "detail": "Critical/High CVE (CVE-2022-1471) violates NIST SP 800-53: SA-11.", "framework": "NIST", "name": "Vulnerability mapped to NIST", "status": "FAIL"}, {"control": "OpenSSF: Vulnerability Reporting", "detail": "Critical/High CVE (CVE-2022-1471) violates OpenSSF: Vulnerability Reporting.", "framework": "OpenSSF", "name": "Vulnerability mapped to OpenSSF", "status": "FAIL"}, {"control": "License Compliance", "detail": "2 copyleft license(s) found in proprietary codebase.", "framework": "Legal / IP", "name": "Open Source License Compliance", "status": "FAIL"}, {"control": "Scorecard / Maintained", "detail": "3 unmaintained dependencies \u2014 security patches unlikely.", "framework": "OpenSSF", "name": "Project Maintenance Risk", "status": "WARN"}, {"control": "SC-2", "detail": "Unmaintained third-party dependencies indicate supplier risk.", "framework": "NIST CSF", "name": "Supplier Assessment", "status": "WARN"}], "critical_cves": 2, "criticality": "HIGH", "cve_summary": [{"contribution": 9.8, "cve_id": "CVE-2022-1471", "cvss": 9.8, "depth": 1, "library": "snakeyaml", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 9.8, "cve_id": "CVE-2022-22965", "cvss": 9.8, "depth": 1, "library": "spring-webmvc", "patch_available": true, "severity": "CRITICAL"}, {"contribution": 7.5, "cve_id": "CVE-2022-25857", "cvss": 7.5, "depth": 1, "library": "snakeyaml", "patch_available": true, "severity": "HIGH"}, {"contribution": 5.61, "cve_id": "CVE-2021-42550", "cvss": 6.6, "depth": 2, "library": "logback-classic", "patch_available": true, "severity": "MEDIUM"}], "description": "Employee HR management and payroll system", "explain_risk": ["Technical Risk Components: Vulnerabilities (73.0 * 60%) + License (79.8 * 25%) + Maintenance (93.6 * 15%) = 77.8", "Business Impact Multipliers: Criticality HIGH (1.25x) * Internet Facing (1.2x) * Patches Available (1.25x)", "Final Business Risk Score calculation: 77.8 * 1.25 * 1.2 * 1.25 = 145.8 (Normalized to 99.3/100)", "Security Health Deduction: Technical Risk (-77.8) + Deep Dependency Penalty (-0.8) + Maintenance Penalty (-6) = 15.5/100"], "health_score": 15.5, "high_cves": 1, "internet_exposure": true, "lic_score": 79.8, "license_conflicts": 2, "maint_score": 93.6, "owner": "carol@corp.com", "risk_band": "CRITICAL", "risk_color": "#ff3860", "risk_score": 99.3, "team": "HR-IT", "technical_risk": 77.8, "total_cves": 4, "unmaintained_libs": 3, "vuln_score": 73.0}};

// Live timestamp
document.getElementById('scanTime').textContent = new Date().toLocaleString();

// Animated counters
document.querySelectorAll('.counter').forEach(el => {
  const target = parseInt(el.dataset.target);
  let current = 0;
  const step = Math.ceil(target / 40);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 30);
});

// ── Risk Bar Chart ──────────────────────────────────────
Plotly.newPlot('riskBarChart', [{
  type: 'bar',
  x: ALL_SCORES.map(s => s.app_name),
  y: ALL_SCORES.map(s => s.risk_score),
  marker: {
    color: ALL_SCORES.map(s => s.risk_color),
    line: { color: 'rgba(255,255,255,0.1)', width: 1 }
  },
  text: ALL_SCORES.map(s => s.risk_score.toFixed(1)),
  textposition: 'outside',
  hovertemplate: '<b>%{x}</b><br>Risk Score: %{y:.1f}<extra></extra>'
}], {
  paper_bgcolor: 'transparent',
  plot_bgcolor: 'transparent',
  font: { color: '#e0e6ed', family: 'Inter', size: 11 },
  margin: { t: 20, b: 80, l: 40, r: 20 },
  xaxis: { tickangle: -35, gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
  yaxis: { range: [0, 110], gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
  showlegend: false,
}, { responsive: true, displayModeBar: false });

// ── Donut Chart ─────────────────────────────────────────
Plotly.newPlot('riskDonut', [{
  type: 'pie',
  hole: 0.6,
  labels: ['Critical Apps', 'High Apps', 'Medium Apps', 'Low Apps'],
  values: [PORTFOLIO.critical_apps, PORTFOLIO.high_apps, PORTFOLIO.medium_apps, PORTFOLIO.low_apps],
  marker: { colors: ['#ff3860','#ff8c00','#ffd700','#23d160'] },
  textinfo: 'label+percent',
  hovertemplate: '<b>%{label}</b><br>%{value} apps (%{percent})<extra></extra>',
  textfont: { color: '#e0e6ed', family: 'Inter', size: 12 }
}], {
  paper_bgcolor: 'transparent',
  plot_bgcolor: 'transparent',
  font: { color: '#e0e6ed', family: 'Inter' },
  margin: { t: 20, b: 20, l: 20, r: 20 },
  showlegend: false,
}, { responsive: true, displayModeBar: false });

// ── Heatmap ─────────────────────────────────────────────
const heatmapApps   = ALL_SCORES.map(s => s.app_name);
const heatmapTypes  = ['Vuln Score', 'License Score', 'Maint Score', 'Total CVEs', 'Critical CVEs'];
const heatmapData   = [
  ALL_SCORES.map(s => s.vuln_score),
  ALL_SCORES.map(s => s.lic_score),
  ALL_SCORES.map(s => s.maint_score),
  ALL_SCORES.map(s => Math.min(100, s.total_cves * 10)),
  ALL_SCORES.map(s => Math.min(100, s.critical_cves * 25)),
];

Plotly.newPlot('riskHeatmap', [{
  type: 'heatmap',
  z: heatmapData,
  x: heatmapApps,
  y: heatmapTypes,
  colorscale: [[0,'#0a1628'],[0.25,'#1a3a5c'],[0.5,'#ffd700'],[0.75,'#ff8c00'],[1,'#ff3860']],
  hovertemplate: '<b>%{x}</b><br>%{y}: %{z:.0f}<extra></extra>',
  showscale: false,
}], {
  paper_bgcolor: 'transparent',
  plot_bgcolor: 'transparent',
  font: { color: '#8899aa', family: 'Inter', size: 10 },
  margin: { t: 10, b: 80, l: 100, r: 10 },
  xaxis: { tickangle: -35, gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
  yaxis: { gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
}, { responsive: true, displayModeBar: false });

// ── Filter buttons ──────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', function () {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    this.classList.add('active');
    const filter = this.dataset.filter;
    document.querySelectorAll('.app-row').forEach(row => {
      if (filter === 'all' || row.dataset.band === filter) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  });
});

// ── Global Search ───────────────────────────────────────
const searchInput = document.getElementById('globalSearch');
const searchDrop  = document.getElementById('searchResults');

searchInput.addEventListener('input', async function () {
  const q = this.value.trim();
  if (q.length < 2) { searchDrop.classList.add('hidden'); return; }
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  const data = await res.json();
  if (!data.length) { searchDrop.innerHTML = '<div class="search-item">No results</div>'; searchDrop.classList.remove('hidden'); return; }
  searchDrop.innerHTML = data.slice(0,8).map(r =>
    `<a class="search-item" href="/app/${r.app_id}">
      <span class="search-cve">${r.cve_id}</span>
      <span class="search-lib">${r.library}</span>
      <span class="search-app">${r.app_name}</span>
      <span class="search-sev sev-${r.severity.toLowerCase()}">${r.severity}</span>
    </a>`
  ).join('');
  searchDrop.classList.remove('hidden');
});

document.addEventListener('click', e => {
  if (!e.target.closest('.nav-search')) searchDrop.classList.add('hidden');
});

// ── Historical Trend Chart ──────────────────────────────
async function loadTrendChart() {
  const res = await fetch('/api/metrics/trends');
  if (res.ok) {
    const data = await res.json();
    const dates = data.map(d => d.date);
    const avgRisk = data.map(d => d.avg_risk);
    const secHealth = data.map(d => d.security_health);
    
    Plotly.newPlot('riskTrendChart', [
      { x: dates, y: avgRisk, type: 'scatter', mode: 'lines+markers', name: 'Avg Risk', line: { color: '#ff3860', width: 3 } },
      { x: dates, y: secHealth, type: 'scatter', mode: 'lines+markers', name: 'Security Health', line: { color: '#23d160', width: 3 } }
    ], {
      paper_bgcolor: 'transparent', plot_bgcolor: 'transparent',
      font: { color: '#e0e6ed', family: 'Inter', size: 11 },
      margin: { t: 20, b: 40, l: 40, r: 20 },
      xaxis: { gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
      yaxis: { range: [0, 100], gridcolor: 'rgba(255,255,255,0.05)', color: '#8899aa' },
      legend: { orientation: 'h', y: -0.2 }
    }, { responsive: true, displayModeBar: false });
  }
}
loadTrendChart();

// ── DataTables Initialization ───────────────────────────
$(document).ready(function() {
  $('#leaderboardTable').DataTable({
    dom: 'Bfrtip',
    buttons: [
      'copyHtml5',
      'excelHtml5',
      'csvHtml5',
      'pdfHtml5'
    ],
    pageLength: 10,
    order: [[4, 'desc']], // Sort by Risk Score descending
    language: {
      search: "Filter Applications:"
    }
  });
}));
