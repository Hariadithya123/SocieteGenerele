"""
Risk Scorer — Computes composite risk scores per application
Formula: Vulnerability Score (60%) + License Risk (25%) + Maintenance Risk (15%)
Adjusted by environment criticality multiplier
"""
import math

CRITICALITY_MULTIPLIER = {
    "CRITICAL": 1.50,
    "HIGH":     1.25,
    "MEDIUM":   1.00,
    "LOW":      0.70,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "NONE":     0.0,
}

LICENSE_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH":     7.0,
    "MEDIUM":   3.0,
    "LOW":      0.0,
    "UNKNOWN":  4.0,
}

DEPTH_DISCOUNT = {1: 1.0, 2: 0.85, 3: 0.70, 4: 0.55}

NORMALIZATION_SCALE = 100.0


def score_application(app, attack_chains, license_conflicts, unmaintained):
    """
    Compute composite risk score (0–100) for an application.

    Returns detailed breakdown dict.
    """
    criticality = app.get("criticality", "MEDIUM")
    criticality_multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.0)
    
    internet_exposure = app.get("internet_exposure", False)
    exposure_multiplier = 1.2 if internet_exposure else 1.0
    
    # ── Technical Risk (Vulnerability + License + Maintenance) ──
    vuln_raw = 0.0
    cve_summary = []
    seen_cves = set()
    for chain in attack_chains:
        cve_id = chain["cve_id"]
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        cvss   = chain["cvss"]
        depth  = chain["depth"]
        disc   = DEPTH_DISCOUNT.get(depth, 0.50)
        contribution = cvss * disc
        vuln_raw += contribution
        cve_summary.append({
            "cve_id":        cve_id,
            "cvss":          cvss,
            "severity":      chain["severity"],
            "depth":         depth,
            "contribution":  round(contribution, 2),
            "library":       chain["vulnerable_lib"],
            "patch_available": chain["patch_available"],
        })

    # Asymptotic scoring (approaches 100 but never saturates instantly)
    # k=0.04 means a raw score of 60 gives ~91%
    vuln_score = 100.0 * (1.0 - math.exp(-0.04 * vuln_raw))

    # ── License Score ───────────────────────────────────────
    lic_raw = 0.0
    for conflict in license_conflicts:
        lic_risk = conflict.get("lic_risk", "MEDIUM")
        depth    = conflict.get("depth", 1)
        disc     = DEPTH_DISCOUNT.get(depth, 0.50)
        lic_raw += LICENSE_WEIGHTS.get(lic_risk, 3.0) * disc

    # k=0.08 means a raw score of 30 gives ~91%
    lic_score = 100.0 * (1.0 - math.exp(-0.08 * lic_raw))

    # ── Maintenance Score ───────────────────────────────────
    maint_raw = 0.0
    for lib in unmaintained:
        age_years  = lib["age_days"] / 365.0
        depth      = lib["depth"]
        disc       = DEPTH_DISCOUNT.get(depth, 0.50)
        # Older = more risky, cap at 5 years
        maint_raw += min(5.0, age_years) * disc * 2.0

    # k=0.12 means a raw score of 20 gives ~91%
    maint_score = 100.0 * (1.0 - math.exp(-0.12 * maint_raw))

    # ── Final Technical Risk ─────────────────────────────────────
    technical_risk = (vuln_score * 0.60) + (lic_score * 0.25) + (maint_score * 0.15)
    
    # ── Patch Availability Multiplier ────────────────────────
    # If patches are available for vulnerabilities, the risk of not patching increases the business impact
    has_patches = any(c.get("patch_available") for c in cve_summary)
    patch_multiplier = 1.25 if has_patches else 1.0
    
    # ── Business Impact Scoring ──────────────────────────────
    # Formula: Technical Risk * Criticality * Internet Exposure * Patch Availability
    raw_final = technical_risk * criticality_multiplier * exposure_multiplier * patch_multiplier
    
    # Asymptotically approach 100 using tanh
    final_score = 100.0 * math.tanh(raw_final / NORMALIZATION_SCALE)

    final_score = min(100.0, final_score)

    # ── Security Health ──────────────────────────────────────
    # Based on normalized technical risk, unmaintained libs, and tech debt (avg depth)
    avg_depth = sum(c["depth"] for c in cve_summary) / len(cve_summary) if cve_summary else 1
    depth_penalty = min(15, (avg_depth - 1) * 3) # Penalty for deeply nested vulnerabilities
    maintenance_penalty = min(20, len(unmaintained) * 2)
    
    security_health = max(0.0, 100.0 - technical_risk - depth_penalty - maintenance_penalty)
    
    # ── Explain Risk ─────────────────────────────────────────
    explain_risk = [
        f"Technical Risk Components: Vulnerabilities ({round(vuln_score,1)} * 60%) + License ({round(lic_score,1)} * 25%) + Maintenance ({round(maint_score,1)} * 15%) = {round(technical_risk,1)}",
        f"Business Impact Multipliers: Criticality {criticality} ({criticality_multiplier}x) * Internet Facing ({exposure_multiplier}x) * Patches Available ({patch_multiplier}x)",
        f"Raw Business Risk Score calculation: {round(technical_risk,1)} * {criticality_multiplier} * {exposure_multiplier} * {patch_multiplier} = {round(raw_final, 1)}",
        f"Normalization: 100 * tanh({round(raw_final,1)} / {NORMALIZATION_SCALE}) = {round(final_score,1)}/100",
        f"Security Health Deduction: Technical Risk (-{round(technical_risk,1)}) + Deep Dependency Penalty (-{round(depth_penalty,1)}) + Maintenance Penalty (-{round(maintenance_penalty,1)}) = {round(security_health,1)}/100"
    ]

    # ── Risk Band ───────────────────────────────────────────
    if final_score >= 75:
        risk_band = "CRITICAL"
        risk_color = "#ff3860"
    elif final_score >= 50:
        risk_band = "HIGH"
        risk_color = "#ff8c00"
    elif final_score >= 25:
        risk_band = "MEDIUM"
        risk_color = "#ffd700"
    else:
        risk_band = "LOW"
        risk_color = "#23d160"

    # ── Compliance Flags & Confidence ───────────────────────
    compliance = _map_compliance(attack_chains, license_conflicts, unmaintained)

    missing_metadata = sum(1 for k in ["owner", "team", "description"] if not app.get(k))
    confidence_score = 100 - (missing_metadata * 2)

    return {
        "app_id":           app["app_id"],
        "app_name":         app["name"],
        "criticality":      criticality,
        "raw_score":        round(raw_final, 1),
        "risk_score":       round(final_score, 1),
        "confidence":       confidence_score,
        "health_score":     round(security_health, 1),
        "technical_risk":   round(technical_risk, 1),
        "business_impact":  round(criticality_multiplier * exposure_multiplier * patch_multiplier, 2),
        "risk_band":        risk_band,
        "risk_color":       risk_color,
        "vuln_score":       round(vuln_score, 1),
        "lic_score":        round(lic_score, 1),
        "maint_score":      round(maint_score, 1),
        "explain_risk":     explain_risk,
        "total_cves":       len(seen_cves),
        "critical_cves":    sum(1 for c in cve_summary if c["severity"] == "CRITICAL"),
        "high_cves":        sum(1 for c in cve_summary if c["severity"] == "HIGH"),
        "cve_summary":      sorted(cve_summary, key=lambda x: x["cvss"], reverse=True),
        "license_conflicts":len(license_conflicts),
        "unmaintained_libs":len(unmaintained),
        "compliance":       compliance,
        "team":             app.get("team", ""),
        "owner":            app.get("owner", ""),
        "description":      app.get("description", ""),
        "internet_exposure":internet_exposure
    }


def score_all_applications(apps, attack_chains_map, license_conflicts_map, unmaintained_map):
    """Score all applications and return sorted risk leaderboard."""
    results = []
    for app in apps:
        app_id = app["app_id"]
        result = score_application(
            app,
            attack_chains_map.get(app_id, []),
            license_conflicts_map.get(app_id, []),
            unmaintained_map.get(app_id, []),
        )
        results.append(result)
    return sorted(results, key=lambda x: x["risk_score"], reverse=True)


def _map_compliance(attack_chains, license_conflicts, unmaintained):
    """Map findings to compliance frameworks."""
    flags = []

    seen_frameworks = set()
    for chain in attack_chains:
        if "compliance" in chain and isinstance(chain["compliance"], dict):
            comp = chain["compliance"]
            for framework, control in comp.items():
                if framework not in seen_frameworks:
                    seen_frameworks.add(framework)
                    flags.append({
                        "framework": framework,
                        "control":   control,
                        "name":      f"Vulnerability mapped to {framework}",
                        "status":    "FAIL",
                        "detail":    f"Critical/High CVE ({chain['cve_id']}) violates {control}."
                    })

    if license_conflicts:
        flags.append({
            "framework": "Legal / IP",
            "control":   "License Compliance",
            "name":      "Open Source License Compliance",
            "status":    "FAIL",
            "detail":    f"{len(license_conflicts)} copyleft license(s) found in proprietary codebase."
        })

    if unmaintained:
        flags.append({
            "framework": "OpenSSF",
            "control":   "Scorecard / Maintained",
            "name":      "Project Maintenance Risk",
            "status":    "WARN",
            "detail":    f"{len(unmaintained)} unmaintained dependencies — security patches unlikely."
        })
        flags.append({
            "framework": "NIST CSF",
            "control":   "SC-2",
            "name":      "Supplier Assessment",
            "status":    "WARN",
            "detail":    "Unmaintained third-party dependencies indicate supplier risk."
        })

    if not flags:
        flags.append({
            "framework": "All Frameworks",
            "control":   "—",
            "name":      "No Issues Detected",
            "status":    "PASS",
            "detail":    "Application meets minimum supply chain security requirements."
        })

    return flags
