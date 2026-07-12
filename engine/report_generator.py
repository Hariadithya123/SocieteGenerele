"""
Report Generator — Produces AI-style narratives and remediation playbooks
Uses template-based generation (no external LLM API required)
"""

MITRE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1499": "Endpoint Denial of Service",
    "T1059.007": "Command & Scripting Interpreter: JavaScript",
    "T1083": "File and Directory Discovery",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1557": "Adversary-in-the-Middle",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "NONE":     "⚪",
}


def generate_app_narrative(app_score, attack_chains, license_conflicts, unmaintained):
    """Generate a human-readable executive narrative for an application."""
    name       = app_score["app_name"]
    risk_band  = app_score["risk_band"]
    score      = app_score["risk_score"]
    team       = app_score["team"]
    criticality = app_score["criticality"]

    lines = []

    # ── Executive Summary ──
    risk_descriptor = {
        "CRITICAL": "severely compromised supply chain security posture",
        "HIGH":     "significant software supply chain vulnerabilities",
        "MEDIUM":   "moderate supply chain risk requiring attention",
        "LOW":      "a healthy dependency posture with minor risks",
    }.get(risk_band, "notable risk indicators")

    lines.append(f"**{name}** ({team} team) has a risk score of **{score}/100** [{risk_band}], indicating {risk_descriptor}.")

    if criticality in ["CRITICAL", "HIGH"]:
        lines.append(f"As a **{criticality}-criticality** system, vulnerabilities here carry amplified business impact.")

    # ── Vulnerability Narrative ──
    if attack_chains:
        worst = attack_chains[0]
        lines.append(f"\n### 🔴 Vulnerability Findings ({len(set(c['cve_id'] for c in attack_chains))} unique CVEs)")
        lines.append(f"The most severe finding is **{worst['cve_id']}** (CVSS {worst['cvss']}) in `{worst['vulnerable_lib']} v{worst['version']}`.")
        lines.append(f"**Attack Chain:** `{worst['path_str']}`")
        lines.append(f"**Description:** {worst['description']}")
        if worst['patch_available']:
            lines.append(f"**Remediation:** Upgrade to `{worst['vulnerable_lib']} v{worst['patch_version']}` (patch available).")
        else:
            lines.append(f"**Remediation:** No official patch available. Consider replacing this library or implementing a WAF rule.")

        if worst.get("mitre"):
            mitre_name = MITRE_NAMES.get(worst["mitre"], worst["mitre"])
            lines.append(f"**MITRE ATT&CK:** [{worst['mitre']}](https://attack.mitre.org/techniques/{worst['mitre'].replace('.','/').replace('T','T')}) — {mitre_name}")

        # Log4Shell special case
        if any(c["cve_id"] == "CVE-2021-44228" for c in attack_chains):
            lines.append("\n> ⚠️ **Log4Shell (CVE-2021-44228) detected.** This is the most exploited vulnerability of 2021-2022. "
                         "JNDI injection allows full RCE with a single malicious log message. Treat as P0 — patch immediately.")

        if any(c["cve_id"] == "CVE-2017-5638" for c in attack_chains):
            lines.append("\n> ⚠️ **Struts2 Equifax CVE (CVE-2017-5638) detected.** This exact vulnerability caused the 2017 Equifax breach "
                         "exposing 147 million records. This library is over 7 years past its fix date.")

        if any(c["cve_id"] == "CVE-2022-22965" for c in attack_chains):
            lines.append("\n> ⚠️ **Spring4Shell (CVE-2022-22965) detected.** RCE via Spring MVC data binding on JDK9+. "
                         "Exploitation requires a servlet container — verify your deployment configuration.")

        if any(c["cve_id"] == "CVE-2022-42889" for c in attack_chains):
            lines.append("\n> ⚠️ **Text4Shell (CVE-2022-42889) detected.** Similar attack surface to Log4Shell. "
                         "StringSubstitutor interpolation enables RCE if attacker controls input strings.")

    # ── License Narrative ──
    if license_conflicts:
        lines.append(f"\n### ⚖️ License Conflict Findings ({len(license_conflicts)} conflict(s))")
        for conflict in license_conflicts[:3]:
            lines.append(f"- `{conflict['library']} v{conflict['version']}` — **{conflict['license']}** license detected in a proprietary application.")
            lines.append(f"  {conflict['description']}")
        if len(license_conflicts) > 3:
            lines.append(f"- ...and {len(license_conflicts)-3} additional license conflicts.")
        lines.append("**Risk:** GPL/AGPL viral copyleft could require open-sourcing the entire application codebase upon distribution.")
        lines.append("**Remediation:** Replace with MIT/Apache-2.0 licensed alternatives or obtain a commercial license.")

    # ── Maintenance Narrative ──
    if unmaintained:
        lines.append(f"\n### 🔧 Maintenance Risk ({len(unmaintained)} unmaintained libraries)")
        oldest = unmaintained[0]
        years = oldest['age_days'] / 365
        lines.append(f"The oldest dependency is `{oldest['library']} v{oldest['version']}`, last updated **{oldest['last_updated']}** ({years:.1f} years ago).")
        lines.append("Unmaintained libraries accumulate unpatched CVEs over time and are not eligible for vendor security support.")
        lines.append("**Remediation:** Migrate to actively maintained alternatives. Prioritize libraries with no security policy.")

    return "\n".join(lines)


def generate_remediation_playbook(app_score, attack_chains, license_conflicts, unmaintained):
    """Generate a prioritized, step-by-step remediation playbook."""
    steps = []
    step_num = 1

    # Critical CVEs first
    critical_chains = [c for c in attack_chains if c["severity"] == "CRITICAL"]
    for chain in critical_chains[:3]:
        steps.append({
            "step":       step_num,
            "priority":   "P0 — IMMEDIATE",
            "color":      "#ff3860",
            "action":     f"Patch {chain['vulnerable_lib']}",
            "detail":     f"Upgrade `{chain['vulnerable_lib']}` from `v{chain['version']}` to `v{chain['patch_version']}` to fix {chain['cve_id']} (CVSS {chain['cvss']}).",
            "why":        chain["description"],
            "effort":     "LOW" if chain["patch_available"] else "HIGH",
            "patch_cmd":  _suggest_patch_command(chain["vulnerable_lib"], chain["patch_version"], app_score.get("language", "Java")),
        })
        step_num += 1

    # High CVEs
    high_chains = [c for c in attack_chains if c["severity"] == "HIGH"]
    for chain in high_chains[:3]:
        steps.append({
            "step":       step_num,
            "priority":   "P1 — THIS SPRINT",
            "color":      "#ff8c00",
            "action":     f"Patch {chain['vulnerable_lib']}",
            "detail":     f"Upgrade `{chain['vulnerable_lib']}` from `v{chain['version']}` to `v{chain['patch_version']}` to fix {chain['cve_id']} (CVSS {chain['cvss']}).",
            "why":        chain["description"],
            "effort":     "LOW",
            "patch_cmd":  _suggest_patch_command(chain["vulnerable_lib"], chain["patch_version"], app_score.get("language", "Java")),
        })
        step_num += 1

    # License conflicts
    for conflict in license_conflicts[:2]:
        steps.append({
            "step":       step_num,
            "priority":   "P1 — THIS SPRINT",
            "color":      "#ff8c00",
            "action":     f"Resolve {conflict['license']} license conflict in {conflict['library']}",
            "detail":     f"Replace `{conflict['library']}` with a permissive-licensed alternative (MIT/Apache-2.0), or obtain a commercial license.",
            "why":        f"GPL/AGPL viral copyleft in proprietary software creates serious legal exposure.",
            "effort":     "MEDIUM",
            "patch_cmd":  f"# Search for MIT/Apache alternatives to {conflict['library']}",
        })
        step_num += 1

    # Unmaintained
    for lib in unmaintained[:2]:
        steps.append({
            "step":       step_num,
            "priority":   "P2 — NEXT QUARTER",
            "color":      "#ffd700",
            "action":     f"Replace unmaintained library {lib['library']}",
            "detail":     f"`{lib['library']} v{lib['version']}` hasn't been updated since {lib['last_updated']} ({lib['age_days']//365} years). Migrate to a maintained alternative.",
            "why":        "Unmaintained libraries accumulate unpatched CVEs and receive no vendor security support.",
            "effort":     "HIGH",
            "patch_cmd":  f"# Plan migration from {lib['library']} — search for actively maintained forks or alternatives",
        })
        step_num += 1

    # Medium CVEs
    medium_chains = [c for c in attack_chains if c["severity"] == "MEDIUM"]
    for chain in medium_chains[:2]:
        steps.append({
            "step":       step_num,
            "priority":   "P2 — NEXT QUARTER",
            "color":      "#ffd700",
            "action":     f"Patch {chain['vulnerable_lib']} (Medium severity)",
            "detail":     f"Upgrade `{chain['vulnerable_lib']}` to fix {chain['cve_id']} (CVSS {chain['cvss']}).",
            "why":        chain["description"],
            "effort":     "LOW",
            "patch_cmd":  _suggest_patch_command(chain["vulnerable_lib"], chain["patch_version"], app_score.get("language", "Java")),
        })
        step_num += 1

    if not steps:
        steps.append({
            "step": 1, "priority": "✅ NO ACTION REQUIRED", "color": "#23d160",
            "action": "Maintain current dependency hygiene",
            "detail": "No critical issues detected. Continue regular dependency audits (monthly).",
            "why": "Proactive maintenance prevents future supply chain incidents.",
            "effort": "LOW", "patch_cmd": "# Keep dependencies up to date with automated tooling",
        })

    return steps


def _suggest_patch_command(lib_name, patch_version, language):
    """Suggest the right package manager command."""
    if language in ["Python"]:
        return f"pip install {lib_name.lower().replace('-','_')}=={patch_version}"
    elif language in ["Java"]:
        return f"<!-- In pom.xml -->\n<dependency>\n  <groupId>...</groupId>\n  <artifactId>{lib_name}</artifactId>\n  <version>{patch_version}</version>\n</dependency>"
    else:
        return f"# Upgrade {lib_name} to {patch_version}"


def generate_portfolio_summary(all_scores):
    """Generate a portfolio-level executive summary."""
    total = len(all_scores)
    critical = sum(1 for s in all_scores if s["risk_band"] == "CRITICAL")
    high     = sum(1 for s in all_scores if s["risk_band"] == "HIGH")
    medium   = sum(1 for s in all_scores if s["risk_band"] == "MEDIUM")
    low      = sum(1 for s in all_scores if s["risk_band"] == "LOW")

    all_cves = sum(s["total_cves"] for s in all_scores)
    all_critical_cves = sum(s["critical_cves"] for s in all_scores)
    all_lic  = sum(s["license_conflicts"] for s in all_scores)
    all_unmaint = sum(s["unmaintained_libs"] for s in all_scores)

    avg_score = sum(s["risk_score"] for s in all_scores) / total if total else 0

    worst_app = all_scores[0] if all_scores else None

    return {
        "total_apps":        total,
        "critical_apps":     critical,
        "high_apps":         high,
        "medium_apps":       medium,
        "low_apps":          low,
        "avg_risk_score":    round(avg_score, 1),
        "total_unique_cves": all_cves,
        "critical_cves":     all_critical_cves,
        "total_license_conflicts": all_lic,
        "total_unmaintained": all_unmaint,
        "worst_app":         worst_app,
        "portfolio_health":  "CRITICAL" if critical > 0 else ("HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"),
    }
