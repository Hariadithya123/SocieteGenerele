# SBOM Risk Intelligence Platform
### Security Control Drift & Misconfiguration Detection Across Enterprise Systems

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Solution Architecture](#3-solution-architecture)
4. [Data Flow & Processing Pipeline](#4-data-flow--processing-pipeline)
5. [Analysis Algorithms](#5-analysis-algorithms)
6. [Risk Scoring Engine](#6-risk-scoring-engine)
7. [User Interface Design](#7-user-interface-design)
8. [API Reference](#8-api-reference)
9. [Dataset Schema](#9-dataset-schema)
10. [Deployment Guide](#10-deployment-guide)
11. [Technology Stack](#11-technology-stack)

---

## 1. Project Overview

The **SBOM Risk Intelligence Platform** is an enterprise-grade security analysis tool that ingests Software Bill of Materials (SBOM) data across multiple applications and produces a mathematically rigorous, normalized risk score per application. It maps vulnerabilities through transitive dependency chains, flags license compliance violations, detects unmaintained libraries, and presents all findings through a modern executive dashboard.

### Key Capabilities

| Feature | Description |
|---|---|
| **CVE Attack Chain Mapping** | Traces the shortest vulnerability propagation path from application to vulnerable library |
| **License Risk Detection** | Identifies copyleft license conflicts in proprietary codebases |
| **Maintenance Risk Scoring** | Flags libraries not updated in 2+ years as supply chain risks |
| **Composite Risk Normalization** | Continuous tanh-based normalization that avoids score saturation |
| **Multi-Dataset Support** | Switch between multiple SBOM datasets (official, problem_10, etc.) |
| **Compliance Mapping** | Maps CVEs to OWASP, NIST, PCI-DSS, OpenSSF frameworks |
| **What-If Simulation** | Simulates the impact of patching specific vulnerabilities |
| **Interactive Dependency Graph** | Cytoscape.js graph visualization of the dependency tree |

---

## 2. Problem Statement

Modern enterprise software relies on hundreds of third-party dependencies. Each dependency may:

- Contain known **CVEs** (Common Vulnerabilities and Exposures)
- Use a **copyleft license** (e.g., GPL) that conflicts with proprietary distribution
- Be **unmaintained** for years, meaning no security patches will be released

Traditional SBOM tools produce long flat lists of vulnerabilities without prioritization or context. Security teams are overwhelmed and unable to determine which applications pose the greatest business risk.

### Challenge

> *"Security Control Drift & Misconfiguration Detection Across Enterprise Systems"*

The platform solves this by:
1. Building a **directed dependency graph** per application using NetworkX.
2. Running **BFS-based attack chain discovery** to trace CVEs to their root impact.
3. Applying a **multi-factor risk formula** that accounts for business criticality, internet exposure, and patch availability.
4. Producing a **normalized, non-saturating risk score** using the hyperbolic tangent function.

---

## 3. Solution Architecture

```
┌────────────────────────────────────────────────────────────┐
│                        Browser / Client                    │
│              (Dashboard · App Detail · Reports)            │
└────────────────────┬───────────────────────────────────────┘
                     │ HTTP / REST API
┌────────────────────▼───────────────────────────────────────┐
│                     Flask Web Server (app.py)              │
│          Routes · Jinja2 Templates · REST Endpoints        │
└────┬────────────┬────────────────┬──────────────┬──────────┘
     │            │                │              │
     ▼            ▼                ▼              ▼
┌─────────┐ ┌──────────┐  ┌──────────────┐ ┌──────────────┐
│DataLoader│ │  Graph   │  │ Risk Scorer  │ │   Report     │
│         │ │ Builder  │  │              │ │  Generator   │
│ Parses  │ │          │  │ Composite    │ │              │
│ CSV/JSON│ │ NetworkX │  │ tanh-based   │ │ PDF / HTML  │
│ Datasets│ │ DiGraph  │  │ Normalization│ │ Exports     │
└─────────┘ └──────────┘  └──────────────┘ └──────────────┘
     │            │
     ▼            ▼
┌─────────────────────────────────────────────────────────┐
│                     Dataset Layer                       │
│  applications.json · sbom_dependencies.csv             │
│  vulnerability_db.json · license_rules.json            │
│  transitive_dependencies.json · dependency_labels.csv  │
└─────────────────────────────────────────────────────────┘
```

### Module Descriptions

| Module | File | Responsibility |
|---|---|---|
| **Web Server** | `app.py` | Flask routes, state management, API endpoints |
| **Data Loader** | `engine/data_loader.py` | Parses all dataset files, handles CSV/JSON formats |
| **Graph Builder** | `engine/graph_builder.py` | Builds NetworkX directed graph, runs CVE/license/maintenance discovery |
| **Risk Scorer** | `engine/risk_scorer.py` | Computes composite normalized risk score per application |
| **Report Generator** | `engine/report_generator.py` | Generates PDF and HTML security reports |

---

## 4. Data Flow & Processing Pipeline

```
Step 1: Data Ingestion
──────────────────────
DataLoader reads:
  - applications.json         → List of applications with metadata
  - sbom_dependencies.csv     → Direct dependency list (app → library)
  - vulnerability_db.json     → CVE database (library → CVE list)
  - license_rules.json        → License risk classification rules
  - transitive_dependencies.json → Transitive (indirect) dependency chains
  - dependency_labels.csv     → Dependency type labels

Step 2: Graph Construction
──────────────────────────
build_full_graph() creates a Directed Acyclic Graph (DAG):
  - App nodes (one per application)
  - Library nodes (one per library@version)
  - Edges represent dependency relationships with depth and type metadata

Step 3: Attack Chain Discovery
──────────────────────────────
For each application:
  find_attack_chains()  → BFS to find all vulnerable library paths
  find_license_conflicts() → Detects copyleft violations
  find_unmaintained()   → Identifies stale libraries (>730 days since update)

Step 4: Risk Scoring
─────────────────────
score_application() computes:
  Vulnerability Score → License Score → Maintenance Score
  → Technical Risk → × Business Multipliers → tanh Normalization → Final Score

Step 5: Leaderboard & Dashboard
──────────────────────────────
score_all_applications() ranks all applications by risk score
Results are stored in AppState and served via Flask templates
```

---

## 5. Analysis Algorithms

### 5.1 CVE Attack Chain Discovery

**Algorithm:** Modified BFS (Breadth-First Search) over the directed dependency graph.

```python
# For each library node reachable from the application root:
for node in nx.descendants(G, app_id):
    if node has CVEs:
        path = nx.shortest_path(G, app_id, node)
        # Record path, CVE details, CVSS score, depth
```

**Depth Discounting:** Vulnerabilities deeper in the dependency tree receive a reduced weight, as they are typically harder to exploit directly.

| Depth | Discount Factor |
|-------|----------------|
| 1 (Direct) | 1.00 (100%) |
| 2 | 0.85 (85%) |
| 3 | 0.70 (70%) |
| 4 | 0.55 (55%) |
| 5+ | 0.50 (50%) |

### 5.2 License Conflict Detection

For each library reachable from the application root:
- Look up the library's license type in `license_rules.json`
- If the license is **copyleft** (e.g., GPL, AGPL) AND the application is **proprietary**
- AND the license risk level is CRITICAL or HIGH → flag as a conflict

### 5.3 Maintenance Risk Detection

A library is flagged as **unmaintained** if:
```
days_since(last_updated) > 730  (2 years)
```

Risk contribution = `min(5.0, age_years) × depth_discount × 2.0`

---

## 6. Risk Scoring Engine

### 6.1 Vulnerability Score

```
vuln_score = 100 × (1 - e^(-0.04 × vuln_raw))
```

Where `vuln_raw` = Σ (CVSS score × depth_discount) for all unique CVEs.

This asymptotic formula ensures the score approaches 100 but never saturates instantly.

### 6.2 License Risk Score

```
lic_score = 100 × (1 - e^(-0.08 × lic_raw))
```

License weights by risk level:

| Risk Level | Weight |
|---|---|
| CRITICAL | 10.0 |
| HIGH | 7.0 |
| MEDIUM | 3.0 |
| UNKNOWN | 4.0 |
| LOW | 0.0 |

### 6.3 Maintenance Score

```
maint_score = 100 × (1 - e^(-0.12 × maint_raw))
```

### 6.4 Technical Risk (Weighted Composite)

```
Technical Risk = (Vuln Score × 0.60) + (Lic Score × 0.25) + (Maint Score × 0.15)
```

| Component | Weight | Rationale |
|---|---|---|
| Vulnerability Score | **60%** | Exploitable CVEs are the primary security threat |
| License Risk | **25%** | Legal exposure is a significant business risk |
| Maintenance Risk | **15%** | Unmaintained libs create long-term supply chain risk |

### 6.5 Business Impact Multipliers

```
Raw Business Score = Technical Risk × Criticality × Exposure × Patch Availability
```

| Multiplier | Factor | Description |
|---|---|---|
| Criticality (CRITICAL) | 1.50× | Business-critical application |
| Criticality (HIGH) | 1.25× | High priority application |
| Criticality (MEDIUM) | 1.00× | Standard application |
| Criticality (LOW) | 0.70× | Low priority internal tool |
| Internet Exposure | 1.20× | Publicly accessible apps face more attack surface |
| Patch Available | 1.25× | Unpatched known vulnerabilities increase negligence risk |

### 6.6 Final Normalization (tanh)

```
Final Score = 100 × tanh(Raw Business Score / NORMALIZATION_SCALE)
```

Where `NORMALIZATION_SCALE = 100.0` (configurable).

**Mathematical Properties:**
- Score is always in range [0, 100]
- Score **never reaches 100** under normal conditions
- Most critical apps fall in the **75–90** range
- Score separation is meaningful across the entire range
- Low-risk apps correctly remain in the **10–35** range

**Score Distribution:**

| Raw Score | Normalized Score | Band |
|---|---|---|
| 0 | 0.0 | LOW |
| 50 | 46.2 | MEDIUM |
| 100 | 76.2 | CRITICAL |
| 150 | 90.5 | CRITICAL |
| 200 | 96.4 | CRITICAL |
| 300 | 99.5 | CRITICAL |

### 6.7 Risk Bands

| Score Range | Band | Color |
|---|---|---|
| 75 – 100 | CRITICAL | 🔴 `#ff3860` |
| 50 – 74 | HIGH | 🟠 `#ff8c00` |
| 25 – 49 | MEDIUM | 🟡 `#ffd700` |
| 0 – 24 | LOW | 🟢 `#23d160` |

### 6.8 Confidence Score

```
Confidence = 100 - (missing_metadata_fields × 2)
```

Missing metadata fields checked: `owner`, `team`, `description`.

---

## 7. User Interface Design

### 7.1 Dashboard (Home Page `/`)

The main dashboard provides an at-a-glance risk posture for the entire application portfolio.

**Components:**
- **Executive Summary Cards** — Total applications, CRITICAL count, total CVEs, license conflicts
- **Risk Leaderboard Table** — All applications ranked by normalized risk score with:
  - Risk score progress bar with color coding
  - Breakdown tooltip on hover (Technical Risk, Business Impact, License, Maintenance, Exposure)
  - Confidence badge showing dataset completeness %
  - CVE severity badges (CRIT / HIGH)
  - License conflict count
  - Unmaintained library count
  - Compliance flag status
- **Dataset Switcher** — Switch between loaded SBOM datasets in the navigation bar
- **Search & Filter** — Real-time search across all applications, CVEs, and libraries

### 7.2 Application Detail Page (`/app/<app_id>`)

A deep-dive view for each application.

**Components:**
- **App Header** — Risk band badge, app name, team, owner, language, criticality badge
- **Risk Gauge** — Animated SVG arc gauge showing the normalized score with confidence indicator
- **6-Card Score Breakdown Grid:**
  1. Technical Risk
  2. Business Impact multiplier
  3. License Risk
  4. Maintenance Risk
  5. Exposure (Internet-facing or Internal)
  6. Final Normalized Score
- **Risk Calculation Explainer** — Step-by-step mathematical explanation, collapsible
- **CVE Attack Chain Explorer** — Each vulnerability shown with:
  - Severity badge, CVE ID, CVSS score
  - Full attack path (App → Library → ... → Vulnerable Lib)
  - Patch availability indicator
- **Interactive Dependency Graph** — Cytoscape.js force-directed graph:
  - Red nodes = CVE-affected libraries
  - Purple nodes = Copyleft license libraries
  - Yellow nodes = Unmaintained libraries
  - Green nodes = Clean libraries
- **License Conflicts Panel** — Copyleft violations with legal description
- **Unmaintained Libraries Panel** — Age-sorted stale dependency list
- **Compliance Framework Mapping** — OWASP, NIST, PCI-DSS, OpenSSF flags
- **What-If Simulation** — Simulates new risk score if specific CVEs were patched

### 7.3 Dataset Manager (`/datasets`)

- Upload new SBOM datasets (ZIP of CSV/JSON files)
- Compare two datasets side by side
- View dataset statistics (app count, CVE count, etc.)

### 7.4 Full Report Page (`/report`)

- Executive summary table of all applications
- Recommended immediate actions
- Exportable as PDF

---

## 8. API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Main dashboard |
| `/app/<app_id>` | GET | Application detail page |
| `/api/app/<app_id>` | GET | Application data as JSON |
| `/api/search` | GET | Search CVEs, libraries, apps |
| `/api/whatif` | POST | What-if simulation for patching |
| `/api/switch_dataset` | POST | Switch active dataset |
| `/report` | GET | Full executive report |
| `/datasets` | GET | Dataset manager |
| `/upload_dataset` | POST | Upload new SBOM dataset |

### Example: API Response (`/api/app/<app_id>`)

```json
{
  "app_id": "app_001",
  "app_name": "PaymentGateway",
  "risk_score": 78.8,
  "raw_score": 106.7,
  "confidence": 100,
  "risk_band": "CRITICAL",
  "technical_risk": 65.2,
  "business_impact": 1.87,
  "vuln_score": 82.1,
  "lic_score": 45.3,
  "maint_score": 20.1,
  "total_cves": 4,
  "critical_cves": 2,
  "high_cves": 1,
  "license_conflicts": 1,
  "unmaintained_libs": 2,
  "internet_exposure": true
}
```

---

## 9. Dataset Schema

### `applications.json`
```json
[
  {
    "app_id": "app_001",
    "name": "PaymentGateway",
    "team": "FinTech",
    "owner": "alice@bank.com",
    "language": "Java",
    "criticality": "CRITICAL",
    "type": "proprietary",
    "internet_exposure": true,
    "description": "Core payment processing system"
  }
]
```

### `sbom_dependencies.csv`
```
app_id,library_name,version,license_type,last_updated,dependency_type,depth,parent_library
app_001,log4j,2.14.1,Apache-2.0,2021-01-01,direct,1,
app_001,jackson-databind,2.9.0,Apache-2.0,2020-06-01,transitive,2,spring-core
```

### `vulnerability_db.json`
```json
{
  "log4j": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss": 10.0,
      "severity": "CRITICAL",
      "affected_versions": ["2.14.1", "2.14.0"],
      "patch_available": true,
      "patch_version": "2.15.0",
      "description": "Log4Shell RCE vulnerability",
      "exploitability": "HIGH",
      "compliance": {
        "OWASP": "A06:2021",
        "NIST": "SI-3"
      }
    }
  ]
}
```

### `license_rules.json`
```json
{
  "GPL-3.0": {
    "copyleft": true,
    "risk_level": "CRITICAL",
    "description": "Strong copyleft — requires full source disclosure on distribution"
  },
  "MIT": {
    "copyleft": false,
    "risk_level": "LOW",
    "description": "Permissive license — safe for commercial use"
  }
}
```

---

## 10. Deployment Guide

### Local Development

**Prerequisites:** Python 3.11+

```bash
# 1. Clone the repository
git clone https://github.com/20MAY07/Socitegenerale.git
cd Socitegenerale

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the development server
python app.py

# 4. Open in browser
# http://127.0.0.1:5000
```

### Production Deployment (Render.com)

**Build Command:**
```bash
pip install -r requirements.txt && pip install gunicorn markdown
```

**Start Command:**
```bash
gunicorn app:app
```

**Environment Variables:**

| Key | Value |
|---|---|
| `PYTHON_VERSION` | `3.11.6` |

**Live URL:** https://socitegenerale-1.onrender.com

---

## 11. Technology Stack

| Layer | Technology | Version |
|---|---|---|
| **Backend Framework** | Flask | 3.0.3 |
| **Graph Engine** | NetworkX | 3.3 |
| **Data Processing** | Pandas, NumPy | 2.2.2 / 1.26.4 |
| **Chart Rendering** | Plotly | 5.22.0 |
| **Dependency Graph Visualization** | Cytoscape.js | 3.29.2 |
| **PDF Report Generation** | ReportLab | 4.2.2 |
| **Template Engine** | Jinja2 | 3.1.4 |
| **Web Server (Production)** | Gunicorn | 22.0.0 |
| **Frontend** | Vanilla HTML/CSS/JS | — |
| **Typography** | Google Fonts (Inter, JetBrains Mono) | — |

---

## Compliance Frameworks Supported

| Framework | Coverage |
|---|---|
| **OWASP Top 10 (2021)** | A06 — Vulnerable & Outdated Components |
| **NIST CSF** | SI-3 Malicious Code Protection · SC-2 Supplier Assessment |
| **PCI-DSS** | Requirement 6 — Secure Systems Development |
| **OpenSSF Scorecard** | Maintained · Dependencies updated |

---

## Authors

**Team:** 20MAY07  
**GitHub:** [https://github.com/20MAY07/Socitegenerale](https://github.com/20MAY07/Socitegenerale)  
**Live Demo:** [https://socitegenerale-1.onrender.com](https://socitegenerale-1.onrender.com)

---

*This platform was developed as part of the Société Générale Hackathon — Problem Statement: Security Control Drift & Misconfiguration Detection Across Enterprise Systems.*
