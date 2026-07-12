"""
SBOM Risk Intelligence Platform — Flask Web Application
"""
import json
import os
import csv
import markdown as md_lib
from markupsafe import Markup
from flask import Flask, render_template, jsonify, request, send_file
import io
import shutil
import zipfile

from engine.data_loader import DataLoader, days_since
from engine.graph_builder import (
    build_full_graph,
    find_attack_chains,
    find_license_conflicts,
    find_unmaintained,
    graph_to_cytoscape,
)
from engine.risk_scorer import score_application, score_all_applications
from engine.report_generator import (
    generate_app_narrative,
    generate_remediation_playbook,
    generate_portfolio_summary,
)

app = Flask(__name__)

# ── Jinja2 markdown filter ────────────────────────────
@app.template_filter('markdown')
def render_markdown(text):
    """Convert markdown text to safe HTML for template rendering."""
    html = md_lib.markdown(
        text,
        extensions=['nl2br', 'sane_lists']
    )
    return Markup(html)

# ── State Management ─────────────────────────────────────────
class AppState:
    def __init__(self):
        self.last_state_hash = ""
        self.current_dataset = "official"
        self.apps = []
        self.vuln_list = []
        self.vuln_lookup = {}
        self.lic_rules = {}
        self.deps = []
        self.labels = []
        self.transitive = []
        self.G = None
        self.attack_chains_map = {}
        self.license_conflicts_map = {}
        self.unmaintained_map = {}
        self.app_scores_map = {}
        self.all_scores = []
        self.portfolio = {}

    def load_dataset(self, dataset_name):
        self.current_dataset = dataset_name
        loader = DataLoader(dataset_name)
        self.apps, self.vuln_list, self.vuln_lookup, self.lic_rules, self.deps, self.labels, self.transitive = loader.load_all()
        
        self.G = build_full_graph(self.apps, self.deps, self.vuln_lookup, self.lic_rules, self.transitive)

        self.attack_chains_map.clear()
        self.license_conflicts_map.clear()
        self.unmaintained_map.clear()
        self.app_scores_map.clear()

        for application in self.apps:
            app_id   = application.get("app_id")
            if not app_id: continue
            app_type = application.get("type", "proprietary")
            chains   = find_attack_chains(self.G, app_id)
            lic_conf = find_license_conflicts(self.G, app_id, app_type)
            unmaint  = find_unmaintained(self.G, app_id)

            self.attack_chains_map[app_id]     = chains
            self.license_conflicts_map[app_id] = lic_conf
            self.unmaintained_map[app_id]      = unmaint

        self.all_scores = score_all_applications(
            self.apps, self.attack_chains_map, self.license_conflicts_map, self.unmaintained_map
        )
        self.portfolio = generate_portfolio_summary(self.all_scores)

        for score in self.all_scores:
            self.app_scores_map[score["app_id"]] = score

        print(f"Loaded dataset '{dataset_name}' — {len(self.apps)} applications scored.")

state = AppState()

def get_directory_state_hash():
    pass

def refresh_data():
    pass # No longer auto-refreshing on request

# Initialize with official dataset
state.load_dataset("official")

@app.before_request
def before_request():
    # Don't refresh on static file requests to avoid overhead
    if not request.path.startswith('/static/'):
        refresh_data()

# ── App lookup ────────────────────────────────────────────
def get_app(app_id):
    return next((a for a in state.apps if a["app_id"] == app_id), None)


# ── Routes ────────────────────────────────────────────────

@app.route('/datasets')
def dataset_manager():
    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    datasets = [d for d in os.listdir(datasets_dir) if os.path.isdir(os.path.join(datasets_dir, d))]
    return render_template('dataset_manager.html', datasets=datasets, current=state.current_dataset)

@app.route('/api/dataset/switch', methods=['POST'])
def switch_dataset():
    data = request.json
    ds_name = data.get("dataset_name")
    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    if not ds_name or not os.path.exists(os.path.join(datasets_dir, ds_name)):
        return jsonify({"success": False, "error": "Dataset not found"}), 404
    
    try:
        state.load_dataset(ds_name)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/compare')
def compare_datasets():
    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    available_datasets = [d for d in os.listdir(datasets_dir) if os.path.isdir(os.path.join(datasets_dir, d))]
    
    ds1_name = request.args.get('ds1', 'official')
    ds2_name = request.args.get('ds2', 'problem10')
    
    if ds1_name not in available_datasets: ds1_name = available_datasets[0] if available_datasets else ""
    if ds2_name not in available_datasets: ds2_name = available_datasets[0] if available_datasets else ""
    
    def get_stats(ds_name):
        loader = DataLoader(ds_name)
        apps, vuln_list, vuln_lookup, lic_rules, deps, labels, transitive = loader.load_all()
        G = build_full_graph(apps, deps, vuln_lookup, lic_rules, transitive)
        
        chains_map = {}
        lic_map = {}
        unmaint_map = {}
        
        for app in apps:
            app_id = app.get("app_id")
            if not app_id: continue
            chains_map[app_id] = find_attack_chains(G, app_id)
            lic_map[app_id] = find_license_conflicts(G, app_id, app.get("type", "proprietary"))
            unmaint_map[app_id] = find_unmaintained(G, app_id)
            
        all_scores = score_all_applications(apps, chains_map, lic_map, unmaint_map)
        
        total_crit_cves = sum(1 for c in chains_map.values() for chain in c if chain.get("severity") == "CRITICAL")
        total_lic_conf = sum(len(c) for c in lic_map.values())
        avg_risk = int(sum(s.get("business_impact", 0) for s in all_scores) / max(1, len(all_scores)))
        
        return {
            "apps": len(apps),
            "deps": len(deps),
            "crit_cves": total_crit_cves,
            "lic_conf": total_lic_conf,
            "avg_risk": avg_risk
        }
    
    stats1 = get_stats(ds1_name) if ds1_name else {}
    stats2 = get_stats(ds2_name) if ds2_name else {}
    
    metrics = [
        {"label": "Applications", "val1": stats1.get("apps",0), "val2": stats2.get("apps",0), "delta": stats2.get("apps",0) - stats1.get("apps",0)},
        {"label": "Dependencies", "val1": stats1.get("deps",0), "val2": stats2.get("deps",0), "delta": stats2.get("deps",0) - stats1.get("deps",0)},
        {"label": "Critical CVEs", "val1": stats1.get("crit_cves",0), "val2": stats2.get("crit_cves",0), "delta": stats2.get("crit_cves",0) - stats1.get("crit_cves",0)},
        {"label": "License Conflicts", "val1": stats1.get("lic_conf",0), "val2": stats2.get("lic_conf",0), "delta": stats2.get("lic_conf",0) - stats1.get("lic_conf",0)},
        {"label": "Average Risk", "val1": stats1.get("avg_risk",0), "val2": stats2.get("avg_risk",0), "delta": stats2.get("avg_risk",0) - stats1.get("avg_risk",0)},
    ]
    
    return render_template('dataset_compare.html', 
                           available_datasets=available_datasets,
                           ds1_name=ds1_name,
                           ds2_name=ds2_name,
                           metrics=metrics,
                           current_dataset=state.current_dataset)

@app.route('/api/dataset/upload', methods=['POST'])
def upload_dataset():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "Empty filename"}), 400
    
    dataset_name = request.form.get("dataset_name", "custom_upload").strip()
    # Sanitize
    dataset_name = "".join(c for c in dataset_name if c.isalnum() or c in "_-")
    if not dataset_name:
        dataset_name = "custom_upload"
        
    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    target_dir = os.path.join(datasets_dir, dataset_name)
    
    os.makedirs(target_dir, exist_ok=True)
    
    # Save the zip
    zip_path = os.path.join(target_dir, "upload.zip")
    file.save(zip_path)
    
    # Extract
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(target_dir)
            
        # Recursive Flattener: find the folder containing applications.json and move its contents to target_dir
        found_dir = None
        for root, dirs, files in os.walk(target_dir):
            if "applications.json" in files or "application.json" in files:
                found_dir = root
                break
        
        if found_dir and found_dir != target_dir:
            for item in os.listdir(found_dir):
                dest = os.path.join(target_dir, item)
                if os.path.exists(dest):
                    if os.path.isdir(dest):
                        shutil.rmtree(dest)
                    else:
                        os.remove(dest)
                shutil.move(os.path.join(found_dir, item), target_dir)
            
            # Clean up all other subdirectories inside target_dir
            for item in os.listdir(target_dir):
                item_path = os.path.join(target_dir, item)
                if os.path.isdir(item_path) and item != "upload.zip":
                    try:
                        shutil.rmtree(item_path)
                    except Exception:
                        pass
        else:
            # Fallback single folder flattener
            extracted_items = [item for item in os.listdir(target_dir) if item != "upload.zip"]
            if len(extracted_items) == 1 and os.path.isdir(os.path.join(target_dir, extracted_items[0])):
                sub_dir = os.path.join(target_dir, extracted_items[0])
                for item in os.listdir(sub_dir):
                    shutil.move(os.path.join(sub_dir, item), target_dir)
                os.rmdir(sub_dir)
                
        # Smart File Normalizer: map variations of names to standard names
        for file_in_dir in os.listdir(target_dir):
            low = file_in_dir.lower()
            src = os.path.join(target_dir, file_in_dir)
            if os.path.isdir(src):
                continue
            if low in ["sbom_dependency.csv", "dependencies.csv", "dependency.csv", "sbom_dependencies.csv"]:
                dest = os.path.join(target_dir, "sbom_dependencies.csv")
                if src != dest:
                    if os.path.exists(dest): os.remove(dest)
                    os.rename(src, dest)
            elif low in ["application.json", "applications.json"]:
                dest = os.path.join(target_dir, "applications.json")
                if src != dest:
                    if os.path.exists(dest): os.remove(dest)
                    os.rename(src, dest)
            elif low in ["vulnerability.json", "vulnerabilities.json", "vulnerability_db.json", "vulnerabilities_db.json"]:
                dest = os.path.join(target_dir, "vulnerability_db.json")
                if src != dest:
                    if os.path.exists(dest): os.remove(dest)
                    os.rename(src, dest)
            elif low in ["license_rule.json", "license_rules.json", "license.json", "licenses.json"]:
                dest = os.path.join(target_dir, "license_rules.json")
                if src != dest:
                    if os.path.exists(dest): os.remove(dest)
                    os.rename(src, dest)
            elif low in ["transitive.json", "transitives.json", "transitive_dependencies.json", "transitive_dependency.json"]:
                dest = os.path.join(target_dir, "transitive_dependencies.json")
                if src != dest:
                    if os.path.exists(dest): os.remove(dest)
                    os.rename(src, dest)
            
    except Exception as e:
        return jsonify({"success": False, "error": "Invalid ZIP file: " + str(e)}), 400
    
    # Validation logic
    required_files = ["applications.json", "sbom_dependencies.csv", "vulnerability_db.json", "license_rules.json"]
    report = []
    has_error = False
    
    for f in required_files:
        file_path = os.path.join(target_dir, f)
        if os.path.exists(file_path):
            # Try parsing
            try:
                if f.endswith(".json"):
                    with open(file_path, "r", encoding="utf-8") as jf:
                        json.load(jf)
                elif f.endswith(".csv"):
                    with open(file_path, "r", encoding="utf-8") as cf:
                        reader = csv.reader(cf)
                        next(reader, None) # read header
                report.append(f"✓ {f} (Valid)")
            except Exception as e:
                report.append(f"✗ {f} (Invalid format: {type(e).__name__})")
                has_error = True
        else:
            report.append(f"✗ {f} missing")
            has_error = True
            
    # Clean up the zip file
    try:
        os.remove(zip_path)
    except Exception:
        pass
        
    if has_error:
        # We don't delete the directory yet in case they want to fix it, or we could.
        return jsonify({
            "success": False, 
            "error": "Validation Failed", 
            "report": report
        }), 400
        
    return jsonify({
        "success": True,
        "dataset_name": dataset_name,
        "report": report
    })

@app.route("/")
def index():
    """Main dashboard — risk leaderboard + portfolio overview."""
    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    available_datasets = [d for d in os.listdir(datasets_dir) if os.path.isdir(os.path.join(datasets_dir, d))]
    
    return render_template(
        "index.html",
        portfolio=state.portfolio,
        all_scores=state.all_scores,
        apps=state.apps,
        current_dataset=state.current_dataset,
        available_datasets=available_datasets
    )


@app.route("/app/<app_id>")
def app_detail(app_id):
    """Per-application detail page with full analysis."""
    application = get_app(app_id)
    if not application:
        return "App not found", 404

    score          = state.app_scores_map.get(app_id, {})
    chains         = state.attack_chains_map.get(app_id, [])
    lic_conflicts  = state.license_conflicts_map.get(app_id, [])
    unmaint        = state.unmaintained_map.get(app_id, [])
    narrative      = generate_app_narrative(score, chains, lic_conflicts, unmaint)
    playbook       = generate_remediation_playbook(score, chains, lic_conflicts, unmaint)
    cytoscape_data = graph_to_cytoscape(state.G, app_id)

    # Dep stats for this app
    app_deps = [d for d in state.deps if d.get("app_id") == app_id]
    app_labels = [l for l in state.labels if l.get("app_id") == app_id]

    datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
    available_datasets = [d for d in os.listdir(datasets_dir) if os.path.isdir(os.path.join(datasets_dir, d))]

    return render_template(
        "app_detail.html",
        application=application,
        score=score,
        chains=chains,
        lic_conflicts=lic_conflicts,
        unmaint=unmaint,
        narrative=narrative,
        playbook=playbook,
        cytoscape_data=json.dumps(cytoscape_data),
        total_deps=len(app_deps),
        all_scores=state.all_scores,
        current_dataset=state.current_dataset,
        available_datasets=available_datasets
    )


@app.route("/api/portfolio")
def api_portfolio():
    """Portfolio-level JSON API."""
    return jsonify(state.portfolio)


@app.route("/api/scores")
def api_scores():
    """All app risk scores as JSON."""
    return jsonify(state.all_scores)


@app.route("/api/app/<app_id>")
def api_app(app_id):
    """Full analysis for a single app as JSON."""
    application = get_app(app_id)
    if not application:
        return jsonify({"error": "Not found"}), 404

    score    = state.app_scores_map.get(app_id, {})
    chains   = state.attack_chains_map.get(app_id, [])
    lic_conf = state.license_conflicts_map.get(app_id, [])
    unmaint  = state.unmaintained_map.get(app_id, [])
    playbook = generate_remediation_playbook(score, chains, lic_conf, unmaint)

    return jsonify({
        "application":       application,
        "score":             score,
        "attack_chains":     chains,
        "license_conflicts": lic_conf,
        "unmaintained":      unmaint,
        "playbook":          playbook,
    })


@app.route("/api/graph/<app_id>")
def api_graph(app_id):
    """Cytoscape.js-compatible graph data for an app."""
    data = graph_to_cytoscape(state.G, app_id)
    return jsonify(data)


@app.route("/api/search")
def api_search():
    """Search for a CVE or library across all apps."""
    query = request.args.get("q", "").lower().strip()
    if not query:
        return jsonify([])

    results = []
    seen_keys = set()
    
    # Primary search: CVE attack chains (matches CVE ID, library name, description)
    for application in state.apps:
        app_id = application["app_id"]
        chains = state.attack_chains_map.get(app_id, [])
        for chain in chains:
            if (query in chain["cve_id"].lower() or
                    query in chain["vulnerable_lib"].lower() or
                    query in chain["description"].lower()):
                key = (app_id, chain["cve_id"], chain["vulnerable_lib"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append({
                        "app_id":   app_id,
                        "app_name": application["name"],
                        "cve_id":   chain["cve_id"],
                        "library":  chain["vulnerable_lib"],
                        "cvss":     chain["cvss"],
                        "severity": chain["severity"],
                    })
    
    # Secondary search: library names in all deps (catches clean libs too)
    app_map = {a["app_id"]: a for a in state.apps}
    for dep in state.deps:
        if len(results) >= 15:
            break
        lib_name = dep.get("library_name") or ""
        if not lib_name or query not in lib_name.lower():
            continue
        dep_app_id = dep.get("app_id") or ""
        dep_app = app_map.get(dep_app_id, {})
        key = (dep_app_id, "DEP", lib_name)
        if key not in seen_keys:
            seen_keys.add(key)
            results.append({
                "app_id":   dep_app_id,
                "app_name": dep_app.get("name", dep_app_id),
                "cve_id":   f"Library: {lib_name} v{dep.get('version','')}",
                "library":  lib_name,
                "cvss":     0,
                "severity": "INFO",
            })
    
    return jsonify(results[:15])


@app.route("/api/export/csv")
def export_csv():
    """Export full risk report as CSV."""
    import csv
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["App ID", "App Name", "Team", "Criticality", "Risk Score", "Risk Band",
                     "Total CVEs", "Critical CVEs", "License Conflicts", "Unmaintained Libs",
                     "Vuln Score", "License Score", "Maintenance Score"])

    for s in state.all_scores:
        writer.writerow([
            s["app_id"], s["app_name"], s["team"], s["criticality"],
            s["risk_score"], s["risk_band"], s["total_cves"], s["critical_cves"],
            s["license_conflicts"], s["unmaintained_libs"],
            s["vuln_score"], s["lic_score"], s["maint_score"],
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="sbom_risk_report.csv"
    )


@app.route("/report")
def full_report():
    """Full portfolio report page."""
    detailed = []
    for s in state.all_scores:
        app_id = s["app_id"]
        chains  = state.attack_chains_map.get(app_id, [])
        lic_con = state.license_conflicts_map.get(app_id, [])
        unmaint = state.unmaintained_map.get(app_id, [])
        playbook = generate_remediation_playbook(s, chains, lic_con, unmaint)
        detailed.append({
            "score":    s,
            "chains":   chains[:5],
            "lic":      lic_con,
            "unmaint":  unmaint,
            "playbook": playbook[:3],
        })
    return render_template("report.html", portfolio=state.portfolio, detailed=detailed, all_scores=state.all_scores)


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """What-if Risk Simulation"""
    data = request.json
    app_id = data.get("app_id")
    library = data.get("library")
    new_version = data.get("new_version")
    
    if not all([app_id, library, new_version]):
        return jsonify({"error": "Missing parameters"}), 400
        
    application = get_app(app_id)
    if not application:
        return jsonify({"error": "App not found"}), 404
        
    # Deep copy dependencies for this app to simulate
    import copy
    sim_deps = copy.deepcopy([d for d in state.deps if d.get("app_id") == app_id])
    sim_transitive = copy.deepcopy(state.transitive)
    
    library = library.strip()
    patched = False
    for d in sim_deps:
        lib_name = d.get("library_name")
        if lib_name and lib_name.strip().lower() == library.lower():
            d["version"] = new_version
            patched = True
            
    if isinstance(sim_transitive, dict):
        for parent, children in sim_transitive.items():
            for i, child in enumerate(children):
                if ":" in child:
                    c_name, c_ver = child.split(":", 1)
                    if c_name.strip().lower() == library.lower():
                        children[i] = f"{c_name}:{new_version}"
                        patched = True
                        
    if not patched:
        return jsonify({"error": "Library not found in application dependencies"}), 404
        
    # Rebuild localized graph
    from engine.graph_builder import build_full_graph, find_attack_chains, find_license_conflicts, find_unmaintained
    from engine.risk_scorer import score_application
    
    sim_G = build_full_graph([application], sim_deps, state.vuln_lookup, state.lic_rules, sim_transitive)
    
    attack_chains = find_attack_chains(sim_G, app_id)
    license_conflicts = find_license_conflicts(sim_G, app_id, application.get("type", "proprietary"))
    unmaintained = find_unmaintained(sim_G, app_id)
    
    new_score = score_application(application, attack_chains, license_conflicts, unmaintained)
    current_score = state.app_scores_map.get(app_id, {})
    
    # Calculate risk reduction
    curr_risk = current_score.get("risk_score", 0)
    new_risk = new_score.get("risk_score", 0)
    reduction = max(0, curr_risk - new_risk)
    reduction_pct = round((reduction / curr_risk) * 100, 1) if curr_risk > 0 else 0
    
    return jsonify({
        "current_score": current_score,
        "simulated_score": new_score,
        "reduction_absolute": round(reduction, 1),
        "reduction_percentage": reduction_pct
    })


@app.route("/api/ai/copilot", methods=["POST"])
def api_ai_copilot():
    """Hybrid AI Copilot - Fallback Rule Engine"""
    data = request.json
    app_id = data.get("app_id")
    query = data.get("query", "").strip()
    
    application = get_app(app_id)
    score = state.app_scores_map.get(app_id, {})
    
    system_prompt = (
        f"You are an expert Software Supply Chain Security Copilot. "
        f"You are helping the user analyze the application '{application.get('name')}' (ID: {app_id}, Criticality: {application.get('criticality')}). "
        f"This application has a supply chain Risk Score of {score.get('risk_score')}/100, "
        f"Security Health score of {score.get('health_score')}/100, and Technical Risk score of {score.get('technical_risk')}/100. "
        f"It has {len(state.attack_chains_map.get(app_id, []))} critical CVE paths, "
        f"{len(state.license_conflicts_map.get(app_id, []))} license conflicts, and "
        f"{len(state.unmaintained_map.get(app_id, []))} unmaintained libraries. "
        f"Keep your answers concise, clear, and professional. You can answer security questions, code, or any general questions the user asks."
    )
    
    # Multi-strategy retry for LLM
    import requests
    import urllib.parse
    import traceback
    
    # Strategy 1: POST with Mistral model (fast timeout)
    try:
        res = requests.post(
            "https://text.pollinations.ai/",
            json={
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": query}
                ],
                "model": "mistral"
            },
            timeout=3
        )
        if res.status_code == 200 and res.text and len(res.text) > 20:
            return jsonify({"response": res.text})
    except Exception:
        pass

    # Strategy 2: GET with Mistral model
    try:
        q_enc = urllib.parse.quote(query[:200])  # Limit query length
        sys_enc = urllib.parse.quote(system_prompt[:500])
        res = requests.get(
            f"https://text.pollinations.ai/{q_enc}?system={sys_enc}&model=mistral",
            timeout=3
        )
        if res.status_code == 200 and res.text and len(res.text) > 20:
            return jsonify({"response": res.text})
    except Exception:
        pass
        
    # Intelligent local fallback — answers any question with full context awareness
    query_lower = query.lower()
    response_md = ""
    
    app_name = application.get('name', 'this application') if application else 'this application'
    app_criticality = application.get('criticality', 'UNKNOWN') if application else 'UNKNOWN'
    chains = state.attack_chains_map.get(app_id, [])
    conflicts = state.license_conflicts_map.get(app_id, [])
    unmainted = state.unmaintained_map.get(app_id, [])
    
    # Business Impact / Criticality questions
    if any(kw in query_lower for kw in ["critical", "business impact", "why high", "why is this", "risk", "score", "dangerous"]):
        multipliers = {'CRITICAL': '1.5x', 'HIGH': '1.25x', 'MEDIUM': '1.0x', 'LOW': '0.7x'}
        mult_str = multipliers.get(app_criticality, '1.0x')
        response_md = f"### 🔴 Business Impact Analysis\n\n"
        response_md += f"**{app_name}** is labeled **{app_criticality}** criticality by your organization.\n\n"
        response_md += f"The **Risk Score** ({score.get('risk_score', 0)}/100) is calculated as:\n"
        response_md += f"- Technical Risk: **{score.get('technical_risk', 0)}/100** (60% Vuln + 25% License + 15% Maintenance)\n"
        response_md += f"- Criticality Multiplier: **{mult_str}** applied\n"
        response_md += f"- Internet Exposure: **{'Yes (+20%)' if application and application.get('internet_exposure') else 'No'}**\n\n"
        response_md += f"**Health Score:** {score.get('health_score', 0)}/100 (higher is better). **Technical Risk:** {score.get('technical_risk', 0)}/100."
        
    # CVE / Vulnerability questions
    elif any(kw in query_lower for kw in ["cve", "vuln", "exploit", "log4", "spring4", "attack", "patch", "fix", "upgrade"]):
        response_md = f"### ⚡ Vulnerability Analysis\n\n"
        if chains:
            critical_chains = [c for c in chains if c.get('severity') == 'CRITICAL']
            high_chains = [c for c in chains if c.get('severity') == 'HIGH']
            response_md += f"**{app_name}** has **{len(chains)} CVE attack paths** ({len(critical_chains)} Critical, {len(high_chains)} High).\n\n"
            if critical_chains:
                worst = critical_chains[0]
                response_md += f"**Worst CVE:** `{worst['cve_id']}` (CVSS **{worst['cvss']}**) in `{worst['vulnerable_lib']} v{worst['version']}`\n"
                response_md += f"**Attack Path:** `{worst['path_str']}`\n"
                response_md += f"**Impact:** {worst['description']}\n"
                if worst.get('patch_available'):
                    response_md += f"\n✅ **Patch Available:** Upgrade to `{worst['vulnerable_lib']} v{worst['patch_version']}`"
                else:
                    response_md += f"\n⚠️ **No official patch.** Consider WAF rules or library replacement."
            elif chains:
                worst = chains[0]
                response_md += f"**Highest CVE:** `{worst['cve_id']}` (CVSS **{worst['cvss']}**) in `{worst['vulnerable_lib']}`\n"
                response_md += f"**Impact:** {worst['description']}"
        else:
            response_md += f"✅ **No CVE attack paths detected** for {app_name}.\n"
            response_md += "This application has no library versions matching the vulnerability database."

    # License / Legal / GPL questions
    elif any(kw in query_lower for kw in ["gpl", "license", "legal", "copyleft", "open source", "copyright", "oss"]):
        response_md = f"### ⚖️ License & Legal Analysis\n\n"
        if conflicts:
            response_md += f"Found **{len(conflicts)} license conflicts** in **{app_name}**:\n\n"
            for c in conflicts[:5]:
                response_md += f"- **{c['library']} v{c['version']}** → `{c.get('license', 'UNKNOWN')}` (Risk: {c.get('lic_risk')} at depth {c.get('depth')})\n"
            response_md += "\n**Risk:** GPL/AGPL copyleft requires open-sourcing the entire proprietary codebase upon distribution.\n"
            response_md += "**Remediation:** Replace with MIT/Apache-2.0 alternatives or obtain a commercial license."
        else:
            response_md += f"✅ No critical license conflicts detected in {app_name}.\n"
            response_md += "All dependencies use permissive licenses compatible with proprietary software."

    # Maintenance / Unmaintained questions
    elif any(kw in query_lower for kw in ["unmaintained", "old", "outdated", "deprecated", "maintenance", "update", "age"]):
        response_md = f"### 🔧 Maintenance Risk Analysis\n\n"
        if unmainted:
            response_md += f"**{app_name}** has **{len(unmainted)} unmaintained libraries** (last updated >2 years ago):\n\n"
            for lib in unmainted[:5]:
                yrs = lib.get('age_days', 0) // 365
                response_md += f"- **{lib['library']} v{lib['version']}** — Last updated: `{lib['last_updated']}` ({yrs} years ago)\n"
            response_md += "\n**Risk:** Unmaintained libraries accumulate unpatched CVEs and receive no security updates.\n"
            response_md += "**Remediation:** Plan migration to actively maintained alternatives in next quarter."
        else:
            response_md += f"✅ All libraries in {app_name} are actively maintained (updated within 2 years)."

    # Remediation / Fix / Reduce risk questions
    elif any(kw in query_lower for kw in ["remediat", "reduce", "fix", "how to", "what should", "priorit", "first", "action", "step"]):
        response_md = f"### 🎯 Top Remediation Priorities\n\n"
        critical_chains = [c for c in chains if c.get('severity') == 'CRITICAL']
        high_chains = [c for c in chains if c.get('severity') == 'HIGH']
        if critical_chains:
            response_md += f"**P0 (Immediate):** Patch these {len(critical_chains)} Critical CVEs:\n"
            for c in critical_chains[:3]:
                response_md += f"1. Upgrade `{c['vulnerable_lib']}` → v{c.get('patch_version','latest')} (fixes {c['cve_id']}, CVSS {c['cvss']})\n"
        if high_chains:
            response_md += f"\n**P1 (This Sprint):** Address {len(high_chains)} High severity CVEs:\n"
            for c in high_chains[:2]:
                response_md += f"- Upgrade `{c['vulnerable_lib']}` → v{c.get('patch_version','latest')} (fixes {c['cve_id']})\n"
        if conflicts:
            response_md += f"\n**P1 (Legal):** Resolve {len(conflicts)} license conflicts.\n"
        if unmainted:
            response_md += f"\n**P2 (Next Quarter):** Replace {len(unmainted)} unmaintained libraries.\n"
        if not chains and not conflicts and not unmainted:
            response_md += f"✅ {app_name} is in good health. Continue regular monthly dependency audits."

    # Compliance questions
    elif any(kw in query_lower for kw in ["compliance", "owasp", "nist", "pci", "soc2", "gdpr", "regulation", "standard", "framework"]):
        response_md = f"### 📋 Compliance Status for {app_name}\n\n"
        has_critical_cves = any(c.get('severity') == 'CRITICAL' for c in chains)
        response_md += f"| Framework | Control | Status |\n|---|---|---|\n"
        response_md += f"| OWASP | A06:2021 Vulnerable Components | {'❌ FAIL' if chains else '✅ PASS'} |\n"
        response_md += f"| NIST SP 800-53 | CM-8 Component Inventory | {'❌ FAIL' if has_critical_cves else '✅ PASS'} |\n"
        response_md += f"| EO 14028 | SBOM Requirement | ✅ PASS |\n"
        response_md += f"| OpenSSF | Scorecard Maintained | {'⚠️ WARN' if unmainted else '✅ PASS'} |\n"
        response_md += f"| Legal/IP | License Compliance | {'⚠️ WARN' if conflicts else '✅ PASS'} |\n"
        if has_critical_cves:
            response_md += f"\n⚠️ **Action Required:** Critical CVEs must be patched to regain OWASP/NIST compliance."

    # SBOM questions
    elif any(kw in query_lower for kw in ["sbom", "bill of material", "software composition", "dependency", "dependencies", "libraries"]):
        response_md = f"### 📦 SBOM Analysis for {app_name}\n\n"
        app_deps = [d for d in state.deps if d.get('app_id') == app_id]
        response_md += f"**{app_name}** has **{len(app_deps)} dependencies** in its SBOM.\n\n"
        direct_deps = [d for d in app_deps if d.get('dependency_type') == 'direct']
        trans_deps = [d for d in app_deps if d.get('dependency_type') == 'transitive']
        response_md += f"- Direct dependencies: **{len(direct_deps)}**\n"
        response_md += f"- Transitive dependencies: **{len(trans_deps)}**\n"
        response_md += f"- Dependencies with CVEs: **{len(chains)}**\n"
        response_md += f"- License conflicts: **{len(conflicts)}**\n"
        response_md += f"- Unmaintained: **{len(unmainted)}**\n"

    # General/unknown questions — provide full context summary
    else:
        response_md = f"### 🧠 Security Copilot — {app_name}\n\n"
        response_md += f"**Current Status:** Risk Score **{score.get('risk_score', 0)}/100** [{score.get('risk_band', 'N/A')}] · Health **{score.get('health_score', 0)}/100**\n\n"
        response_md += f"**Findings Summary:**\n"
        response_md += f"- ⚡ CVE Paths: **{len(chains)}** ({sum(1 for c in chains if c.get('severity')=='CRITICAL')} Critical)\n"
        response_md += f"- ⚖️ License Conflicts: **{len(conflicts)}**\n"
        response_md += f"- 🔧 Unmaintained Libs: **{len(unmainted)}**\n"
        response_md += f"- 🏢 App Criticality: **{app_criticality}** | Internet Exposed: **{'Yes' if application and application.get('internet_exposure') else 'No'}**\n\n"
        response_md += f"You asked: *\"{query}\"*\n\n"
        if any(kw in query_lower for kw in ["hello", "hi", "hey", "what can", "help"]):
            response_md = f"👋 Hello! I'm your **Security Copilot** for **{app_name}**.\n\nI can answer questions about:\n- CVE vulnerabilities and attack paths\n- License conflicts and legal risks\n- Unmaintained dependencies\n- Compliance status (OWASP, NIST, EO14028)\n- Risk score calculations\n- How to remediate findings\n- SBOM analysis\n\nAsk me anything!"
        else:
            response_md += f"Try asking: *Why is this risky?*, *Show CVEs*, *How to reduce risk?*, *License issues?*"
        
    return jsonify({"response": response_md})


@app.route("/api/metrics/trends")
def api_trends():
    """Historical timeline trends (mocked backward from current state)"""
    curr = state.portfolio
    
    # Generate realistic historical data based on current metrics
    def mock_past(days_ago):
        fuzz = 1.0 + (days_ago * 0.02) # Risk was higher in the past
        return {
            "date": (__import__('datetime').datetime.now() - __import__('datetime').timedelta(days=days_ago)).strftime('%Y-%m-%d'),
            "avg_risk": min(100, round(curr.get("avg_risk", 0) * fuzz, 1)),
            "security_health": max(0, round(100 - (curr.get("avg_risk", 0) * fuzz), 1)),
            "total_cves": int(curr.get("total_cves", 0) * (fuzz + 0.1)),
            "resolved_cves": int(days_ago * 3) # Mock resolved count
        }
        
    timeline = [
        mock_past(30),
        mock_past(7),
        mock_past(1),
        {
            "date": "Today",
            "avg_risk": curr.get("avg_risk", 0),
            "security_health": round(100 - curr.get("avg_risk", 0), 1),
            "total_cves": curr.get("total_cves", 0),
            "resolved_cves": 0
        }
    ]
    return jsonify(timeline)


if __name__ == "__main__":
    app.run(debug=False, use_reloader=False, port=5000)
