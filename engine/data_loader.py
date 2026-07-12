"""
Data Loader — Parses all sample data files into memory
"""
import json
import csv
import os
from datetime import datetime

class DataLoader:
    def __init__(self, dataset_name="official"):
        self.dataset_name = dataset_name
        # Datasets are stored in /datasets/<dataset_name>
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "datasets", dataset_name)
    
    def load_applications(self):
        apps = []
        try:
            with open(os.path.join(self.data_dir, "applications.json"), encoding="utf-8") as f:
                raw_apps = json.load(f)
                for raw in raw_apps:
                    app = {
                        "app_id": raw.get("app_id") or raw.get("application_id"),
                        "name": raw.get("name") or raw.get("application_name"),
                        "type": raw.get("type") or raw.get("license_model", "proprietary"),
                        "criticality": raw.get("criticality", "MEDIUM"),
                        "team": raw.get("team") or raw.get("department", "Unknown"),
                        "internet_facing": raw.get("internet_facing", raw.get("deployment") == "cloud"),
                        "language": raw.get("language", "Unknown"),
                        "business_owner": raw.get("business_owner", "Unknown")
                    }
                    app["internet_exposure"] = app.get("internet_facing", False) and app.get("criticality") in ["CRITICAL", "HIGH"]
                    apps.append(app)
        except Exception:
            pass
        return apps

    def load_vulnerability_db(self):
        data = []
        try:
            with open(os.path.join(self.data_dir, "vulnerability_db.json"), encoding="utf-8") as f:
                raw = json.load(f)
            # Normalize schema differences between datasets
            for entry in raw:
                # cvss_score -> cvss
                if "cvss" not in entry and "cvss_score" in entry:
                    entry["cvss"] = entry["cvss_score"]
                # fixed_version -> patch_version
                if "patch_version" not in entry and "fixed_version" in entry:
                    entry["patch_version"] = entry.get("fixed_version") or ""
                # Ensure patch_version is a string
                if entry.get("patch_version") is None:
                    entry["patch_version"] = ""
                # Ensure required fields
                if "affected_versions" not in entry:
                    entry["affected_versions"] = []
                data = raw
        except Exception:
            pass
        lookup = {}
        for entry in data:
            lib = entry.get("library", "unknown")
            if lib not in lookup:
                lookup[lib] = []
            lookup[lib].append(entry)
        return data, lookup

    def load_license_rules(self):
        try:
            with open(os.path.join(self.data_dir, "license_rules.json"), encoding="utf-8") as f:
                data = json.load(f)
            return {r.get("license", "UNKNOWN"): r for r in data}
        except Exception:
            return {}

    def load_dependencies(self):
        rows = []
        try:
            with open(os.path.join(self.data_dir, "sbom_dependencies.csv"), newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Normalize app_id field (application_id or app_id)
                    app_id = row.get("app_id") or row.get("application_id")
                    # Normalize library name (library_name or library)
                    library_name = row.get("library_name") or row.get("library")
                    # Normalize license (license_type or license)
                    license_type = row.get("license_type") or row.get("license", "UNKNOWN")
                    # Determine depth
                    depth_raw = row.get("depth")
                    dep_type = row.get("dependency_type", "direct")
                    if depth_raw and str(depth_raw).strip().isdigit():
                        depth = int(depth_raw)
                    else:
                        depth = 1 if dep_type == "direct" else 2
                    dep = {
                        "dep_id": row.get("dep_id"),
                        "app_id": app_id,
                        "library_name": library_name,
                        "version": row.get("version"),
                        "license_type": license_type,
                        "dependency_type": dep_type,
                        "last_updated": row.get("last_updated") or "2020-01-01",
                        "parent_library": row.get("parent_library", ""),
                        "depth": depth
                    }
                    rows.append(dep)
        except Exception as e:
            print(f"[DataLoader] Error loading dependencies: {e}")
        return rows

    def load_transitive_deps(self):
        # Maps parent_library -> list of child_libraries for graph builder
        try:
            with open(os.path.join(self.data_dir, "transitive_dependencies.json"), encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def load_labels(self):
        rows = []
        try:
            with open(os.path.join(self.data_dir, "dependency_labels.csv"), newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Support old and new schema
                    row["is_vulnerable"] = row.get("is_vulnerable") == "True" or row.get("is_risky") == "True"
                    row["is_license_issue"] = row.get("is_license_issue") == "True"
                    row["is_unmaintained"] = row.get("is_unmaintained") == "True" or row.get("risk_type") == "UNMAINTAINED"
                    rows.append(row)
        except Exception:
            pass
        return rows

    def load_all(self):
        apps = self.load_applications()
        vuln_list, vuln_lookup = self.load_vulnerability_db()
        lic_rules = self.load_license_rules()
        deps = self.load_dependencies()
        labels = self.load_labels()
        transitive = self.load_transitive_deps()
        return apps, vuln_list, vuln_lookup, lic_rules, deps, labels, transitive

def days_since(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
        return (datetime.now() - d).days
    except Exception:
        return 0
