import os
import sys
import hashlib
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.data_loader import load_dependencies, DATA_DIR, load_vulnerability_db
from engine.graph_builder import _match_cves

def get_sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"

def run_trace():
    print("\n--- EXECUTION TRACE ---")
    csv_path = os.path.join(DATA_DIR, "sbom_dependencies.csv")
    print(f"1. Absolute path: {csv_path}")
    
    mtime = os.path.getmtime(csv_path) if os.path.exists(csv_path) else 0
    print(f"2. File modification timestamp: {mtime} ({time.ctime(mtime) if mtime else 'N/A'})")
    
    print(f"3. SHA256 Hash: {get_sha256(csv_path)}")
    
    deps = load_dependencies()
    log4j_rows = [d for d in deps if d.get('library_name') == 'log4j-core']
    print(f"4. log4j-core rows loaded: {json.dumps(log4j_rows, indent=2)}")
    
    version = log4j_rows[0]['version'] if log4j_rows else "NONE"
    print(f"5. Version in memory: {version}")
    
    _, vuln_lookup = load_vulnerability_db()
    hits = _match_cves("log4j-core", version, vuln_lookup)
    
    print(f"6. Vulnerability Engine Matches for {version}: {len(hits)} hits")
    for hit in hits:
        print(f"   -> Detected: {hit['cve_id']}")
    print("-----------------------\n")

if __name__ == "__main__":
    run_trace()
