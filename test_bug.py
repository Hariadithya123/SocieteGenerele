import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.data_loader import load_all
from engine.graph_builder import build_full_graph, _match_cves

apps, vuln_list, vuln_lookup, lic_rules, deps, labels = load_all()

# Find log4j-core version 2.17.1 in deps
for d in deps:
    if d.get("library") == "log4j-core":
        print(f"Found {d['library']} {d['version']} in app {d['app_id']}")

hits = _match_cves("log4j-core", "2.17.1", vuln_lookup)
print("Hits for 2.17.1:", len(hits))

hits = _match_cves("log4j-core", "2.14.1", vuln_lookup)
print("Hits for 2.14.1:", len(hits))

