import os
import sys
import math

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from engine.data_loader import DataLoader
from engine.risk_scorer import score_all_applications

def test_normalization():
    print("Testing Normalization...")
    loader = DataLoader("official")
    apps, vuln_list, vuln_lookup, lic_rules, deps, labels, transitive = loader.load_all()
    
    from engine.graph_builder import build_full_graph, find_attack_chains, find_license_conflicts, find_unmaintained
    G = build_full_graph(apps, deps, vuln_lookup, lic_rules, transitive)
    
    attack_chains_map = {}
    license_conflicts_map = {}
    unmaintained_map = {}
    
    for application in apps:
        app_id = application["app_id"]
        attack_chains_map[app_id] = find_attack_chains(G, app_id)
        license_conflicts_map[app_id] = find_license_conflicts(G, app_id, application.get("type", "proprietary"))
        unmaintained_map[app_id] = find_unmaintained(G, app_id)
        
    scores = score_all_applications(apps, attack_chains_map, license_conflicts_map, unmaintained_map)
    
    print("\n--- Real Applications Distribution ---")
    for s in scores:
        print(f"App: {s['app_name']:<20} Raw: {s['raw_score']:<5} -> Normalized: {s['risk_score']:<5} | Band: {s['risk_band']}")
        
    # Check max score
    max_score = max(s['risk_score'] for s in scores)
    print(f"\nMax Normalized Score in Official Dataset: {max_score}")
    assert max_score <= 98.0, "Critical apps should rarely exceed 95 and never hit 100 unless mathematically extreme"
    
    # Check synthetic extremum
    extremes_raw = [0, 50, 100, 150, 200, 300, 500]
    print("\n--- Theoretical Distribution ---")
    for raw in extremes_raw:
        normalized = 100.0 * math.tanh(raw / 100.0)
        print(f"Raw: {raw:<5} -> Normalized: {normalized:.1f}")
        
    print("\nRegression tests passed successfully!")

if __name__ == "__main__":
    test_normalization()
