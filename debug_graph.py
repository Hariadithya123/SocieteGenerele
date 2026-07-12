import sys
sys.path.insert(0, '.')
from engine.data_loader import DataLoader
from engine.graph_builder import build_full_graph, find_attack_chains
import networkx as nx

loader = DataLoader("official")
apps, vuln_list, vuln_lookup, lic_rules, deps, labels, transitive = loader.load_all()

print(f"Apps loaded: {len(apps)}")
print(f"Deps loaded: {len(deps)}")
print(f"CVEs in lookup: {len(vuln_lookup)}")

G = build_full_graph(apps, deps, vuln_lookup, lic_rules, transitive)
print(f"Graph nodes: {len(G.nodes())}")
print(f"Graph edges: {len(G.edges())}")

# Check APP-001
app_id = "APP-001"
print(f"\nAPP-001 direct neighbors: {list(G.successors(app_id))[:5]}")
print(f"APP-001 descendants: {len(nx.descendants(G, app_id))}")

chains = find_attack_chains(G, app_id)
print(f"APP-001 attack chains: {len(chains)}")

# Check if jackson-databind 2.9.5 is in graph and reachable from APP-001
node_key = "jackson-databind@2.9.5"
print(f"\n'{node_key}' in graph: {node_key in G.nodes()}")
if node_key in G.nodes():
    ndata = G.nodes[node_key]
    print(f"  cve_ids: {ndata.get('cve_ids')}")
    try:
        path = nx.shortest_path(G, app_id, node_key)
        print(f"  path from APP-001: {path}")
    except Exception as e:
        print(f"  no path: {e}")
