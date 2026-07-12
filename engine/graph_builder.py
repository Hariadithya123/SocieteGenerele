"""
Graph Builder — Builds NetworkX dependency graphs per application
Supports full transitive chain resolution and CVE attack-path discovery
"""
import networkx as nx
from packaging.version import parse as parse_version
from .data_loader import days_since

UNMAINTAINED_DAYS = 730  # 2 years


def build_full_graph(apps, deps, vuln_lookup, lic_rules, transitive=None):
    """
    Build a single directed multi-app dependency graph.
    Node types: 'app' | 'library'
    Edge attrs: dep_type, depth, app_id
    """
    if transitive is None:
        transitive = []
        
    # Build lookup for transitive JSON if provided
    trans_lookup = {}
    for t in transitive:
        app_id = t.get("application_id")
        child_key = f"{t.get('child_library')}@{t.get('child_version')}"
        parent_key = f"{t.get('parent_library')}@{t.get('parent_version')}"
        key = (app_id, child_key)
        if key not in trans_lookup:
            trans_lookup[key] = []
        trans_lookup[key].append(parent_key)

    G = nx.DiGraph()

    # Add application nodes
    for app in apps:
        G.add_node(app["app_id"],
                   node_type="app",
                   name=app["name"],
                   criticality=app["criticality"],
                   team=app["team"],
                   app_type=app["type"])

    # Add library nodes and edges
    for dep in deps:
        lib_key = f"{dep['library_name']}@{dep['version']}"

        # Resolve CVEs for this library version
        cve_hits = _match_cves(dep["library_name"], dep["version"], vuln_lookup)
        max_cvss  = max((c["cvss"] for c in cve_hits), default=0.0)
        cve_ids   = [c["cve_id"] for c in cve_hits]

        # Resolve license info
        lic_info  = lic_rules.get(dep["license_type"], {})
        is_copyleft = lic_info.get("copyleft", False)
        lic_risk    = lic_info.get("risk_level", "UNKNOWN")

        # Maintenance status
        age_days      = days_since(dep["last_updated"])
        is_unmaintained = age_days > UNMAINTAINED_DAYS

        # Add / update library node
        if lib_key not in G.nodes:
            G.add_node(lib_key,
                       node_type="library",
                       library_name=dep["library_name"],
                       version=dep["version"],
                       license_type=dep["license_type"],
                       cve_hits=cve_hits,
                       cve_ids=cve_ids,
                       max_cvss=max_cvss,
                       is_copyleft=is_copyleft,
                       lic_risk=lic_risk,
                       last_updated=dep["last_updated"],
                       age_days=age_days,
                       is_unmaintained=is_unmaintained)

        # Determine edge sources
        if trans_lookup:
            parents = trans_lookup.get((dep["app_id"], lib_key), [])
            if not parents:
                # Direct
                G.add_edge(dep["app_id"], lib_key, dep_type=dep["dependency_type"], depth=dep.get("depth", 1), app_id=dep["app_id"])
            else:
                for parent_key in parents:
                    G.add_edge(parent_key, lib_key, dep_type="transitive", depth=dep.get("depth", 2), app_id=dep["app_id"])
        else:
            if dep["dependency_type"] == "direct" or not dep.get("parent_library"):
                src = dep["app_id"]
            else:
                parent_match = next(
                    (f"{d['library_name']}@{d['version']}"
                     for d in deps
                     if d["library_name"] == dep["parent_library"] and d["app_id"] == dep["app_id"]),
                    dep["app_id"]
                )
                src = parent_match

            G.add_edge(src, lib_key,
                       dep_type=dep["dependency_type"],
                       depth=dep.get("depth", 1),
                       app_id=dep["app_id"])

    # Process transitive dependencies list to ensure all transitive nodes and edges are added
    if transitive:
        for t in transitive:
            app_id = t.get("application_id")
            if not app_id:
                continue
            parent_lib = t.get("parent_library")
            parent_ver = t.get("parent_version")
            child_lib = t.get("child_library")
            child_ver = t.get("child_version")
            
            parent_key = f"{parent_lib}@{parent_ver}"
            child_key = f"{child_lib}@{child_ver}"
            
            # Ensure parent node exists
            if parent_key not in G.nodes:
                lic_type = "UNKNOWN"
                last_updated = "2025-01-01"
                for d in deps:
                    if d.get("library_name") == parent_lib:
                        lic_type = d.get("license_type", "UNKNOWN")
                        last_updated = d.get("last_updated", "2025-01-01")
                        break
                cve_hits = _match_cves(parent_lib, parent_ver, vuln_lookup)
                max_cvss  = max((c["cvss"] for c in cve_hits), default=0.0)
                cve_ids   = [c["cve_id"] for c in cve_hits]
                lic_info  = lic_rules.get(lic_type, {})
                is_copyleft = lic_info.get("copyleft", False)
                lic_risk    = lic_info.get("risk_level", "UNKNOWN")
                age_days      = days_since(last_updated)
                is_unmaintained = age_days > UNMAINTAINED_DAYS
                
                G.add_node(parent_key,
                           node_type="library",
                           library_name=parent_lib,
                           version=parent_ver,
                           license_type=lic_type,
                           cve_hits=cve_hits,
                           cve_ids=cve_ids,
                           max_cvss=max_cvss,
                           is_copyleft=is_copyleft,
                           lic_risk=lic_risk,
                           last_updated=last_updated,
                           age_days=age_days,
                           is_unmaintained=is_unmaintained)
            
            # Ensure child node exists
            if child_key not in G.nodes:
                lic_type = "UNKNOWN"
                last_updated = "2025-01-01"
                for d in deps:
                    if d.get("library_name") == child_lib:
                        lic_type = d.get("license_type", "UNKNOWN")
                        last_updated = d.get("last_updated", "2025-01-01")
                        break
                cve_hits = _match_cves(child_lib, child_ver, vuln_lookup)
                max_cvss  = max((c["cvss"] for c in cve_hits), default=0.0)
                cve_ids   = [c["cve_id"] for c in cve_hits]
                lic_info  = lic_rules.get(lic_type, {})
                is_copyleft = lic_info.get("copyleft", False)
                lic_risk    = lic_info.get("risk_level", "UNKNOWN")
                age_days      = days_since(last_updated)
                is_unmaintained = age_days > UNMAINTAINED_DAYS
                
                G.add_node(child_key,
                           node_type="library",
                           library_name=child_lib,
                           version=child_ver,
                           license_type=lic_type,
                           cve_hits=cve_hits,
                           cve_ids=cve_ids,
                           max_cvss=max_cvss,
                           is_copyleft=is_copyleft,
                           lic_risk=lic_risk,
                           last_updated=last_updated,
                           age_days=age_days,
                           is_unmaintained=is_unmaintained)
            
            # Add edge from parent to child
            G.add_edge(parent_key, child_key, dep_type="transitive", depth=2, app_id=app_id)

    return G


def get_app_subgraph(G, app_id):
    """Return subgraph of all nodes reachable from a given app."""
    reachable = nx.descendants(G, app_id)
    reachable.add(app_id)
    return G.subgraph(reachable).copy()


def find_attack_chains(G, app_id):
    """
    BFS from app node to find all paths that lead to a vulnerable library.
    Returns list of dicts with path, cve, cvss, severity.
    """
    chains = []
    try:
        for node in nx.descendants(G, app_id):
            ndata = G.nodes.get(node, {})
            if ndata.get("node_type") != "library":
                continue
            if not ndata.get("cve_ids"):
                continue
            # Find shortest path from app to this vulnerable node (O(V+E) instead of O(V!))
            try:
                path = nx.shortest_path(G, app_id, node)
                for cve in ndata["cve_hits"]:
                    chains.append({
                        "path": path,
                        "path_str": " → ".join(
                            G.nodes[n].get("library_name", G.nodes[n].get("name", n))
                            for n in path
                        ),
                            "vulnerable_lib": ndata["library_name"],
                            "version": ndata["version"],
                            "cve_id": cve["cve_id"],
                            "cvss": cve["cvss"],
                            "severity": cve["severity"],
                            "depth": len(path) - 1,
                            "exploitability": cve.get("exploitability", "MEDIUM"),
                            "description": cve.get("description", ""),
                            "patch_available": cve.get("patch_available", False),
                            "patch_version": cve.get("patch_version", ""),
                            "mitre": cve.get("mitre", ""),
                            "compliance": cve.get("compliance", {})
                        })
            except nx.NetworkXNoPath:
                continue
    except nx.NodeNotFound:
        pass
    # Deduplicate by cve_id + depth
    seen = set()
    unique = []
    for c in chains:
        key = (c["cve_id"], c["depth"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return sorted(unique, key=lambda x: x["cvss"], reverse=True)


def find_license_conflicts(G, app_id, app_type="proprietary"):
    """Find all license conflicts for an app."""
    conflicts = []
    for node in nx.descendants(G, app_id):
        ndata = G.nodes.get(node, {})
        if ndata.get("node_type") != "library":
            continue
        lic = ndata.get("license_type", "")
        is_copyleft = ndata.get("is_copyleft", False)
        lic_risk = ndata.get("lic_risk", "LOW")
        if app_type == "proprietary" and is_copyleft and lic_risk in ["CRITICAL", "HIGH"]:
            # Find depth
            try:
                paths = list(nx.all_simple_paths(G, app_id, node, cutoff=5))
                depth = min(len(p) - 1 for p in paths) if paths else 1
            except Exception:
                depth = 1
            conflicts.append({
                "library": ndata["library_name"],
                "version": ndata["version"],
                "license": lic,
                "lic_risk": lic_risk,
                "depth": depth,
                "dep_type": "direct" if depth == 1 else "transitive",
                "description": f"{ndata['library_name']} uses {lic} — viral copyleft. Distributing {app_id} may require open-sourcing entire codebase."
            })
    return sorted(conflicts, key=lambda x: (0 if x["lic_risk"] == "CRITICAL" else 1, x["depth"]))


def find_unmaintained(G, app_id):
    """Find all unmaintained libraries for an app."""
    result = []
    for node in nx.descendants(G, app_id):
        ndata = G.nodes.get(node, {})
        if ndata.get("node_type") != "library":
            continue
        if ndata.get("is_unmaintained"):
            try:
                paths = list(nx.all_simple_paths(G, app_id, node, cutoff=5))
                depth = min(len(p) - 1 for p in paths) if paths else 1
            except Exception:
                depth = 1
            result.append({
                "library": ndata["library_name"],
                "version": ndata["version"],
                "last_updated": ndata["last_updated"],
                "age_days": ndata["age_days"],
                "license": ndata.get("license_type", ""),
                "depth": depth,
                "dep_type": "direct" if depth == 1 else "transitive",
            })
    return sorted(result, key=lambda x: x["age_days"], reverse=True)


def _match_cves(lib_name, version, vuln_lookup):
    """Match a library+version against the vulnerability database."""
    candidates = vuln_lookup.get(lib_name, [])
    hits = []
    for entry in candidates:
        affected = entry.get("affected_versions", [])
        if version in affected or _version_range_match(version, affected):
            ec = entry.copy()
            if "cvss_score" in ec and "cvss" not in ec:
                ec["cvss"] = ec["cvss_score"]
            hits.append(ec)
    return hits


def _version_range_match(version, affected_versions):
    """
    Robust version match using packaging.version.
    Since affected_versions in DB is an explicit list, we do exact match.
    If ranges (e.g. '< 2.15.0') were used, we would evaluate them here.
    """
    try:
        v_obj = parse_version(version)
        for av in affected_versions:
            # If the version string exactly matches, or if it matches when parsed
            if version == av or v_obj == parse_version(av):
                return True
    except Exception:
        pass
    return False


def graph_to_cytoscape(G, app_id):
    """Convert subgraph to Cytoscape.js-compatible JSON for frontend rendering."""
    sg = get_app_subgraph(G, app_id)
    elements = []

    for node in sg.nodes():
        ndata = sg.nodes[node]
        node_type = ndata.get("node_type", "library")
        has_cve = bool(ndata.get("cve_ids"))
        is_unmaintained = ndata.get("is_unmaintained", False)
        is_copyleft = ndata.get("is_copyleft", False)
        max_cvss = ndata.get("max_cvss", 0)

        if node_type == "app":
            classes = "app-node"
            label = ndata.get("name", node)
        elif has_cve:
            classes = f"vuln-node cvss-{'critical' if max_cvss >= 9 else 'high' if max_cvss >= 7 else 'medium'}"
            label = f"{ndata.get('library_name', node)}\n{ndata.get('version', '')}"
        elif is_copyleft:
            classes = "license-node"
            label = f"{ndata.get('library_name', node)}\n({ndata.get('license_type', '')})"
        elif is_unmaintained:
            classes = "unmaintained-node"
            label = f"{ndata.get('library_name', node)}\n⚠ Unmaintained"
        else:
            classes = "clean-node"
            label = f"{ndata.get('library_name', node)}\n{ndata.get('version', '')}"

        elements.append({
            "data": {
                "id": node,
                "label": label,
                "node_type": node_type,
                "has_cve": has_cve,
                "max_cvss": max_cvss,
                "cve_ids": ndata.get("cve_ids", []),
                "license": ndata.get("license_type", ""),
                "last_updated": ndata.get("last_updated", ""),
                "is_unmaintained": is_unmaintained,
            },
            "classes": classes
        })

    for src, tgt, edata in sg.edges(data=True):
        dep_type = edata.get("dep_type", "direct")
        elements.append({
            "data": {
                "id": f"{src}__{tgt}",
                "source": src,
                "target": tgt,
                "dep_type": dep_type,
            },
            "classes": f"edge-{dep_type}"
        })

    return elements
