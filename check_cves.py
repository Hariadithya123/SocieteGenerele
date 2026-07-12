import json, csv

vuln_data = json.load(open('datasets/official/vulnerability_db.json'))
vuln_lookup = {}
for entry in vuln_data:
    lib = entry.get('library', 'unknown')
    if lib not in vuln_lookup:
        vuln_lookup[lib] = []
    vuln_lookup[lib].append(entry)

with open('datasets/official/sbom_dependencies.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    deps = list(reader)

hits = 0
for dep in deps:
    lib = dep.get('library_name')
    ver = dep.get('version')
    candidates = vuln_lookup.get(lib, [])
    for entry in candidates:
        affected = entry.get('affected_versions', [])
        if ver in affected:
            cid = entry["cve_id"]
            print(f"  HIT: {lib} {ver} -> {cid}")
            hits += 1

print(f"Total hits: {hits}")
print(f"Total deps: {len(deps)}")
print(f"Total CVEs: {len(vuln_data)}")
