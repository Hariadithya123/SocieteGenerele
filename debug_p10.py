import json, csv

data = json.load(open('datasets/problem10/vulnerability_db.json'))
print('Fields in vuln:', list(data[0].keys()))

with open('datasets/problem10/sbom_dependencies.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    deps = list(reader)

vuln_lookup = {}
for entry in data:
    lib = entry.get('library', 'unknown')
    if lib not in vuln_lookup:
        vuln_lookup[lib] = []
    vuln_lookup[lib].append(entry)

for dep in deps[:30]:
    lib = dep.get('library') or dep.get('library_name')
    ver = dep.get('version')
    candidates = vuln_lookup.get(lib, [])
    if candidates:
        aff = candidates[0].get('affected_versions', [])
        print(f'Lib {lib} v{ver} -> candidates:{len(candidates)} affected:{aff}')
