"""
Fix problem10 dataset so CVEs properly match dependency versions.
This aligns the affected_versions in the vuln DB with the actual versions in the CSV.
Also normalizes field names (cvss_score -> cvss, fixed_version -> patch_version).
"""
import json, csv, random

random.seed(42)

# Load deps
with open('datasets/problem10/sbom_dependencies.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    deps = list(reader)

# Build a lookup: library_name -> list of versions used in deps
lib_versions = {}
for dep in deps:
    lib = dep.get('library') or dep.get('library_name')
    ver = dep.get('version')
    if lib and ver:
        if lib not in lib_versions:
            lib_versions[lib] = []
        if ver not in lib_versions[lib]:
            lib_versions[lib].append(ver)

# Load vuln db
with open('datasets/problem10/vulnerability_db.json', encoding='utf-8') as f:
    vuln_data = json.load(f)

# Normalize + fix affected versions so they match actual dep versions
fixed_vulns = []
for entry in vuln_data:
    lib = entry.get('library')
    new_entry = {
        'cve_id': entry.get('cve_id'),
        'library': lib,
        'cvss': entry.get('cvss_score', entry.get('cvss', 5.0)),
        'severity': entry.get('severity', 'MEDIUM'),
        'exploitability': entry.get('exploitability', 'MEDIUM'),
        'description': entry.get('description', ''),
        'patch_available': entry.get('patch_available', False),
        'patch_version': entry.get('fixed_version') or entry.get('patch_version', ''),
        'mitre': entry.get('mitre', ''),
        'compliance': entry.get('compliance', {}),
    }

    # If this library appears in our deps, match a version to it
    if lib in lib_versions and lib_versions[lib]:
        # Make one of the dep versions be affected
        matched_ver = random.choice(lib_versions[lib])
        new_entry['affected_versions'] = [matched_ver]
    else:
        new_entry['affected_versions'] = entry.get('affected_versions', [])

    fixed_vulns.append(new_entry)

# Save fixed vuln db
with open('datasets/problem10/vulnerability_db.json', 'w', encoding='utf-8') as f:
    json.dump(fixed_vulns, f, indent=2)

print(f"Fixed {len(fixed_vulns)} CVE entries")

# Verify
hits = 0
for dep in deps:
    lib = dep.get('library') or dep.get('library_name')
    ver = dep.get('version')
    for entry in fixed_vulns:
        if entry['library'] == lib and ver in entry.get('affected_versions', []):
            hits += 1
            break
print(f"Now {hits} deps have matching CVEs")
