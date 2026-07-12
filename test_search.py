import requests
tests = ['log4j', 'log4j-core', 'jackson', 'spring', 'CVE-2017', 'commons', 'flask', 'requests', 'struts']
for q in tests:
    r = requests.get(f'http://127.0.0.1:5000/api/search?q={q}')
    results = r.json()
    if results:
        lib = results[0].get('library','')
        sev = results[0].get('severity','')
        print(f"[{q}]: {len(results)} results - first: {lib} ({sev})")
    else:
        print(f"[{q}]: 0 results")
