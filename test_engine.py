import os
import sys

# Ensure engine modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.graph_builder import _version_range_match
from engine.risk_scorer import score_application

def test_version_matching():
    print("Testing Version Matching...")
    
    # CVE-2021-44228 for Log4j affects "2.14.1" but not "1.7.36" or "2.17.1"
    affected = ["2.14.1", "2.0"]
    
    assert not _version_range_match("1.7.36", affected), "1.7.36 should NOT match"
    assert _version_range_match("2.14.1", affected), "2.14.1 SHOULD match"
    assert not _version_range_match("2.17.1", affected), "2.17.1 should NOT match"
    
    print("✅ Version matching tests passed.")

def test_scoring_saturation():
    print("Testing Asymptotic Scoring (No saturation)...")
    
    # We will simulate high vulnerabilities
    chains = [
        {"cvss": 10.0, "severity": "CRITICAL", "depth": 1, "patch_available": False, "cve_id": f"CVE-100{i}", "vulnerable_lib": f"lib{i}"}
        for i in range(10) # 10 critical vulns
    ]
    
    # Should be high, but not exactly 100
    app = {"app_id": "TEST", "name": "Test App", "criticality": "CRITICAL", "team": "Sec"}
    score = score_application(app, chains, [], [])
    
    print(f"Computed Score with 10 Critical Vulns: {score['risk_score']}")
    assert score['risk_score'] < 100.0, "Score hit exactly 100.0 (saturated!)"
    assert score['risk_score'] > 85.0, "Score too low for 10 critical vulns"
    
    print("✅ Scoring saturation tests passed.")

if __name__ == "__main__":
    test_version_matching()
    test_scoring_saturation()
    print("✅ All tests passed!")
