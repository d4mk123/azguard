from pathlib import Path

from azguard.collector import collect_from_file
from azguard.anomaly_detector import (
    detect_shadowing,
    detect_redundancy,
    run_anomaly_detection,
    detect_ml_anomalies,
)

FIXTURES_DIR = Path(__file__).parents[3] / "test-data"


def collect(fixture_name: str):
    return collect_from_file(FIXTURES_DIR / fixture_name)


def test_shadowed_rules_detected():
    nsgs = collect("shadowed-rules.json")
    results = run_anomaly_detection(nsgs)
    shadowed = [r for r in results if "shadowed" in r.evidence]
    rule_names = [r.rule_name for r in shadowed]
    assert "DenySSHFromSubnet" in rule_names
    assert "DenyRDPFromSubnet" in rule_names


def test_shadowing_opposite_access():
    nsgs = collect("shadowed-rules.json")
    results = detect_shadowing(nsgs[0])
    assert len(results) == 2
    for r in results:
        assert r.status == "fail"
        assert r.severity == "Medium"
        assert "shadowed" in r.evidence


def test_no_redundancy_in_shadowed_fixture():
    nsgs = collect("shadowed-rules.json")
    results = detect_redundancy(nsgs[0])
    assert len(results) == 0


def test_clean_nsg_no_anomalies():
    nsgs = collect("clean-nsg.json")
    results = run_anomaly_detection(nsgs)
    assert len(results) == 0


def test_empty_nsg_no_anomalies():
    nsgs = collect("empty-nsg.json")
    results = run_anomaly_detection(nsgs)
    assert len(results) == 0


# === ML-specific tests ===


def test_ml_skipped_for_small_nsg():
    """NSGs with fewer than 8 rules should skip ML detection"""
    nsgs = collect("shadowed-rules.json")
    results = detect_ml_anomalies(nsgs[0])
    assert len(results) == 0


def test_ml_skipped_for_empty_nsg():
    """Empty NSGs should skip ML detection"""
    nsgs = collect("empty-nsg.json")
    results = detect_ml_anomalies(nsgs[0])
    assert len(results) == 0


def test_ml_catches_weird_rule():
    """ML should detect a planted weird rule among normal rules"""
    nsgs = collect("one-weird-rule.json")
    results = detect_ml_anomalies(nsgs[0])
    rule_names = [r.rule_name for r in results]
    assert "Weird-UDP-All" in rule_names


def test_ml_catches_outlier_protocol():
    """ML should detect a rule with unusual protocol/port combo"""
    nsgs = collect("outlier-protocol.json")
    results = detect_ml_anomalies(nsgs[0])
    rule_names = [r.rule_name for r in results]
    assert "Strange-Deny" in rule_names


def test_ml_few_false_positives_on_normal_nsg():
    """Normal business NSG should have at most 2 ML flagged rules"""
    nsgs = collect("normal-business-nsg.json")
    results = detect_ml_anomalies(nsgs[0])
    assert len(results) <= 2


def test_ml_anomalies_have_explainability():
    """ML anomalies should include which features drove the score"""
    nsgs = collect("one-weird-rule.json")
    results = detect_ml_anomalies(nsgs[0])
    for r in results:
        assert "differ significantly" in r.evidence
        assert "Top reasons:" in r.evidence


def test_ml_detects_some_in_large_ruleset():
    """Large ruleset with planted violations should have at least 1 ML anomaly"""
    nsgs = collect("large-ruleset.json")
    results = detect_ml_anomalies(nsgs[0])
    assert len(results) >= 1


def test_ml_results_properly_formatted():
    """ML anomaly CheckResults should have correct fields"""
    nsgs = collect("one-weird-rule.json")
    results = detect_ml_anomalies(nsgs[0])
    for r in results:
        assert r.control_id == "ANOMALY"
        assert r.status == "fail"
        assert r.severity == "Medium"
        assert r.nsg_name == "one-weird-nsg"
        assert r.rule_name is not None
