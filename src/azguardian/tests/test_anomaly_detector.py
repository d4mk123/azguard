from pathlib import Path

from azguardian.collector import collect_from_file
from azguardian.anomaly_detector import (
    detect_shadowing,
    detect_redundancy,
    run_anomaly_detection,
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
