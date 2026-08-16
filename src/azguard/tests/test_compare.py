import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3] / "validation"))

from compare import compare, load_azguard, load_defender, render  # noqa: E402


def _azguard_finding(control_id, status, evidence="e"):
    return {
        "control_id": control_id,
        "status": status,
        "severity": "High",
        "nsg_name": "test-nsg",
        "rule_name": None,
        "evidence": evidence,
    }


def _defender_assessment(control_id, code):
    return {
        "id": "/subscriptions/x/providers/Microsoft.Security/assessments/abc",
        "display_name": control_id,
        "status": {"code": code, "cause": "", "description": ""},
        "control_id": control_id,
    }


def test_compare_match_pass_pass():
    az = [_azguard_finding("7.1", "pass")]
    df = [_defender_assessment("6.1.2", "Healthy")]
    result = compare(az, df)
    assert len(result["rows"]) == 1
    assert result["rows"][0]["match"] is True


def test_compare_match_fail_fail():
    az = [_azguard_finding("7.1", "fail")]
    df = [_defender_assessment("6.1.3", "NotHealthy")]
    result = compare(az, df)
    assert result["rows"][0]["match"] is True


def test_compare_mismatch_pass_fail():
    az = [_azguard_finding("7.1", "pass")]
    df = [_defender_assessment("6.1.2", "NotHealthy")]
    result = compare(az, df)
    assert result["rows"][0]["match"] is False


def test_compare_manual_always_match():
    az = [_azguard_finding("7.1", "manual")]
    df = [_defender_assessment("6.1.2", "Healthy")]
    result = compare(az, df)
    assert result["rows"][0]["match"] is True


def test_unmapped_azguard_collected():
    az = [_azguard_finding("7.11", "fail"), _azguard_finding("N/A", "fail")]
    result = compare(az, [])
    assert len(result["unmatched_azguard"]) == 2
    assert result["rows"] == []


def test_azguard_without_defender_equivalent_unmatched():
    az = [_azguard_finding("7.1", "fail")]
    result = compare(az, [])
    assert result["rows"] == []
    assert len(result["unmatched_azguard"]) == 1


def test_unmatched_defender_collected():
    az = [_azguard_finding("7.1", "pass")]
    df = [
        _defender_assessment("6.1.2", "Healthy"),
        _defender_assessment("2.1.2", "NotHealthy"),
    ]
    result = compare(az, df)
    assert result["unmatched_defender"] == ["2.1.2"]


def test_defender_unhealthy_maps_to_fail():
    az = [_azguard_finding("7.1", "fail")]
    df = [_defender_assessment("6.1.2", "Unhealthy")]
    result = compare(az, df)
    assert result["rows"][0]["match"] is True


def test_render_contains_summary(tmp_path):
    az = [_azguard_finding("7.1", "fail"), _azguard_finding("7.11", "fail")]
    df = [_defender_assessment("6.1.2", "NotHealthy")]
    text = render(compare(az, df))
    assert "matched: 1 / 1" in text
    assert "7.11" in text


def test_load_handles_bare_list_and_wrapped(tmp_path):
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps([{"control_id": "7.1", "status": "fail"}]))
    assert load_azguard(bare)[0]["control_id"] == "7.1"

    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"value": [{"control_id": "7.1", "status": "fail"}]}))
    assert load_defender(wrapped)[0]["control_id"] == "7.1"
