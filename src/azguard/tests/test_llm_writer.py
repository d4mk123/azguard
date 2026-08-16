import json

from azguard.llm_report_writer import findings_to_json, build_prompt
from azguard.rule_engine import CheckResult


def _sample_results() -> list[CheckResult]:
    return [
        CheckResult(
            control_id="7.1",
            status="fail",
            severity="Critical",
            nsg_name="web-nsg",
            rule_name="RDP",
            evidence="RDP exposed to internet.",
        ),
        CheckResult(
            control_id="7.5",
            status="pass",
            severity="High",
            nsg_name="web-nsg",
            rule_name=None,
            evidence="Flow log retention >= 90 days.",
        ),
        CheckResult(
            control_id="ANOMALY",
            status="fail",
            severity="Medium",
            nsg_name="data-nsg",
            rule_name="WeirdRule",
            evidence="Rule is statistically unusual.",
        ),
        CheckResult(
            control_id="6.1.1.5",
            status="manual",
            severity="Medium",
            nsg_name="N/A",
            rule_name=None,
            evidence="Manual verification required.",
        ),
    ]


def test_findings_to_json_returns_valid_json():
    results = _sample_results()
    output = findings_to_json(results)
    data = json.loads(output)
    assert "total_findings" in data
    assert data["total_findings"] == 4
    assert "by_severity" in data
    assert data["by_severity"]["Critical"] == 1
    assert data["by_severity"]["Medium"] == 2
    assert "findings" in data
    assert len(data["findings"]) == 4


def test_findings_to_json_sorted_by_severity():
    results = _sample_results()
    output = findings_to_json(results)
    data = json.loads(output)
    severities = [f["severity"] for f in data["findings"]]
    assert severities == ["Critical", "High", "Medium", "Medium"]


def test_findings_to_json_includes_all_fields():
    results = _sample_results()
    output = findings_to_json(results)
    data = json.loads(output)
    finding = data["findings"][0]
    assert finding["control_id"] == "7.1"
    assert finding["status"] == "fail"
    assert finding["severity"] == "Critical"
    assert finding["nsg"] == "web-nsg"
    assert finding["rule"] == "RDP"
    assert "RDP exposed" in finding["evidence"]


def test_build_prompt_includes_findings():
    results = _sample_results()
    findings_json = findings_to_json(results)
    prompt = build_prompt(findings_json)
    assert "RDP exposed" in prompt
    assert "Executive Summary" in prompt
    assert "Detailed Findings" in prompt
    assert "Prioritized Action Plan" in prompt
