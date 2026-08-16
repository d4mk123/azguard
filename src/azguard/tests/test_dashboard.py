import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from azguard.collector import collect_from_bytes, collect_flow_logs_from_bytes
from azguard.dashboard import _report_bytes, run_scan
from azguard.models import FlowLog, NetworkSecurityGroup
from azguard.rule_engine import CheckResult

FIXTURES_DIR = Path(__file__).parents[3] / "test-data"
VIOLATION = FIXTURES_DIR / "violation-nsg.json"
FLOW_LOGS = FIXTURES_DIR / "flow-logs.json"
DASHBOARD = Path(__file__).parents[1] / "dashboard.py"


def test_collect_from_bytes_list():
    nsgs = collect_from_bytes(VIOLATION.read_bytes())
    assert isinstance(nsgs, list)
    assert nsgs
    assert all(isinstance(nsg, NetworkSecurityGroup) for nsg in nsgs)


def test_collect_from_bytes_wrapped():
    raw = json.loads(VIOLATION.read_text())
    if isinstance(raw, list):
        raw = {"value": raw}
    nsgs = collect_from_bytes(json.dumps(raw).encode())
    assert nsgs


def test_collect_from_bytes_malformed():
    with pytest.raises(Exception):
        collect_from_bytes(b"not json")


def test_collect_from_bytes_wrong_shape():
    with pytest.raises(ValidationError):
        collect_from_bytes(json.dumps({"value": "nope"}).encode())


def test_collect_flow_logs_from_bytes():
    logs = collect_flow_logs_from_bytes(FLOW_LOGS.read_bytes())
    assert isinstance(logs, list)
    assert all(isinstance(log, FlowLog) for log in logs)


def test_run_scan_returns_expected_shape():
    nsgs, results, narrative = run_scan(
        VIOLATION.read_bytes(), FLOW_LOGS.read_bytes(), "test-model", False
    )
    assert isinstance(nsgs, list) and nsgs
    assert isinstance(results, list)
    assert results
    assert all(isinstance(r, CheckResult) for r in results)
    assert narrative == ""


def test_report_bytes_exports():
    nsgs, results, narrative = run_scan(
        VIOLATION.read_bytes(), FLOW_LOGS.read_bytes(), "test-model", False
    )
    html = _report_bytes(results, narrative, nsgs, "html")
    pdf = _report_bytes(results, narrative, nsgs, "pdf")
    assert html.lstrip().startswith((b"<", b"<!doctype"))
    assert pdf.startswith(b"%PDF")


def test_dashboard_loads():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(DASHBOARD), default_timeout=60)
    at.run()
    assert not at.exception
    assert at.title[0].value == "azguard — Azure NSG CIS Compliance Dashboard"
    messages = [str(i.value) for i in list(at.info) + list(at.warning)]
    assert any("Upload" in m for m in messages)


def test_dashboard_scan_flow():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(DASHBOARD), default_timeout=60)
    at.run()
    at.sidebar.file_uploader[0].set_value(
        [("violation-nsg.json", VIOLATION.read_bytes(), "application/json")]
    )
    at.button[0].click().run()
    assert not at.exception
    assert any(m.label == "NSGs" and m.value == "1" for m in at.metric)
    assert at.dataframe
