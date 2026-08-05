from pathlib import Path

from typer.testing import CliRunner

from azguard.cli import app
from azguard.models import NetworkSecurityGroup
from azguard.rule_engine import CheckResult

FIXTURES_DIR = Path(__file__).parents[3] / "test-data"
VIOLATION = FIXTURES_DIR / "violation-nsg.json"

runner = CliRunner()


def _sample_nsg(name: str = "test-nsg") -> NetworkSecurityGroup:
    return NetworkSecurityGroup(id=f"/x/{name}", name=name, location="eastus")


def _sample_result() -> CheckResult:
    return CheckResult(
        control_id="7.1",
        status="fail",
        severity="Critical",
        nsg_name="test-nsg",
        evidence="RDP exposed to internet.",
    )


def _stub_report_generator(monkeypatch, tmp_path, captured: dict):
    def fake_html(results, narrative, nsgs, out_path):
        captured["html"] = (results, narrative, nsgs, str(out_path))
        Path(out_path).write_text("<html/>")
        return str(out_path)

    def fake_pdf(results, narrative, nsgs, out_path):
        captured["pdf"] = (results, narrative, nsgs, str(out_path))
        Path(out_path).write_text("%PDF")
        return str(out_path)

    monkeypatch.setattr("azguard.cli.generate_html_report", fake_html)
    monkeypatch.setattr("azguard.cli.generate_pdf_report", fake_pdf)


def test_scan_happy_path_writes_html(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "azguard.cli.collect_from_file",
        lambda path: [_sample_nsg()],
    )
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    out = tmp_path / "out.html"
    result = runner.invoke(
        app, ["--input", str(VIOLATION), "--format", "html", "--no-llm", "--output", str(out)]
    )

    assert result.exit_code == 0
    assert out.exists()
    assert "Scanned 1 NSG(s)" in result.output
    assert captured["html"][3] == str(out)


def test_scan_default_format_both(tmp_path, monkeypatch):
    monkeypatch.setattr("azguard.cli.collect_from_file", lambda path: [_sample_nsg()])
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    result = runner.invoke(app, ["--input", str(VIOLATION), "--no-llm"])

    assert result.exit_code == 0
    assert "html" in captured and "pdf" in captured


def test_output_pdf_derives_html_path(tmp_path, monkeypatch):
    monkeypatch.setattr("azguard.cli.collect_from_file", lambda path: [_sample_nsg()])
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    out_pdf = tmp_path / "scan.pdf"
    result = runner.invoke(
        app, ["--input", str(VIOLATION), "--no-llm", "--output", str(out_pdf)]
    )

    assert result.exit_code == 0
    assert captured["pdf"][3] == str(out_pdf)
    assert captured["html"][3] == str(tmp_path / "scan.html")


def test_missing_input_file(tmp_path, monkeypatch):
    result = runner.invoke(app, ["--input", str(tmp_path / "nope.json"), "--no-llm"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_missing_flow_logs_file(tmp_path, monkeypatch):
    result = runner.invoke(
        app,
        ["--input", str(VIOLATION), "--flow-logs", str(tmp_path / "nope.json"), "--no-llm"],
    )
    assert result.exit_code == 1
    assert "not found" in result.output


def test_input_and_subscription_mutually_exclusive():
    result = runner.invoke(
        app, ["--input", "x.json", "--subscription", "abc", "--no-llm"]
    )
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output


def test_neither_input_nor_subscription():
    result = runner.invoke(app, ["--no-llm"])
    assert result.exit_code == 1
    assert "--input" in result.output or "--subscription" in result.output


def test_invalid_format():
    result = runner.invoke(
        app, ["--input", "x.json", "--format", "xml", "--no-llm"]
    )
    assert result.exit_code == 1
    assert "format" in result.output.lower()


def test_no_llm_skips_llm(tmp_path, monkeypatch):
    monkeypatch.setattr("azguard.cli.collect_from_file", lambda path: [_sample_nsg()])
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    captured = {}

    def fail_if_called(*args, **kwargs):
        raise AssertionError("LLM should not be called with --no-llm")

    monkeypatch.setattr("azguard.cli.generate_report", fail_if_called)
    _stub_report_generator(monkeypatch, tmp_path, captured)

    result = runner.invoke(app, ["--input", str(VIOLATION), "--format", "html", "--no-llm"])

    assert result.exit_code == 0
    assert captured["html"][1] == ""


def test_llm_narrative_passed_to_report(tmp_path, monkeypatch):
    monkeypatch.setattr("azguard.cli.collect_from_file", lambda path: [_sample_nsg()])
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    monkeypatch.setattr("azguard.cli.generate_report", lambda results, model_name: "AI narrative")
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    result = runner.invoke(app, ["--input", str(VIOLATION), "--format", "html"])

    assert result.exit_code == 0
    assert captured["html"][1] == "AI narrative"


def test_llm_failure_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr("azguard.cli.collect_from_file", lambda path: [_sample_nsg()])
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    monkeypatch.setattr(
        "azguard.cli.generate_report",
        lambda results, model_name: (_ for _ in ()).throw(RuntimeError("ollama down")),
    )
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    result = runner.invoke(app, ["--input", str(VIOLATION), "--format", "html"])

    assert result.exit_code == 0
    assert "skipped" in result.output
    assert "skipped" in captured["html"][1]


def test_subscription_uses_azure_collector(tmp_path, monkeypatch):
    called = {}

    def fake_azure(subscription_id):
        called["sub"] = subscription_id
        return [_sample_nsg()]

    monkeypatch.setattr("azguard.cli.collect_from_azure", fake_azure)
    monkeypatch.setattr("azguard.cli.run_anomaly_detection", lambda nsgs: [])
    monkeypatch.setattr("azguard.cli.run_engine", lambda nsgs, fl: [_sample_result()])
    captured = {}
    _stub_report_generator(monkeypatch, tmp_path, captured)

    result = runner.invoke(
        app, ["--subscription", "sub-123", "--format", "html", "--no-llm"]
    )

    assert result.exit_code == 0
    assert called.get("sub") == "sub-123"
