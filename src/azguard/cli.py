import json
from pathlib import Path

import typer

from .collector import (
    collect_from_file,
    collect_from_azure,
    collect_flow_logs_from_file,
    collect_flow_logs_from_azure,
)
from .rule_engine import run_engine
from .anomaly_detector import run_anomaly_detection
from .llm_report_writer import generate_report
from .report_generator import generate_html_report, generate_pdf_report

app = typer.Typer(help="Azure NSG CIS Compliance Analyzer")

SEVERITIES = ["Critical", "High", "Medium", "Low"]


def _resolve_report_path(base: Path, ext: str) -> Path:
    if base.suffix == f".{ext}":
        return base
    if base.suffix:
        return base.with_suffix(f".{ext}")
    return Path(f"{base}.{ext}")


@app.callback()
def main() -> None:
    """azguard — Azure NSG CIS Compliance Analyzer."""


@app.command()
def scan(
    input_path: Path | None = typer.Option(
        None, "--input", "-i", help="Path to az network nsg list JSON export"
    ),
    subscription: str | None = typer.Option(
        None, "--subscription", "-s", help="Azure subscription ID"
    ),
    flow_logs: Path | None = typer.Option(
        None, "--flow-logs", help="Path to flow-log JSON export"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file base"),
    report_format: str = typer.Option("both", "--format", help="pdf, html, or both"),
    no_llm: bool = typer.Option(False, "--no-llm/--llm", help="Skip the LLM narrative"),
    no_flow_logs: bool = typer.Option(
        False,
        "--no-flow-logs",
        help="Skip live flow-log collection when scanning a subscription",
    ),
    json_output: Path | None = typer.Option(
        None,
        "--json",
        "-j",
        help="Write findings as JSON to this path (machine-readable, for validation tooling)",
    ),
    model: str = typer.Option(
        "qwen2.5:7b-instruct", "--model", help="Ollama model name"
    ),
):
    if input_path and subscription:
        typer.echo(
            "Error: --input and --subscription are mutually exclusive.", err=True
        )
        raise typer.Exit(code=1)
    if not input_path and not subscription:
        typer.echo(
            "Error: provide either --input <file> or --subscription <id>.", err=True
        )
        raise typer.Exit(code=1)
    if report_format not in ("pdf", "html", "both"):
        typer.echo("Error: --format must be one of: pdf, html, both", err=True)
        raise typer.Exit(code=1)
    if input_path and not input_path.exists():
        typer.echo(f"Error: input file not found: {input_path}", err=True)
        raise typer.Exit(code=1)
    if flow_logs and not flow_logs.exists():
        typer.echo(f"Error: flow-logs file not found: {flow_logs}", err=True)
        raise typer.Exit(code=1)

    try:
        nsgs = (
            collect_from_file(input_path)
            if input_path
            else collect_from_azure(subscription)
        )
    except Exception as e:
        typer.echo(f"Error: failed to collect NSG data ({e})", err=True)
        raise typer.Exit(code=1)
    flow_logs_data = None
    if flow_logs:
        flow_logs_data = collect_flow_logs_from_file(flow_logs)
    elif subscription and not no_flow_logs:
        try:
            flow_logs_data = collect_flow_logs_from_azure(subscription)
        except Exception as e:
            typer.echo(f"Warning: flow-log collection skipped ({e})", err=True)
            flow_logs_data = None

    results = run_engine(nsgs, flow_logs_data)
    results += run_anomaly_detection(nsgs)

    narrative = ""
    if not no_llm:
        try:
            narrative = generate_report(results, model_name=model)
            typer.echo("LLM narrative generated.")
        except Exception as e:
            typer.echo(f"Warning: LLM narrative skipped ({e})", err=True)
            narrative = (
                "*(LLM narrative skipped — AI writer unavailable during this scan)*"
            )

    out_html = Path("report.html")
    out_pdf = Path("report.pdf")
    if output:
        if report_format in ("pdf", "both"):
            out_pdf = _resolve_report_path(output, "pdf")
        if report_format in ("html", "both"):
            out_html = _resolve_report_path(output, "html")

    if json_output:
        json_output.write_text(json.dumps([r.model_dump() for r in results], indent=2))
        typer.echo(f"Findings JSON: {json_output}")

    if report_format in ("html", "both"):
        typer.echo(
            f"HTML report: {generate_html_report(results, narrative, nsgs, out_html)}"
        )
    if report_format in ("pdf", "both"):
        typer.echo(
            f"PDF report:  {generate_pdf_report(results, narrative, nsgs, out_pdf)}"
        )

    passes = sum(1 for r in results if r.status == "pass")
    fails = sum(1 for r in results if r.status == "fail")
    manuals = sum(1 for r in results if r.status == "manual")
    sev = {s: sum(1 for r in results if r.severity == s) for s in SEVERITIES}
    typer.echo("")
    typer.echo(f"Scanned {len(nsgs)} NSG(s) — {len(results)} checks")
    typer.echo(f"  Pass: {passes}  Fail: {fails}  Manual: {manuals}")
    typer.echo(
        f"  Severity: Critical={sev['Critical']} High={sev['High']} Medium={sev['Medium']} Low={sev['Low']}"
    )


if __name__ == "__main__":
    app()
