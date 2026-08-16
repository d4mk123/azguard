from collections import defaultdict
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .charts import donut_chart, severity_bar_chart
from .models import NetworkSecurityGroup
from .rule_engine import CheckResult

TEMPLATE_DIR = Path(__file__).parent / "templates"
GLOBAL_NSG_LABEL = "Global / Manual Checks"
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _gather_summary(results: list[CheckResult]) -> dict:
    passes = sum(1 for r in results if r.status == "pass")
    fails = sum(1 for r in results if r.status == "fail")
    manuals = sum(1 for r in results if r.status == "manual")
    by_severity = {}
    for r in results:
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
    return {
        "total": len(results),
        "pass": passes,
        "fail": fails,
        "manual": manuals,
        "by_severity": by_severity,
    }


def _result_to_dict(r: CheckResult) -> dict:
    nsg = GLOBAL_NSG_LABEL if r.nsg_name in ("N/A", "", None) else r.nsg_name
    return {
        "control_id": r.control_id,
        "status": r.status,
        "severity": r.severity,
        "nsg_name": nsg,
        "rule_name": r.rule_name,
        "evidence": r.evidence,
    }


def _build_nsg_breakdown(
    results: list[CheckResult],
    nsgs: list[NetworkSecurityGroup] | None,
) -> list[dict]:
    nsg_map: dict[str, dict] = {}
    for nsg in nsgs or []:
        nsg_map[nsg.name] = {
            "location": nsg.location,
            "rules_count": len(nsg.security_rules),
        }

    by_nsg: dict[str, dict] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "manual": 0, "top_issue": ""}
    )
    for r in results:
        nsg_key = GLOBAL_NSG_LABEL if r.nsg_name in ("N/A", "", None) else r.nsg_name
        by_nsg[nsg_key][r.status] += 1
        if r.status == "fail" and not by_nsg[nsg_key]["top_issue"]:
            by_nsg[nsg_key]["top_issue"] = r.evidence[:80]

    breakdown = []
    for name, counts in by_nsg.items():
        is_global = name == GLOBAL_NSG_LABEL
        loc = (
            "Cross-NSG / Tenant-level checks (see table)"
            if is_global
            else nsg_map.get(name, {}).get("location", "—")
        )
        breakdown.append(
            {
                "name": name,
                "location": loc,
                "is_global": is_global,
                **counts,
            }
        )
    breakdown.sort(key=lambda x: (0 if x["is_global"] else 1, -x["fail"]))
    return breakdown


def _render_html(
    results: list[CheckResult],
    llm_narrative: str,
    nsgs: list[NetworkSecurityGroup] | None,
    template_name: str = "report.html",
) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(template_name)

    findings = [_result_to_dict(r) for r in results if r.control_id != "ANOMALY"]
    anomalies = [_result_to_dict(r) for r in results if r.control_id == "ANOMALY"]
    summary = _gather_summary(results)
    total_rules = sum(len(nsg.security_rules) for nsg in (nsgs or []))

    summary_pfm = {
        "pass": summary["pass"],
        "fail": summary["fail"],
        "manual": summary["manual"],
    }

    try:
        chart_donut = donut_chart(summary_pfm)
    except Exception:
        chart_donut = ""
    try:
        chart_severity = severity_bar_chart(summary["by_severity"])
    except Exception:
        chart_severity = ""

    findings_cis = [f for f in findings if f["control_id"] != "N/A"]
    findings_extra = [f for f in findings if f["control_id"] == "N/A"]

    return template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        nsg_count=len(nsgs or []),
        total_rules=total_rules,
        summary=summary,
        nsg_breakdown=_build_nsg_breakdown(results, nsgs),
        findings=findings_cis,
        findings_extra=findings_extra,
        anomalies=anomalies,
        chart_donut=chart_donut,
        chart_severity=chart_severity,
        llm_narrative=llm_narrative or "No AI narrative generated.",
    )


def generate_html_report(
    results: list[CheckResult],
    llm_narrative: str = "",
    nsgs: list[NetworkSecurityGroup] | None = None,
    output_path: str | Path = "report.html",
) -> str:
    html = _render_html(results, llm_narrative, nsgs)
    output_path = Path(output_path)
    output_path.write_text(html)
    return str(output_path)


def generate_pdf_report(
    results: list[CheckResult],
    llm_narrative: str = "",
    nsgs: list[NetworkSecurityGroup] | None = None,
    output_path: str | Path = "report.pdf",
) -> str:
    html = _render_html(results, llm_narrative, nsgs, template_name="report_pdf.html")
    from weasyprint import HTML

    output_path = Path(output_path)
    HTML(string=html).write_pdf(str(output_path))
    return str(output_path)
