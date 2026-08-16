import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from azguard.anomaly_detector import run_anomaly_detection
from azguard.charts import donut_fig, severity_bar_fig
from azguard.collector import (
    collect_from_azure,
    collect_from_bytes,
    collect_flow_logs_from_bytes,
)
from azguard.llm_report_writer import generate_report
from azguard.report_generator import generate_html_report, generate_pdf_report
from azguard.rule_engine import run_engine

SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["pass", "fail", "manual"]


@st.cache_data(show_spinner="Scanning NSGs...")
def run_scan(nsg_bytes: bytes, flow_bytes: bytes | None, model: str, use_llm: bool):
    nsgs = collect_from_bytes(nsg_bytes)
    flow_logs = collect_flow_logs_from_bytes(flow_bytes) if flow_bytes else None
    results = run_engine(nsgs, flow_logs)
    results += run_anomaly_detection(nsgs)
    narrative = ""
    if use_llm:
        try:
            narrative = generate_report(results, model_name=model)
        except Exception as e:
            narrative = f"*(AI narrative unavailable: {e})*"
    return nsgs, results, narrative


def _result_rows(results) -> list[dict]:
    rows = []
    for r in results:
        rows.append(
            {
                "Control": r.control_id,
                "Status": r.status,
                "Severity": r.severity,
                "NSG": r.nsg_name,
                "Rule": r.rule_name or "",
                "Evidence": r.evidence,
            }
        )
    return rows


@st.cache_data(show_spinner=False)
def _report_bytes(results, narrative, nsgs, kind: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / f"report.{kind}"
        if kind == "html":
            generate_html_report(results, narrative, nsgs, out)
        else:
            generate_pdf_report(results, narrative, nsgs, out)
        return out.read_bytes()


def main() -> None:
    st.set_page_config(page_title="azguard — NSG CIS Analyzer", layout="wide")
    st.title("azguard — Azure NSG CIS Compliance Dashboard")

    with st.sidebar:
        st.header("Scan input")
        uploaded = st.file_uploader("NSG fixture (JSON)", type="json")
        flow_uploaded = st.file_uploader("Flow logs (JSON, optional)", type="json")
        st.divider()
        sub_id = st.text_input("Or Azure subscription ID (live scan)")
        st.divider()
        model = st.text_input("Ollama model", value="qwen2.5:7b-instruct")
        run_btn = st.button("Run scan", type="primary")

    if bool(uploaded) == bool(sub_id):
        st.sidebar.warning("Upload a fixture OR enter a subscription ID, not both.")
        st.stop()

    if run_btn:
        try:
            if uploaded:
                nsgs, results, narrative = run_scan(
                    uploaded.getvalue(),
                    flow_uploaded.getvalue() if flow_uploaded else None,
                    model,
                    False,
                )
            else:
                nsgs = collect_from_azure(sub_id)
                results = run_engine(nsgs, None)
                results += run_anomaly_detection(nsgs)
                narrative = ""
        except Exception as e:
            st.error(f"Scan failed: {e}")
            st.stop()
        st.session_state["nsgs"] = nsgs
        st.session_state["results"] = results
        st.session_state["narrative"] = narrative
        st.session_state["model"] = model
        st.session_state["scanned"] = True

    if not st.session_state.get("scanned"):
        st.info(
            "Upload an NSG JSON fixture (e.g. test-data/violation-nsg.json) and click Run scan."
        )
        st.stop()

    nsgs = st.session_state["nsgs"]
    results = st.session_state["results"]
    narrative = st.session_state["narrative"]
    model = st.session_state["model"]

    summary = {
        "pass": sum(1 for r in results if r.status == "pass"),
        "fail": sum(1 for r in results if r.status == "fail"),
        "manual": sum(1 for r in results if r.status == "manual"),
    }
    by_severity = {}
    for r in results:
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

    total_rules = sum(len(nsg.security_rules) for nsg in nsgs)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("NSGs", len(nsgs))
    c2.metric("Security rules", total_rules)
    c3.metric("Checks", len(results))
    c4.metric("Fail", summary["fail"])
    c5.metric("Pass", summary["pass"])

    col_l, col_r = st.columns(2)
    with col_l:
        st.markdown("#### Status")
        st.pyplot(donut_fig(summary))
    with col_r:
        st.markdown("#### Severity")
        st.pyplot(severity_bar_fig(by_severity))

    st.divider()

    findings = [r for r in results if r.control_id != "ANOMALY"]
    anomalies = [r for r in results if r.control_id == "ANOMALY"]

    st.subheader("Findings")
    f_status = st.multiselect("Status", STATUSES, default=STATUSES)
    f_sev = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    filtered = [r for r in findings if r.status in f_status and r.severity in f_sev]
    if filtered:
        st.dataframe(
            pd.DataFrame(_result_rows(filtered)), width="stretch", hide_index=True
        )
    else:
        st.caption("No findings match the current filters.")

    st.divider()

    st.subheader("Anomalies")
    if anomalies:
        st.dataframe(
            pd.DataFrame(_result_rows(anomalies)), width="stretch", hide_index=True
        )
        st.caption(
            "Shadowed/redundant rule pairs and statistically unusual rules (Isolation Forest)."
        )
    else:
        st.caption("No anomalies detected.")

    st.divider()

    st.subheader("AI Summary")
    if narrative:
        st.markdown(narrative)
    else:
        st.caption(
            "No AI narrative yet. Click 'Regenerate AI summary' to generate one (requires Ollama)."
        )

    if st.button("Regenerate AI summary", key="regenerate"):
        with st.spinner("Querying Ollama..."):
            try:
                st.session_state["narrative"] = generate_report(
                    results, model_name=model
                )
            except Exception as e:
                st.session_state["narrative"] = f"*(AI narrative unavailable: {e})*"
        st.rerun()

    st.divider()

    st.subheader("Report export")

    def lazy_report(kind: str) -> bytes:
        try:
            return _report_bytes(results, narrative, nsgs, kind)
        except Exception as e:
            st.error(f"{kind.upper()} export failed: {e}")
            return b""

    c_html, c_pdf = st.columns(2)
    with c_html:
        st.download_button(
            "Download HTML report",
            data=lambda: lazy_report("html"),
            file_name="report.html",
            mime="text/html",
        )
    with c_pdf:
        st.download_button(
            "Download PDF report",
            data=lambda: lazy_report("pdf"),
            file_name="report.pdf",
            mime="application/pdf",
        )
    st.caption("Reports are generated on demand. PDF export can take ~10–15 seconds.")


if __name__ == "__main__":
    main()
