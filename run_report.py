from pathlib import Path

from azguard.collector import collect_from_file, collect_flow_logs_from_file
from azguard.rule_engine import run_engine
from azguard.anomaly_detector import run_anomaly_detection
from azguard.report_generator import generate_html_report, generate_pdf_report

FIXTURE_PATH = Path("test-data/violation-nsg.json")
FLOW_LOG_PATH = Path("test-data/flow-logs.json")

nsgs = collect_from_file(str(FIXTURE_PATH))
flow_logs = collect_flow_logs_from_file(str(FLOW_LOG_PATH)) if FLOW_LOG_PATH.exists() else None
results = run_engine(nsgs, flow_logs)
results += run_anomaly_detection(nsgs)

print(f"Loaded {len(nsgs)} NSG(s), {len(results)} checks/anomalies")

try:
    from azguard.llm_report_writer import generate_report
    narrative = generate_report(results, model_name="llama3.2:3b")
    print("LLM narrative generated.")
except Exception as e:
    narrative = "*(LLM narrative skipped — AI writer unavailable during this scan)*"
    print(f"LLM skipped ({e})")

html_path = generate_html_report(results, narrative, nsgs, "report.html")
print(f"HTML report: {html_path}")

pdf_path = generate_pdf_report(results, narrative, nsgs, "report.pdf")
print(f"PDF report:  {pdf_path}")
