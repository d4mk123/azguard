import json
from typing import Any

from .rule_engine import CheckResult

SYSTEM_PROMPT = (
    "You are an Azure Network Security Group (NSG) compliance analyst. "
    "Your job is to review findings from a security scan of Azure NSG rules. "
    "CRITICAL RULE: Only discuss the findings provided below. "
    "Do NOT add, infer, or fabricate any issues that are not explicitly listed. "
    "If a finding mentions a specific NSG name, rule name, or port, use those exact values. "
    "Write in clear, plain English suitable for a system administrator who may not be a security expert."
)

USER_PROMPT_TEMPLATE = """Here are the findings from scanning my Azure Network Security Groups:

{findings_json}

Please produce the following:

1. **Executive Summary** — 3-5 sentences summarizing the overall security posture, number of findings by severity, and the most critical issue.

2. **Detailed Findings** — For each finding, provide:
   - The finding name/ID
   - What the issue is (in plain English)
   - Why it is a risk
   - The exact Azure CLI command to fix it

3. **Prioritized Action Plan** — A numbered list of actions ordered from most to least critical, with the specific NSG and rule name for each.
"""


def _severity_sort_key(r: CheckResult) -> int:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return order.get(r.severity, 4)


def findings_to_json(results: list[CheckResult]) -> str:
    sorted_results = sorted(results, key=_severity_sort_key)
    findings_list: list[dict[str, Any]] = []
    for r in sorted_results:
        findings_list.append({
            "control_id": r.control_id,
            "status": r.status,
            "severity": r.severity,
            "nsg": r.nsg_name,
            "rule": r.rule_name,
            "evidence": r.evidence,
        })
    summary = {
        "total_findings": len(findings_list),
        "by_severity": {
            "Critical": sum(1 for r in results if r.severity == "Critical"),
            "High": sum(1 for r in results if r.severity == "High"),
            "Medium": sum(1 for r in results if r.severity == "Medium"),
            "Low": sum(1 for r in results if r.severity == "Low"),
        },
        "findings": findings_list,
    }
    return json.dumps(summary, indent=2)


def build_prompt(findings_json: str) -> str:
    return USER_PROMPT_TEMPLATE.format(findings_json=findings_json)


def generate_report(
    results: list[CheckResult],
    model_name: str = "qwen2.5:7b-instruct",
) -> str:
    from ollama import chat

    findings_json = findings_to_json(results)
    prompt = build_prompt(findings_json)
    response = chat(
        model=model_name,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return response["message"]["content"]