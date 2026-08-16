# azguard — Demo Runbook

Three scenarios showing azguard end-to-end: a misconfigured NSG, a compliant one,
and the "before/after" fix narrative that makes the best demo.

All commands run from the repository root with the virtual environment activated.

---

## Scenario 1 — Violation: open management ports

```bash
azguard scan --input test-data/violation-nsg.json --output demo-violation --format html --no-llm
```

**Expected output (CLI summary):**

```
Scanned 1 NSG(s) — 19 checks
  Pass: 3  Fail: 8  Manual: 8
  Severity: Critical=5 High=2 Medium=11 Low=1
```

**Key findings in `demo-violation.html`:**
- `7.1` Critical — RDP (3389) exposed to the internet
- `7.2` Critical — SSH (22) exposed to the internet
- `7.4` Medium — HTTP(S) (80/443) exposed to the internet
- 5 Critical-severity results total: RDP, SSH, and HTTP/S exposure plus the
  overly-broad inbound rules on the same NSG

---

## Scenario 2 — Clean: compliant NSG

```bash
azguard scan --input test-data/clean-nsg.json --output demo-clean --format html --no-llm
```

**Expected output (CLI summary):**

```
Scanned 1 NSG(s) — 18 checks
  Pass: 6  Fail: 4  Manual: 8
  Severity: Critical=3 High=2 Medium=10 Low=3
```

The clean fixture contains no internet-exposed management ports — Critical-severity
findings drop from 5 to 3, total failures from 8 to 4. This is the "improved"
state your before/after narrative demonstrates.

---

## Scenario 3 — Anomaly detection: shadowed + weird rules

```bash
azguard scan --input test-data/shadowed-rules.json --output demo-shadow --format html --no-llm
azguard scan --input test-data/one-weird-rule.json --output demo-weird --format html --no-llm
```

**Expected:**
- `shadowed-rules.json` → the **Anomalies** section lists the shadowed deny rules
  (a broad allow silently overrides a narrower deny).
- `one-weird-rule.json` → the ML layer flags the statistically unusual
  `Weird-UDP-All` rule (Isolation Forest outlier).

---

## Before / after demo narrative

The strongest 2-minute demo:

1. Scan `violation-nsg.json` → show the Critical RDP/SSH findings.
2. Point out the `az network nsg rule delete` / restrict command in the remediation
   section.
3. Scan `clean-nsg.json` → show the pass counts climb and the Critical findings
   disappear.

This directly demonstrates value: *azguard finds the risk, tells you how to fix
it, and verifies the fix.*

---

## Generating the AI narrative for the demo

```bash
ollama pull qwen2.5:7b-instruct   # once
azguard scan --input test-data/violation-nsg.json --output demo-ai --format html
```

The report's executive summary and prioritized action plan are then written by the
local model.

---

## Portfolio blurb (one-pager draft)

> **azguard — Azure NSG CIS Compliance Analyzer**
>
> A solo, end-to-end security tool that scans Azure Network Security Group
> configurations against the CIS Microsoft Azure Foundations Benchmark. It combines
> a deterministic rule engine (~20 controls), a two-layer anomaly detector
> (rule-pair analysis + Isolation Forest), and a locally-hosted LLM that writes
> plain-English remediation guidance — all running locally with no paid API keys.
> Delivered as a Typer CLI, a Streamlit dashboard, and HTML/PDF reports. Tested with
> a 99-test suite and validated against Microsoft Defender for Cloud's CIS
> compliance assessments on a Terraform-provisioned test environment. Built over a
> 21-day solo plan (see `azure_new_plan.md`).

---

## Demo assets checklist

- [x] Run scenarios 1–3 and capture the CLI summary text above as actual output
- [x] Save `report.html` screenshots into `docs/screenshots/`
- [x] Link the screenshots in `README.md` (placeholder block removed)
- [ ] Record a short clip of the before/after narrative (optional)
