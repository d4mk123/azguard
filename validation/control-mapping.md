# Control-ID Mapping: azguard ↔ Microsoft Defender for Cloud (CIS v2.0.0)

This table maps the controls implemented in `src/azguard/rule_engine.py` (built
from the **CIS Microsoft Azure Foundations Benchmark v6.0.0** PDF) to the control
IDs used by **Microsoft Defender for Cloud's Regulatory Compliance** standard
(CIS **v2.0.0**).

> **Important caveat:** the numbering schemes differ between CIS versions. Some
> controls have no direct v2.0.0 equivalent, and Defender evaluates a much wider
> scope than NSGs (VMs, storage, key vault, SQL, etc.). A perfect 1:1 match is not
> expected — the goal is to document agreement and explain any divergence.

## Mapping table

| azguard control | Title (v6.0.0) | Defender CIS v2.0.0 | Notes / expected agreement |
|-----------------|----------------|---------------------|----------------------------|
| 7.1 | RDP access from the Internet evaluated and restricted | 6.1.2 / 6.1.3 | Defender covers VM-level RDP exposure; NSG scope may not align 1:1 |
| 7.2 | SSH access from the Internet evaluated and restricted | 6.1.2 / 6.1.3 | Same caveat as 7.1 |
| 7.3 | UDP port access from the Internet restricted | (none direct) | Defender does not map this to a CIS v2.0.0 control; azguard-only |
| 7.4 | HTTP(S) access from the Internet restricted | 6.1.2 / 6.1.3 | Web exposure overlap, differing methodology |
| 7.5 | NSG flow log retention ≥ 90 days | (none direct in v2.0.0) | v2.0.0 predates the flow-log retention control; azguard-only |
| 7.11 | Subnets associated with Network Security Groups | (none direct) | azguard-only heuristic (flags NSGs with no subnet association) |
| 6.1.1.5 | NSG flow logs captured and sent to Log Analytics | (see 2.3 / network logging) | Defender maps logging broadly, not per-NSG |
| 6.1.1.6 | VNet flow logs captured and sent to Log Analytics | (see 2.3) | Successor to 6.1.1.5; not in Defender v2.0.0 directly |
| 6.1.2.3 | Activity log alert: create/update NSG | (see 5.2.x activity log) | Defender groups activity-log alert checks differently |
| 6.1.2.4 | Activity log alert: delete NSG | (see 5.2.x activity log) | Same as above |
| 2.1.2 | NSGs configured for Databricks subnets | 3.11 | Databricks-specific; only relevant if Databricks is deployed |

## Controls Defender checks that azguard does not

These live in the v2.0.0 standard and are outside azguard's NSG scope. Record them
as "out of scope" in the comparison:

- 6.1.1–6.1.5 OS/database/endpoint protection recommendations
- 2.1–2.3 IAM and password policies
- 3.1–3.13 storage, SQL, Key Vault security configs
- 4.x / 7.x / 8.x: App Service, VM, container, logging controls

## How to use this

1. Run azguard against the live environment → export findings as JSON.
2. Enable the CIS v2.0.0 standard in Defender for Cloud → export the compliance
   assessment results (see `defender-export-format.md`).
3. Run `compare.py --azguard findings.json --defender defender.json` to produce
   the side-by-side table.
4. Investigate and document any mismatch in `validation/README.md`.
