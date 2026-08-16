# Defender for Cloud CIS v2.0.0 export format expected by compare.py

`compare.py` reads a Defender export produced by exporting the Regulatory
Compliance results for the CIS Microsoft Azure Foundations Benchmark v2.0.0
standard. The tool accepts the results of:

```
az security assessment list --subscription <sub>
```

or the exported regulatory compliance JSON from the portal.

## azguard findings shape

The azguard side is produced by the CLI:

```
azguard scan --subscription <id> --json findings.json
```

Each entry is a serialized `CheckResult`:

```json
[
  {
    "control_id": "7.1",
    "status": "fail",
    "severity": "Critical",
    "nsg_name": "violation-nsg",
    "rule_name": "RDP",
    "evidence": "NSG 'violation-nsg' has an inbound rule 'RDP' allowing Tcp traffic from the internet to ports 3389."
  }
]
```

- `status`: "pass" | "fail" | "manual"
- `control_id`: "N/A" for heuristic checks (any-any rule, missing deny-all, etc.)

## Defender export shape

The tool normalizes each Defender assessment to:

```json
[
  {
    "id": "/subscriptions/<sub>/providers/Microsoft.Security/assessments/<guid>",
    "display_name": "RDP access from the Internet should be restricted",
    "status": {
      "code": "NotHealthy",
      "cause": "",
      "description": ""
    },
    "control_id": "6.1.2"
  }
]
```

- `status.code` values: "Healthy", "NotHealthy", "NotApplicable",
  "NotScoped", "Unhealthy" (older API)
- `control_id` is the CIS v2.0.0 control ID the assessment maps to

## Normalization rules in compare.py

1. azguard `status` is normalized to `pass` / `fail` / `other`
   (where `manual` → `other`).
2. Defender `status.code` is normalized: `Healthy` → `pass`,
   `NotHealthy`/`Unhealthy` → `fail`, everything else → `other`.
3. The join is done on `control_id` through the mapping in
   `control-mapping.md`; unmatched IDs are reported in the
   "not comparable" section rather than silently dropped.
