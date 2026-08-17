# Live Azure Validation

This directory holds the tooling that validates azguard against a live Azure
environment and Microsoft Defender for Cloud's CIS regulatory compliance
results.

## What this proves

1. **Real-data correctness** — azguard's collectors, Pydantic models, and rule
   engine hold up on genuine ARM payloads (not just hand-crafted fixtures).
2. **Finding correctness** — azguard's pass/fail results agree with Defender for
   Cloud's CIS v2.0.0 assessments, an independent, Microsoft-maintained source
   of truth.

## Prerequisites

- An Azure subscription (Azure for Students / GitHub Student Developer Pack).
- Terraform installed and on `PATH`.
- Azure CLI (`az`) authenticated as a service principal or user with Reader
  rights (and Owner/Contributor to provision + assign the CIS policy).
- The azguard environment (see `../pyproject.toml`).

## Files

| File | Purpose |
|------|---------|
| `compare.py` | Joins azguard findings JSON + Defender export JSON into a side-by-side table. |
| `control-mapping.md` | Maps azguard control IDs (CIS v6.0.0) to Defender CIS v2.0.0 IDs, with coverage notes. |
| `defender-export-format.md` | Documented JSON shapes both inputs must match. |
| `../terraform/` | Provisions the intentionally-misconfigured live environment. |

## How to run the validation

```bash
# 1. Provision the intentionally-misconfigured environment
cd terraform
terraform init
terraform apply -auto-approve

# 2. Scan the live environment and export findings as JSON
cd ..
azguard scan --subscription <sub-id> --json validation/findings.json --no-llm

# 3. In the portal: Microsoft Defender for Cloud -> Regulatory compliance ->
#    enable CIS Microsoft Azure Foundations Benchmark v2.0.0, wait for the first
#    assessment run (15 min - 24 h), then export the results as
#    validation/defender.json

# 4. Compare
cd validation
python compare.py --azguard findings.json --defender defender.json

# 5. Tear down (never leave this environment running)
cd terraform
terraform destroy -auto-approve
```

## Expected outcome & honest caveats

- Controls 7.1 / 7.2 / 7.4 should agree with Defender's 6.1.x (RDP/SSH exposure).
- Controls with no v2.0.0 equivalent (7.3, 7.5, 7.11, 6.1.x logging) show up in
  the "not comparable" section — this is expected, not a bug.
- Defender evaluates a much broader scope than NSGs; controls like IAM, storage,
  and SQL are out of scope for azguard and will appear as unmatched defender
  controls.
- The comparison is evidence of *agreement on the overlapping scope*, not a
  claim of full CIS certification. Document mismatches and any numbering drift in
  the README.
