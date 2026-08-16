#!/usr/bin/env python3
"""Compare azguard findings against a Defender for Cloud CIS v2.0.0 export.

Produces a side-by-side table of control agreement and flags mismatches.

Usage:
    python compare.py --azguard findings.json --defender defender.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# azguard control id -> Defender CIS v2.0.0 control id (see control-mapping.md).
# A control may map to multiple defender ids; compare against any of them.
CONTROL_MAPPING = {
    "7.1": {"6.1.2", "6.1.3"},
    "7.2": {"6.1.2", "6.1.3"},
    "7.4": {"6.1.2", "6.1.3"},
    "2.1.2": {"3.11"},
}

# azguard controls with no v2.0.0 equivalent (never comparable)
UNMAPPED_AZGUARD = {"7.3", "7.5", "7.11", "6.1.1.5", "6.1.1.6", "6.1.2.3", "6.1.2.4"}

AZGUARD_MANUAL = {"manual"}
DEFENDER_HEALTHY = {"healthy"}
DEFENDER_UNHEALTHY = {"nothealthy", "unhealthy"}


def _normalize_azguard_status(status: str) -> str:
    if status == "pass":
        return "pass"
    if status == "fail":
        return "fail"
    return "other"


def _normalize_defender_status(code: str) -> str:
    code = (code or "").lower()
    if code in DEFENDER_HEALTHY:
        return "pass"
    if code in DEFENDER_UNHEALTHY:
        return "fail"
    return "other"


def load_azguard(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else data.get("value", [])


def load_defender(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else data.get("value", [])


def _defender_by_control(assessments: list[dict]) -> dict[str, str]:
    """control_id -> normalized status (first non-'other' wins)."""
    out: dict[str, str] = {}
    for a in assessments:
        cid = a.get("control_id")
        if not cid:
            continue
        status = _normalize_defender_status(a.get("status", {}).get("code", ""))
        if cid not in out or status != "other":
            out[cid] = status
    return out


def compare(azguard_results: list[dict], defender_assessments: list[dict]) -> dict:
    defender = _defender_by_control(defender_assessments)
    rows: list[dict] = []
    unmatched_azguard: list[dict] = []
    unmatched_defender: list[str] = []

    for r in azguard_results:
        cid = r.get("control_id", "N/A")
        if cid == "N/A" or cid in UNMAPPED_AZGUARD:
            unmatched_azguard.append(r)
            continue

        target_ids = CONTROL_MAPPING.get(cid, set())
        candidate = {d: defender[d] for d in target_ids if d in defender}
        if not candidate:
            unmatched_azguard.append(r)
            continue

        az_status = _normalize_azguard_status(r.get("status", "other"))
        defender_statuses = set(candidate.values())
        match = az_status == "pass" and defender_statuses == {"pass"}
        match = match or (az_status == "fail" and "fail" in defender_statuses)
        match = match or (az_status == "other")
        rows.append(
            {
                "control_id": cid,
                "azguard_status": az_status,
                "defender_status": ",".join(sorted(defender_statuses)),
                "match": match,
                "evidence": r.get("evidence", ""),
            }
        )

    comparable = {d for ids in CONTROL_MAPPING.values() for d in ids}
    unmatched_defender = sorted(d for d in defender if d not in comparable)

    return {
        "rows": rows,
        "unmatched_azguard": unmatched_azguard,
        "unmatched_defender": unmatched_defender,
    }


def render(result: dict) -> str:
    lines: list[str] = []
    rows = result["rows"]
    lines.append(f"{'control':<10} {'azguard':<8} {'defender':<12} match")
    lines.append("-" * 48)
    for row in rows:
        lines.append(
            f"{row['control_id']:<10} {row['azguard_status']:<8} "
            f"{row['defender_status']:<12} {'YES' if row['match'] else 'NO'}"
        )
    lines.append("")
    lines.append(f"matched: {sum(1 for r in rows if r['match'])} / {len(rows)}")
    if rows:
        mismatches = [r for r in rows if not r["match"]]
        for m in mismatches:
            lines.append(f"  MISMATCH {m['control_id']}: {m['evidence'][:80]}")
    lines.append("")
    lines.append(f"azguard results not comparable: {len(result['unmatched_azguard'])}")
    for r in result["unmatched_azguard"]:
        lines.append(
            f"  [{r.get('control_id', 'N/A')}] {r.get('status')}: {r.get('evidence', '')[:80]}"
        )
    if result["unmatched_defender"]:
        lines.append(f"defender controls with no azguard equivalent: {len(result['unmatched_defender'])}")
        lines.append("  " + ", ".join(result["unmatched_defender"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azguard", required=True, type=Path, help="azguard findings JSON")
    parser.add_argument("--defender", required=True, type=Path, help="Defender export JSON")
    args = parser.parse_args(argv)

    if not args.azguard.exists():
        parser.error(f"azguard file not found: {args.azguard}")
    if not args.defender.exists():
        parser.error(f"defender file not found: {args.defender}")

    result = compare(load_azguard(args.azguard), load_defender(args.defender))
    print(render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
