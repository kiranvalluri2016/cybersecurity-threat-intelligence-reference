from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from uuid import uuid4

from .audit import AuditLedger
from .contracts import authorize
from .logging_config import configure_logging, log_event
from .pipeline import analyze, load_events


def main() -> None:
    parser = argparse.ArgumentParser(prog="threat-intel")
    parser.add_argument("--version", action="version", version="threat-intel 0.1.0")
    subcommands = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subcommands.add_parser("analyze")
    analyze_parser.add_argument("--caller", required=True)
    analyze_parser.add_argument("--tenant", required=True)
    analyze_parser.add_argument("--input", type=Path, required=True)
    analyze_parser.add_argument("--baseline", type=Path, required=True)
    analyze_parser.add_argument("--state", type=Path, required=True)
    validate_parser = subcommands.add_parser("validate-fixtures")
    validate_parser.add_argument("--caller", required=True)
    validate_parser.add_argument("--tenant", required=True)
    validate_parser.add_argument("--input", type=Path, required=True)
    validate_parser.add_argument("--baseline", type=Path, required=True)
    inspect_parser = subcommands.add_parser("inspect")
    inspect_parser.add_argument("--caller", required=True)
    inspect_parser.add_argument("--tenant", required=True)
    inspect_parser.add_argument("--state", type=Path, required=True)
    explain_parser = subcommands.add_parser("explain-finding")
    explain_parser.add_argument("--caller", required=True)
    explain_parser.add_argument("--tenant", required=True)
    explain_parser.add_argument("--finding-id", required=True)
    explain_parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        authorize(args.caller, args.tenant)
        if args.command in {"analyze", "validate-fixtures"}:
            input_events = load_events(args.input)
            if any(event.tenant_id != args.tenant for event in input_events):
                raise ValueError("input contains an event outside the authorized tenant")
            baseline_events = load_events(args.baseline)
            if not any(event.tenant_id == args.tenant for event in baseline_events):
                raise ValueError("baseline contains no event for the authorized tenant")
        if args.command == "validate-fixtures":
            print(json.dumps({"fixture_valid": True, "tenant_id": args.tenant, "input_event_count": len(input_events), "baseline_event_count": len(baseline_events)}, sort_keys=True))
        elif args.command == "analyze":
            ledger = AuditLedger(args.state)
            run_id = str(uuid4())
            logger = configure_logging()
            ledger.append(run_id, args.tenant, "run_started", {"event_count": len(input_events)})
            log_event(logger, "run_started", {"run_id": run_id, "tenant_id": args.tenant, "event_count": len(input_events)})
            findings = analyze(input_events, baseline_events, ledger, run_id, logger)
            ledger.append(run_id, args.tenant, "run_completed", {"finding_count": len(findings)})
            log_event(logger, "run_completed", {"run_id": run_id, "tenant_id": args.tenant, "finding_count": len(findings), "outcome": "completed"})
            print(json.dumps({"run_id": run_id, "findings": findings, "audit_valid": ledger.verify()}, sort_keys=True))
        elif args.command == "inspect":
            ledger = AuditLedger(args.state)
            print(json.dumps({"findings": ledger.findings_for(args.tenant), "audit_valid": ledger.verify()}, sort_keys=True))
        else:
            ledger = AuditLedger(args.state)
            finding = ledger.finding_for(args.tenant, args.finding_id)
            if finding is None:
                raise ValueError("finding is unavailable in the authorized tenant")
            explanation = {
                "finding_id": finding["finding_id"],
                "tenant_id": finding["tenant_id"],
                "risk_score": finding["risk_score"],
                "risk_band": finding["risk_band"],
                "confidence": finding["confidence"],
                "rule_ids": finding["rule_ids"],
                "technique_ids": finding["technique_ids"],
                "evidence_event_count": len(finding["evidence_event_ids"]),
                "anomaly_support_event_count": len(finding["anomaly_support_event_ids"]),
                "uncertainty": finding["uncertainty"],
                "recommendation": finding["recommendation"],
            }
            ledger.append(str(finding["run_id"]), args.tenant, "finding_explained", {"finding_id": str(finding["finding_id"])})
            print(json.dumps({"explanation": explanation, "audit_valid": ledger.verify()}, sort_keys=True))
    except (PermissionError, ValueError, OSError) as error:
        print(json.dumps({"error": "request_rejected", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
