from __future__ import annotations

import json
import logging
import sqlite3
from datetime import timedelta
from io import StringIO
from pathlib import Path

import pytest

from threat_intelligence_reference.audit import AuditLedger
from threat_intelligence_reference.contracts import TelemetryEvent, authorize
from threat_intelligence_reference.mitre_mapping import ATTACK_VERSION
from threat_intelligence_reference.logging_config import log_event
from threat_intelligence_reference.pipeline import analyze, load_events


ROOT = Path(__file__).resolve().parents[1]


def events(name: str) -> list[TelemetryEvent]:
    return load_events(ROOT / "sample_data" / name / "events.json")


def test_correlated_synthetic_evidence_is_deterministic_and_advisory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    first = analyze(events("scenario_correlated_high_risk"), events("baseline"), ledger, "run-1")
    second = analyze(events("scenario_correlated_high_risk"), events("baseline"), ledger, "run-1")
    assert first[0]["finding_id"] == second[0]["finding_id"]
    assert first[0]["risk_score"] == 100
    assert first[0]["confidence"] == "high"
    assert first[0]["attack_version"] == ATTACK_VERSION
    assert first[0]["rule_ids"] == ["AUTH_FAILURE_BURST", "SUSPICIOUS_COMMAND_EXECUTION", "UNUSUAL_OUTBOUND_TRANSFER"]
    assert first[0]["technique_ids"] == ["T1041", "T1059", "T1110"]
    assert first[0]["evidence_event_ids"] == ["evt-001", "evt-002", "evt-003", "evt-004", "evt-005"]
    assert "no automated action" in first[0]["recommendation"]
    assert len(ledger.findings_for("tenant-alpha")) == 1
    assert ledger.verify()


def test_authentication_burst_requires_identity_events_inside_window_and_is_ordered(tmp_path: Path) -> None:
    identity_events = [event for event in events("scenario_correlated_high_risk") if event.source_type == "identity"]
    first = analyze(list(reversed(identity_events)), events("baseline"), AuditLedger(tmp_path / "ordered.sqlite"), "run-window")
    assert first[0]["rule_ids"] == ["AUTH_FAILURE_BURST"]
    assert first[0]["evidence_event_ids"] == ["evt-001", "evt-002", "evt-003"]
    delayed = [event.model_copy(update={"observed_at_utc": event.observed_at_utc + timedelta(minutes=index * 16)}) for index, event in enumerate(identity_events)]
    assert analyze(delayed, events("baseline"), AuditLedger(tmp_path / "outside.sqlite"), "run-outside") == []


def test_cross_tenant_identical_entities_do_not_correlate(tmp_path: Path) -> None:
    findings = analyze(events("scenario_cross_tenant_negative"), events("baseline"), AuditLedger(tmp_path / "audit.sqlite"), "run-cross")
    assert {finding["tenant_id"] for finding in findings} == {"tenant-alpha", "tenant-beta"}
    assert all(finding["risk_score"] < 80 for finding in findings)
    assert all(finding["confidence"] != "high" for finding in findings)


def test_unrelated_rule_hits_never_inflate_selected_evidence_group(tmp_path: Path) -> None:
    unrelated = [
        event.model_copy(update={"principal_ref": "principal-unrelated", "host_ref": "host-unrelated"}) if event.event_type == "suspicious_command" else event
        for event in events("scenario_correlated_high_risk")
    ]
    finding = analyze(unrelated, events("baseline"), AuditLedger(tmp_path / "audit.sqlite"), "run-unrelated")[0]
    assert finding["risk_score"] == 70
    assert finding["confidence"] != "high"
    assert finding["rule_ids"] == ["SUSPICIOUS_COMMAND_EXECUTION"]
    assert finding["technique_ids"] == ["T1059"]
    assert finding["evidence_event_ids"] == ["evt-004"]


def test_entity_linked_evidence_outside_time_window_does_not_correlate(tmp_path: Path) -> None:
    delayed = [
        event.model_copy(update={"observed_at_utc": event.observed_at_utc + timedelta(minutes=17)}) if event.event_type == "suspicious_command" else event
        for event in events("scenario_correlated_high_risk")
    ]
    finding = analyze(delayed, events("baseline"), AuditLedger(tmp_path / "audit.sqlite"), "run-delayed")[0]
    assert finding["risk_score"] == 70
    assert finding["confidence"] != "high"


def test_three_source_group_requires_one_combined_fifteen_minute_window(tmp_path: Path) -> None:
    stretched = [
        event.model_copy(update={"observed_at_utc": event.observed_at_utc + timedelta(minutes=12)}) if event.event_type == "suspicious_command" else event.model_copy(update={"observed_at_utc": event.observed_at_utc + timedelta(minutes=26)}) if event.event_type == "unusual_transfer" else event
        for event in events("scenario_correlated_high_risk")
    ]
    finding = analyze(stretched, events("baseline"), AuditLedger(tmp_path / "audit.sqlite"), "run-combined-window")[0]
    assert finding["rule_ids"] == ["AUTH_FAILURE_BURST", "SUSPICIOUS_COMMAND_EXECUTION"]
    assert finding["technique_ids"] == ["T1059", "T1110"]
    assert finding["evidence_event_ids"] == ["evt-001", "evt-002", "evt-003", "evt-004"]
    assert finding["risk_score"] < 100
    assert "UNUSUAL_OUTBOUND_TRANSFER" not in finding["rule_ids"]


def test_anomaly_without_correlated_rule_evidence_is_not_double_counted(tmp_path: Path) -> None:
    findings = analyze(events("scenario_cross_tenant_negative"), events("baseline"), AuditLedger(tmp_path / "audit.sqlite"), "run-anomaly")
    alpha = next(item for item in findings if item["tenant_id"] == "tenant-alpha")
    assert alpha["risk_score"] == 70
    assert "anomaly_not_counted_without_correlated_rule_evidence" in alpha["uncertainty"]


def test_reopened_ledger_verifies_sequence_run_tenant_and_finding_digest(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite"
    original = analyze(events("scenario_correlated_high_risk"), events("baseline"), AuditLedger(path), "run-restart")[0]
    restarted = AuditLedger(path)
    assert restarted.verify()
    assert restarted.findings_for("tenant-alpha")[0]["finding_id"] == original["finding_id"]


def test_persisted_finding_or_tenant_tampering_blocks_authoritative_reads(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite"
    finding = analyze(events("scenario_correlated_high_risk"), events("baseline"), AuditLedger(path), "run-tamper")[0]
    with sqlite3.connect(path) as connection:
        connection.execute("update findings set tenant_id = ? where finding_id = ?", ("tenant-beta", finding["finding_id"]))
    ledger = AuditLedger(path)
    assert not ledger.verify()
    with pytest.raises(ValueError, match="integrity"):
        ledger.findings_for("tenant-alpha")


def test_audit_envelope_tampering_is_detected(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.append("run-1", "tenant-alpha", "run_started", {"event_count": 1})
    assert ledger.verify()
    with sqlite3.connect(tmp_path / "audit.sqlite") as connection:
        connection.execute("update audit set run_id = ? where seq = 1", ("forged-run",))
    assert not ledger.verify()


def test_contract_collision_and_source_bound_context_fail_closed(tmp_path: Path) -> None:
    payload = json.loads((ROOT / "sample_data" / "baseline" / "events.json").read_text())
    collision = dict(payload[0])
    collision["payload"] = {"failed_count": 99}
    path = tmp_path / "collision.json"
    path.write_text(json.dumps([payload[0], collision]))
    with pytest.raises(ValueError, match="collision"):
        load_events(path)
    with pytest.raises(Exception):
        TelemetryEvent.model_validate({"event_id": "bad", "tenant_id": "wrong", "observed_at_utc": "not-a-time", "source_type": "identity", "event_type": "x", "payload": {}})
    authorize("tenant-alpha")
    with pytest.raises(PermissionError):
        authorize("tenant-beta")


def test_structured_logging_excludes_unapproved_raw_context() -> None:
    stream = StringIO()
    logger = logging.getLogger("test-privacy")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(stream))
    log_event(logger, "finding_created", {"run_id": "run-1", "tenant_id": "tenant-alpha", "event_count": 2, "payload": "do-not-log", "principal_ref": "principal-private"})
    entry = stream.getvalue()
    assert '"run_id":"run-1"' in entry
    assert "do-not-log" not in entry
    assert "principal-private" not in entry
