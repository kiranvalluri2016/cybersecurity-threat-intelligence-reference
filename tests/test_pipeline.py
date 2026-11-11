from __future__ import annotations

import json
import logging
from io import StringIO
from datetime import timedelta
from pathlib import Path

import pytest

from threat_intelligence_reference.audit import AuditLedger
from threat_intelligence_reference.contracts import TelemetryEvent, authorize
from threat_intelligence_reference.mitre_mapping import ATTACK_VERSION
from threat_intelligence_reference.logging_config import log_event
from threat_intelligence_reference.pipeline import analyze, load_events


ROOT = Path(__file__).resolve().parents[1]


def events(name: str):
    return load_events(ROOT / "sample_data" / name / "events.json")


def test_correlated_synthetic_evidence_is_deterministic_and_advisory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    first = analyze(events("scenario_correlated_high_risk"), events("baseline"), ledger, "run-1")
    second = analyze(events("scenario_correlated_high_risk"), events("baseline"), ledger, "run-1")
    assert first[0]["finding_id"] == second[0]["finding_id"]
    assert first[0]["risk_score"] == 100
    assert first[0]["confidence"] == "high"
    assert first[0]["attack_version"] == ATTACK_VERSION
    assert first[0]["technique_ids"] == ["T1041", "T1059", "T1110"]
    assert "no automated action" in first[0]["recommendation"]
    assert len(ledger.findings_for("tenant-alpha")) == 1
    assert ledger.verify()


def test_cross_tenant_identical_entities_do_not_correlate(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    findings = analyze(events("scenario_cross_tenant_negative"), events("baseline"), ledger, "run-cross")
    assert {finding["tenant_id"] for finding in findings} == {"tenant-alpha", "tenant-beta"}
    assert all(finding["risk_score"] < 80 for finding in findings)
    assert all(finding["confidence"] != "high" for finding in findings)


def test_same_tenant_unrelated_entities_do_not_receive_correlation_bonus(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    unrelated = [
        event.model_copy(update={"principal_ref": "principal-unrelated", "host_ref": "host-unrelated"}) if event.event_type == "suspicious_command" else event
        for event in events("scenario_correlated_high_risk")
    ]
    finding = analyze(unrelated, events("baseline"), ledger, "run-unrelated")[0]
    assert finding["risk_score"] <= 75
    assert finding["confidence"] != "high"
    assert "insufficient_entity_or_temporal_relationship" in finding["uncertainty"]


def test_anomaly_without_correlated_rule_evidence_is_not_double_counted(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    finding = analyze(events("scenario_cross_tenant_negative"), events("baseline"), ledger, "run-anomaly")
    alpha = next(item for item in finding if item["tenant_id"] == "tenant-alpha")
    assert alpha["risk_score"] == 70
    assert "anomaly_not_counted_without_correlated_rule_evidence" in alpha["uncertainty"]


def test_entity_linked_evidence_outside_the_time_window_does_not_correlate(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    delayed = [
        event.model_copy(update={"observed_at_utc": event.observed_at_utc + timedelta(minutes=17)}) if event.event_type == "suspicious_command" else event
        for event in events("scenario_correlated_high_risk")
    ]
    finding = analyze(delayed, events("baseline"), ledger, "run-delayed")[0]
    assert finding["risk_score"] <= 75
    assert finding["confidence"] != "high"


def test_reopened_ledger_preserves_findings_and_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite"
    first = AuditLedger(path)
    original = analyze(events("scenario_correlated_high_risk"), events("baseline"), first, "run-restart")[0]
    restarted = AuditLedger(path)
    assert restarted.verify()
    assert restarted.findings_for("tenant-alpha")[0]["finding_id"] == original["finding_id"]


def test_duplicate_collision_and_invalid_contract_fail_closed(tmp_path: Path) -> None:
    payload = json.loads((ROOT / "sample_data" / "baseline" / "events.json").read_text())
    collision = dict(payload[0])
    collision["payload"] = {"failed_count": 99}
    path = tmp_path / "collision.json"
    path.write_text(json.dumps([payload[0], collision]))
    with pytest.raises(ValueError, match="collision"):
        load_events(path)
    with pytest.raises(Exception):
        TelemetryEvent.model_validate({"event_id": "bad", "tenant_id": "wrong", "observed_at_utc": "not-a-time", "source_type": "identity", "event_type": "x", "payload": {}})


def test_trusted_caller_is_independent_of_requested_tenant() -> None:
    authorize("analyst-alpha", "tenant-alpha")
    with pytest.raises(PermissionError):
        authorize("analyst-alpha", "tenant-beta")
    with pytest.raises(PermissionError):
        authorize("invented-caller", "tenant-alpha")


def test_audit_tampering_is_detected(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.append("run-1", "tenant-alpha", "run_started", {"event_count": 1})
    assert ledger.verify()
    import sqlite3
    with sqlite3.connect(tmp_path / "audit.sqlite") as connection:
        connection.execute("update audit set payload = ? where seq = 1", (json.dumps({"action": "forged"}),))
    assert not ledger.verify()


def test_structured_logging_excludes_unapproved_raw_context() -> None:
    stream = StringIO()
    logger = logging.getLogger("test-privacy")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    log_event(logger, "finding_created", {"run_id": "run-1", "tenant_id": "tenant-alpha", "event_count": 2, "payload": "do-not-log", "principal_ref": "principal-private"})
    entry = stream.getvalue()
    assert '"run_id":"run-1"' in entry
    assert "do-not-log" not in entry
    assert "principal-private" not in entry
