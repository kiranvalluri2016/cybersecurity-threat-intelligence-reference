from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import TypedDict
from uuid import NAMESPACE_URL, uuid5

from sklearn.ensemble import IsolationForest

from .audit import AuditLedger
from .contracts import TelemetryEvent
from .logging_config import log_event
from .mitre_mapping import ATTACK_VERSION, MAPPING_VERSION, RULE_MAPPINGS


RISK_POLICY_VERSION = "risk-policy-v1"
CORRELATION_WINDOW = timedelta(minutes=15)


class RuleEvidence(TypedDict):
    rule_id: str
    severity: int
    source: str
    evidence_ids: list[str]
    principal_ref: str | None
    host_ref: str | None


def load_events(path: Path) -> list[TelemetryEvent]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    events = [TelemetryEvent.model_validate(item) for item in payload]
    seen: dict[tuple[str, str], str] = {}
    for event in events:
        key = (event.tenant_id, event.event_id)
        digest = event.canonical_digest()
        if key in seen and seen[key] != digest:
            raise ValueError("event ID collision with differing content")
        seen[key] = digest
    return sorted({(event.tenant_id, event.event_id): event for event in events}.values(), key=lambda event: (event.observed_at_utc, event.event_id))


def _features(event: TelemetryEvent) -> list[float]:
    return [float(event.payload.get("outbound_bytes", 0)), float(event.payload.get("rarity_score", 0)), float(event.payload.get("failed_count", 0))]


def _anomaly_support(events: list[TelemetryEvent], baseline: list[TelemetryEvent]) -> tuple[bool, list[str]]:
    if not baseline:
        return False, ["baseline_missing"]
    model = IsolationForest(random_state=17, contamination=0.15, n_estimators=32).fit([_features(event) for event in baseline])
    scores = model.decision_function([_features(event) for event in events])
    anomalous = [event.event_id for event, score in zip(events, scores, strict=True) if score < 0]
    return bool(anomalous), anomalous


def _within_window(first: RuleEvidence, second: RuleEvidence, by_id: dict[str, TelemetryEvent]) -> bool:
    timestamps = [by_id[event_id].observed_at_utc for event_id in first["evidence_ids"] + second["evidence_ids"]]
    return bool(timestamps) and max(timestamps) - min(timestamps) <= CORRELATION_WINDOW


def _group_within_window(group: list[RuleEvidence], by_id: dict[str, TelemetryEvent]) -> bool:
    timestamps = [by_id[event_id].observed_at_utc for rule in group for event_id in rule["evidence_ids"]]
    return bool(timestamps) and max(timestamps) - min(timestamps) <= CORRELATION_WINDOW


def _auth_burst_rules(events: list[TelemetryEvent]) -> list[RuleEvidence]:
    by_principal: dict[str, list[TelemetryEvent]] = defaultdict(list)
    for event in events:
        if event.source_type == "identity" and event.event_type == "auth_failure" and event.principal_ref:
            by_principal[event.principal_ref].append(event)
    rules: list[RuleEvidence] = []
    for principal, principal_events in sorted(by_principal.items()):
        ordered = sorted(principal_events, key=lambda event: (event.observed_at_utc, event.event_id))
        windows = []
        for start, first in enumerate(ordered):
            window = [event for event in ordered[start:] if event.observed_at_utc - first.observed_at_utc <= CORRELATION_WINDOW]
            if len(window) >= 3:
                windows.append(window)
        if windows:
            selected = sorted(windows, key=lambda window: (-len(window), tuple(event.event_id for event in window)))[0]
            rules.append({"rule_id": "AUTH_FAILURE_BURST", "severity": 55, "source": "identity", "evidence_ids": [event.event_id for event in selected], "principal_ref": principal, "host_ref": None})
    return rules


def _rule_evidence(events: list[TelemetryEvent]) -> list[RuleEvidence]:
    rules = _auth_burst_rules(events)
    for event in events:
        if event.source_type == "endpoint" and event.event_type == "suspicious_command" and float(event.payload.get("rarity_score", 0)) >= 0.8 and event.principal_ref:
            rules.append({"rule_id": "SUSPICIOUS_COMMAND_EXECUTION", "severity": 70, "source": "endpoint", "evidence_ids": [event.event_id], "principal_ref": event.principal_ref, "host_ref": event.host_ref})
        if event.source_type == "network" and event.event_type == "unusual_transfer" and float(event.payload.get("outbound_bytes", 0)) >= 1000 and event.host_ref:
            rules.append({"rule_id": "UNUSUAL_OUTBOUND_TRANSFER", "severity": 60, "source": "network", "evidence_ids": [event.event_id], "principal_ref": event.principal_ref, "host_ref": event.host_ref})
    return rules


def _select_evidence_group(rules: list[RuleEvidence], by_id: dict[str, TelemetryEvent]) -> list[RuleEvidence]:
    """Choose one deterministic candidate group; unrelated rule hits cannot inflate it."""
    candidates: list[list[RuleEvidence]] = [[rule] for rule in rules]
    auth_rules = [rule for rule in rules if rule["source"] == "identity"]
    network_rules = [rule for rule in rules if rule["source"] == "network"]
    for endpoint in (rule for rule in rules if rule["source"] == "endpoint"):
        auth = next((rule for rule in auth_rules if rule["principal_ref"] == endpoint["principal_ref"] and _within_window(rule, endpoint, by_id)), None)
        network = next((rule for rule in network_rules if rule["host_ref"] == endpoint["host_ref"] and _within_window(rule, endpoint, by_id)), None)
        if auth is not None:
            candidates.append([endpoint, auth])
        if network is not None:
            candidates.append([endpoint, network])
        if auth is not None and network is not None:
            combined = [endpoint, auth, network]
            if _group_within_window(combined, by_id):
                candidates.append(combined)
    return sorted(candidates, key=lambda group: (-len({rule["source"] for rule in group}), -max(rule["severity"] for rule in group), -len({rule["rule_id"] for rule in group}), tuple(sorted(event_id for rule in group for event_id in rule["evidence_ids"])) ))[0]


def analyze(events: list[TelemetryEvent], baseline: list[TelemetryEvent], ledger: AuditLedger, run_id: str, logger: logging.Logger | None = None) -> list[dict[str, object]]:
    by_tenant: dict[str, list[TelemetryEvent]] = defaultdict(list)
    for event in events:
        by_tenant[event.tenant_id].append(event)
    findings: list[dict[str, object]] = []
    for tenant_id, tenant_events in sorted(by_tenant.items()):
        tenant_events = sorted(tenant_events, key=lambda event: (event.observed_at_utc, event.event_id))
        event_by_id = {event.event_id: event for event in tenant_events}
        rules = _rule_evidence(tenant_events)
        if not rules:
            continue
        group = _select_evidence_group(rules, event_by_id)
        sources = {rule["source"] for rule in group}
        correlation_bonus = 20 if len(sources) == 3 else 10 if len(sources) == 2 else 0
        evidence_ids = sorted({event_id for rule in group for event_id in rule["evidence_ids"]})
        evidence_events = [event_by_id[event_id] for event_id in evidence_ids]
        anomaly, anomaly_events = _anomaly_support(evidence_events, [event for event in baseline if event.tenant_id == tenant_id])
        rule_ids = sorted({rule["rule_id"] for rule in group})
        technique_ids = sorted({RULE_MAPPINGS[rule_id] for rule_id in rule_ids})
        anomaly_bonus = 10 if anomaly and correlation_bonus else 0
        risk = min(100, max(rule["severity"] for rule in group) + correlation_bonus + (5 if len(technique_ids) >= 2 else 0) + anomaly_bonus)
        confidence = "high" if len(sources) >= 2 else "medium" if anomaly else "low"
        uncertainty = [] if correlation_bonus else ["insufficient_entity_or_temporal_relationship"]
        if not anomaly:
            uncertainty.append("no_anomaly_support")
        elif not correlation_bonus:
            uncertainty.append("anomaly_not_counted_without_correlated_rule_evidence")
        finding_id = str(uuid5(NAMESPACE_URL, f"{run_id}:{tenant_id}:{','.join(evidence_ids)}"))
        finding = {"finding_id": finding_id, "run_id": run_id, "tenant_id": tenant_id, "risk_score": risk, "risk_band": "critical" if risk >= 80 else "high" if risk >= 60 else "moderate", "confidence": confidence, "uncertainty": uncertainty, "rule_ids": rule_ids, "technique_ids": technique_ids, "attack_version": ATTACK_VERSION, "mapping_version": MAPPING_VERSION, "risk_policy_version": RISK_POLICY_VERSION, "evidence_event_ids": evidence_ids, "anomaly_support_event_ids": anomaly_events, "recommendation": "Advisory only: review the correlated synthetic evidence; no automated action is performed."}
        ledger.record_finding(finding)
        if logger is not None:
            log_event(logger, "finding_created", {"run_id": run_id, "tenant_id": tenant_id, "finding_id": finding_id, "event_count": len(evidence_ids), "outcome": finding["risk_band"]})
        findings.append(finding)
    return findings
