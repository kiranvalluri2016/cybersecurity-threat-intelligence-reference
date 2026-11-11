from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def analyze_command(state: Path) -> list[str]:
    return [sys.executable, "-m", "threat_intelligence_reference.cli", "analyze", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_correlated_high_risk/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json"), "--state", str(state)]


def test_cli_analysis_and_tenant_isolated_inspection(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    analyzed = json.loads(subprocess.run(analyze_command(state), check=True, capture_output=True, text=True).stdout)
    assert analyzed["audit_valid"] is True
    inspection = subprocess.run([sys.executable, "-m", "threat_intelligence_reference.cli", "inspect", "--tenant", "tenant-alpha", "--state", str(state)], check=True, capture_output=True, text=True)
    persisted = json.loads(inspection.stdout)
    assert persisted["audit_valid"] is True
    assert persisted["findings"][0]["finding_id"] == analyzed["findings"][0]["finding_id"]


def test_cli_does_not_accept_caller_impersonation_or_cross_tenant_target(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    impersonation = subprocess.run(analyze_command(state)[:4] + ["--caller", "analyst-beta"] + analyze_command(state)[4:], capture_output=True, text=True)
    assert impersonation.returncode == 2
    assert "unrecognized arguments" in impersonation.stderr
    cross_tenant = subprocess.run([sys.executable, "-m", "threat_intelligence_reference.cli", "inspect", "--tenant", "tenant-beta", "--state", str(state)], capture_output=True, text=True)
    assert cross_tenant.returncode == 2
    assert "request_rejected" in cross_tenant.stderr


def test_cli_rejects_mixed_tenant_input_without_state_mutation(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "analyze", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_cross_tenant_negative/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json"), "--state", str(state)]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 2
    assert "request_rejected" in completed.stderr
    assert not state.exists()


def test_validate_fixtures_accepts_authorized_contract_and_rejects_mixed_tenant_input() -> None:
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "validate-fixtures", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_correlated_high_risk/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json")]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    assert json.loads(completed.stdout) == {"baseline_event_count": 3, "fixture_valid": True, "input_event_count": 5, "tenant_id": "tenant-alpha"}
    mixed = subprocess.run(command[: command.index("--input") + 1] + [str(ROOT / "sample_data/scenario_cross_tenant_negative/events.json")] + command[command.index("--input") + 2 :], capture_output=True, text=True)
    assert mixed.returncode == 2
    assert "request_rejected" in mixed.stderr


def test_explain_finding_uses_verified_tenant_scoped_persisted_state(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    analyzed = json.loads(subprocess.run(analyze_command(state), check=True, capture_output=True, text=True).stdout)
    finding_id = analyzed["findings"][0]["finding_id"]
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "explain-finding", "--tenant", "tenant-alpha", "--finding-id", finding_id, "--state", str(state)]
    explained = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
    assert explained["audit_valid"] is True
    assert explained["explanation"]["finding_id"] == finding_id
    assert explained["explanation"]["evidence_event_count"] == 5
    with sqlite3.connect(state) as connection:
        connection.execute("update findings set tenant_id = ? where finding_id = ?", ("tenant-beta", finding_id))
    tampered = subprocess.run(command, capture_output=True, text=True)
    assert tampered.returncode == 2
    assert "audit integrity verification failed" in tampered.stderr
