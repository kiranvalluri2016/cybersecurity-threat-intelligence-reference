from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cli_analysis_and_tenant_isolated_inspection(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "analyze", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_correlated_high_risk/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json"), "--state", str(state)]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    result = json.loads(completed.stdout)
    assert result["audit_valid"] is True
    inspection = subprocess.run([sys.executable, "-m", "threat_intelligence_reference.cli", "inspect", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--state", str(state)], check=True, capture_output=True, text=True)
    persisted = json.loads(inspection.stdout)
    assert persisted["audit_valid"] is True
    assert persisted["findings"][0]["finding_id"] == result["findings"][0]["finding_id"]
    denied = subprocess.run(command[: command.index("--tenant") + 1] + ["tenant-beta"] + command[command.index("--tenant") + 2 :], capture_output=True, text=True)
    assert denied.returncode != 0


def test_cli_rejects_mixed_tenant_input_without_state_mutation(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "analyze", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_cross_tenant_negative/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json"), "--state", str(state)]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 2
    assert "request_rejected" in completed.stderr
    assert not state.exists()


def test_validate_fixtures_accepts_authorized_contract_and_rejects_mixed_tenant_input(tmp_path: Path) -> None:
    command = [sys.executable, "-m", "threat_intelligence_reference.cli", "validate-fixtures", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_correlated_high_risk/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json")]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    result = json.loads(completed.stdout)
    assert result == {"baseline_event_count": 3, "fixture_valid": True, "input_event_count": 5, "tenant_id": "tenant-alpha"}
    mixed = subprocess.run(command[: command.index("--input") + 1] + [str(ROOT / "sample_data/scenario_cross_tenant_negative/events.json")] + command[command.index("--input") + 2 :], capture_output=True, text=True)
    assert mixed.returncode == 2
    assert "request_rejected" in mixed.stderr


def test_explain_finding_uses_persisted_tenant_scoped_state(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    analyze_command = [sys.executable, "-m", "threat_intelligence_reference.cli", "analyze", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--input", str(ROOT / "sample_data/scenario_correlated_high_risk/events.json"), "--baseline", str(ROOT / "sample_data/baseline/events.json"), "--state", str(state)]
    analyzed = json.loads(subprocess.run(analyze_command, check=True, capture_output=True, text=True).stdout)
    finding_id = analyzed["findings"][0]["finding_id"]
    explain_command = [sys.executable, "-m", "threat_intelligence_reference.cli", "explain-finding", "--caller", "analyst-alpha", "--tenant", "tenant-alpha", "--finding-id", finding_id, "--state", str(state)]
    explained = json.loads(subprocess.run(explain_command, check=True, capture_output=True, text=True).stdout)
    assert explained["audit_valid"] is True
    assert explained["explanation"]["finding_id"] == finding_id
    assert explained["explanation"]["evidence_event_count"] == 5
    cross_tenant = subprocess.run(explain_command[: explain_command.index("--caller") + 1] + ["analyst-beta"] + explain_command[explain_command.index("--caller") + 2 :2] + ["--tenant", "tenant-beta"] + explain_command[explain_command.index("--tenant") + 2 :], capture_output=True, text=True)
    assert cross_tenant.returncode == 2
    assert "request_rejected" in cross_tenant.stderr
