# Cybersecurity Threat Intelligence Reference

A local-only cybersecurity detection reference using synthetic identity, endpoint, and network telemetry. It combines deterministic rules, bounded anomaly support, tenant-safe event correlation, versioned MITRE ATT&CK mapping, explainable risk scores, and advisory-only findings.

It is a reference project, not a production security platform.

## What it demonstrates

- Typed telemetry contracts with canonical event validation and duplicate-collision rejection.
- Deterministic detection rules for failed-auth bursts, suspicious command execution, and unusual outbound transfer.
- Tenant, entity, and event-time constrained correlation.
- Synthetic-baseline-only Isolation Forest anomaly support with fixed seed.
- MITRE ATT&CK v20.1 mapping contract with exact mapping version persisted on each finding.
- Deterministic risk, confidence, uncertainty, and advisory-only recommendation logic.
- SQLite audit hash chain and tamper detection.
- Trusted synthetic analyst context that cannot be overridden by a caller-supplied tenant.
- JSON structured logging with only bounded operational metadata.

## Local setup

Verified Phase 0 baseline: Python 3.12.11, SQLite 3.50.3, Pydantic 2.14.3, scikit-learn 1.9.1, and pytest 8.4.2.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
PYTHON_COMMAND=.venv/bin/python ./scripts/validate-local.sh

.venv/bin/threat-intel analyze \
  --tenant tenant-alpha \
  --input sample_data/scenario_correlated_high_risk/events.json \
  --baseline sample_data/baseline/events.json \
  --state /tmp/threat-intel-reference.sqlite

.venv/bin/threat-intel validate-fixtures \
  --tenant tenant-alpha \
  --input sample_data/scenario_correlated_high_risk/events.json \
  --baseline sample_data/baseline/events.json

.venv/bin/threat-intel inspect \
  --tenant tenant-alpha \
  --state /tmp/threat-intel-reference.sqlite

.venv/bin/threat-intel explain-finding \
  --tenant tenant-alpha \
  --finding-id '<persisted-finding-id>' \
  --state /tmp/threat-intel-reference.sqlite
```

The deterministic `scenario_correlated_high_risk` fixture contains an identity failed-auth burst, a related endpoint command and a related network transfer for `tenant-alpha`; it yields one advisory critical finding. `scenario_cross_tenant_negative` deliberately reuses opaque entity strings across tenants and must not correlate them. Run the complete local suite with `.venv/bin/python -m pytest -q`.

`validate-fixtures` performs typed, collision, baseline-presence and tenant-scope checks without creating a state database. `explain-finding` reads only a persisted finding from the source-bound execution context's authorized tenant and returns its bounded scoring basis; it never returns raw telemetry or entity references.

For local V1, every CLI process runs under the source-bound `local-analyst-alpha` synthetic execution context. There is intentionally no caller or analyst selector argument: user-provided CLI text cannot switch tenant identity. A real authentication boundary is outside this reference POC.

## Boundaries

The project does not read real telemetry, download threat intelligence, connect to a SIEM/EDR/SOAR, invoke an LLM, create a ticket, isolate a host, disable an account, or perform remediation. It includes no credentials, GitHub Actions workflow, cloud service, or external network integration.

See [architecture](docs/architecture.md), [data contracts](docs/data-contracts.md), [risk policy](docs/risk-policy.md), [governance](docs/governance.md), and [MITRE mapping](docs/mitre-mapping.md).
