# Governance and privacy

The CLI receives a source-bound synthetic execution context rather than a caller-provided analyst identifier. The context is fixed to one tenant in local V1, and a CLI tenant argument never grants authority or changes that identity. Audit records contain sanitized metadata, event IDs, and hash-chain values rather than raw payloads or entity references. SQLite audit history is local evidence, not immutable WORM storage.

The deterministic detector, anomaly model and MITRE mapping supply evidence only. The V1 recommendation is explicitly advisory and cannot trigger remediation. Untrusted telemetry values are validated through an `extra=forbid` contract and are never interpreted as instructions. Anomaly evidence is tenant-local, baseline-only and contributes at most one bounded score bonus after deterministic rule correlation; it does not create a separate duplicated finding.
