# Governance and privacy

Trusted synthetic callers map to one tenant in source-controlled local configuration. A CLI tenant argument never grants authority. Audit records contain sanitized metadata, event IDs, and hash-chain values rather than raw payloads or entity references. SQLite audit history is local evidence, not immutable WORM storage.

The deterministic detector, anomaly model and MITRE mapping supply evidence only. The V1 recommendation is explicitly advisory and cannot trigger remediation. Untrusted telemetry values are validated through an `extra=forbid` contract and are never interpreted as instructions. Anomaly evidence is tenant-local, baseline-only and contributes at most one bounded score bonus after deterministic rule correlation; it does not create a separate duplicated finding.
