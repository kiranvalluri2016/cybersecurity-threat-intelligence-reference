# Telemetry and correlation contracts

Every event has a tenant, opaque entity references, UTC event time, source type, event type, payload, schema version, and tenant-scoped event ID. Events are sorted by event time then ID. Reused IDs with differing canonical content fail closed.

Correlation requires the same tenant plus a valid principal or host relationship and an event-time window of 15 minutes. Identical references from different tenants never correlate.
