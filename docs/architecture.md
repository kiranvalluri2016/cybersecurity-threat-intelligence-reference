# Architecture and recovery boundaries

```mermaid
flowchart LR
    Source[Synthetic JSON telemetry] --> Contract[Typed contract and canonical validation]
    Contract --> Partition[Tenant partition and event-time ordering]
    Partition --> Rules[Deterministic identity endpoint network rules]
    Partition --> Baseline[Synthetic tenant baseline]
    Baseline --> IF[Fixed-seed Isolation Forest]
    Rules --> Correlation[Entity and 15-minute correlation]
    IF --> Risk[Versioned risk policy]
    Correlation --> Risk
    Risk --> Finding[Advisory-only finding]
    Finding --> SQLite[(SQLite findings and hash-chain audit)]
    Trusted[Trusted synthetic analyst context] --> CLI[CLI tenant authorization]
    CLI --> Partition
    SQLite --> Inspect[Authorized tenant-scoped inspect and explain]
```

## Isolation and processing

`tenant_id` is required on every event, finding and audit record. A source-bound synthetic execution context authorizes the requested tenant; there is no caller-selectable CLI identity. The CLI tenant value is only a requested scope. A mixed-tenant input is rejected instead of silently filtered. `validate-fixtures` performs this validation without state creation. Stored findings and `explain-finding` lookups both require a tenant predicate, so a known finding ID does not disclose another tenant's record.

Correlation does not arise merely because records share a tenant or time window. An endpoint rule must bridge identity evidence by the same `principal_ref` and/or network evidence by the same `host_ref`, with every evidence record in the 15-minute window. The tenant-local baseline is the only training input to Isolation Forest. An anomaly adds one bounded bonus only when rule evidence is already correlated; it cannot independently create a high-confidence finding.

## Persistence and recovery

SQLite commits finding persistence and its `finding_created` audit record in one local transaction. Every audit hash covers its sequential event number, run ID, tenant ID, sanitized payload, and previous hash. A finding-created record also includes a digest of the persisted finding, which `verify()` rechecks before inspection or explanation returns data. Finding IDs are deterministic from a supplied run, tenant and canonical evidence identifiers; re-running the same analysis with the same run replaces the same finding record rather than creating a second finding identity. A new CLI invocation intentionally receives a new run ID and creates its own local audit evidence. This local design does not claim multi-store atomicity, WORM retention, distributed recovery, or concurrent-writer guarantees.

## Operational boundary

Structured logs include only UTC time, correlation run ID, tenant, bounded counts, finding ID and outcome. They do not include raw telemetry payloads, entity references, URL-like values, credentials or recommendation inputs. The pipeline makes advisory findings only; it does not call a ticketing system, block traffic, modify identity, or execute remediation.
