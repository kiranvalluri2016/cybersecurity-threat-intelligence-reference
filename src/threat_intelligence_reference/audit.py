from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash(previous: str, envelope: dict[str, object]) -> str:
    return hashlib.sha256(previous.encode() + _canonical(envelope).encode()).hexdigest()


def _finding_digest(finding: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(finding).encode()).hexdigest()


class AuditLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute("create table if not exists audit (seq integer primary key, run_id text not null, tenant_id text not null, payload text not null, prior_hash text not null, record_hash text not null)")
            connection.execute("create table if not exists findings (finding_id text primary key, run_id text not null, tenant_id text not null, finding_json text not null)")

    def _append(self, connection: sqlite3.Connection, run_id: str, tenant_id: str, action: str, metadata: dict[str, object]) -> None:
        prior = connection.execute("select seq, record_hash from audit order by seq desc limit 1").fetchone()
        seq = (prior[0] + 1) if prior else 1
        previous = prior[1] if prior else "0" * 64
        payload = {"action": action, "metadata": metadata}
        envelope = {"seq": seq, "run_id": run_id, "tenant_id": tenant_id, "payload": payload}
        connection.execute("insert into audit(seq, run_id, tenant_id, payload, prior_hash, record_hash) values (?, ?, ?, ?, ?, ?)", (seq, run_id, tenant_id, _canonical(payload), previous, _hash(previous, envelope)))

    def append(self, run_id: str, tenant_id: str, action: str, metadata: dict[str, object]) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._append(connection, run_id, tenant_id, action, metadata)

    def record_finding(self, finding: dict[str, object]) -> None:
        digest = _finding_digest(finding)
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("insert or replace into findings(finding_id, run_id, tenant_id, finding_json) values (?, ?, ?, ?)", (finding["finding_id"], finding["run_id"], finding["tenant_id"], _canonical(finding)))
            self._append(connection, str(finding["run_id"]), str(finding["tenant_id"]), "finding_created", {"finding_id": str(finding["finding_id"]), "finding_digest": digest, "risk_score": finding["risk_score"], "event_count": len(finding["evidence_event_ids"])})

    def verify(self) -> bool:
        previous = "0" * 64
        expected_seq = 1
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute("select seq, run_id, tenant_id, payload, prior_hash, record_hash from audit order by seq")
            for seq, run_id, tenant_id, payload_text, prior_hash, record_hash in rows:
                payload = json.loads(payload_text)
                envelope = {"seq": seq, "run_id": run_id, "tenant_id": tenant_id, "payload": payload}
                if seq != expected_seq or prior_hash != previous or _hash(previous, envelope) != record_hash:
                    return False
                if payload.get("action") == "finding_created":
                    metadata = payload.get("metadata")
                    if not isinstance(metadata, dict) or not isinstance(metadata.get("finding_id"), str) or not isinstance(metadata.get("finding_digest"), str):
                        return False
                    row = connection.execute("select run_id, tenant_id, finding_json from findings where finding_id = ?", (metadata["finding_id"],)).fetchone()
                    if row is None or row[0] != run_id or row[1] != tenant_id:
                        return False
                    finding = json.loads(row[2])
                    if finding.get("finding_id") != metadata["finding_id"] or finding.get("run_id") != run_id or finding.get("tenant_id") != tenant_id or _finding_digest(finding) != metadata["finding_digest"]:
                        return False
                previous = record_hash
                expected_seq += 1
        return True

    def _require_valid(self) -> None:
        if not self.verify():
            raise ValueError("audit integrity verification failed")

    def findings_for(self, tenant_id: str) -> list[dict[str, object]]:
        self._require_valid()
        with sqlite3.connect(self.path) as connection:
            return [json.loads(row[0]) for row in connection.execute("select finding_json from findings where tenant_id = ? order by finding_id", (tenant_id,))]

    def finding_for(self, tenant_id: str, finding_id: str) -> dict[str, object] | None:
        self._require_valid()
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("select finding_json from findings where tenant_id = ? and finding_id = ?", (tenant_id, finding_id)).fetchone()
        return json.loads(row[0]) if row else None
