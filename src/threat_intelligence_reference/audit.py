from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path


def _hash(previous: str, payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(previous.encode() + encoded).hexdigest()


class AuditLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute("create table if not exists audit (seq integer primary key autoincrement, run_id text, tenant_id text, payload text not null, prior_hash text not null, record_hash text not null)")
            connection.execute("create table if not exists findings (finding_id text primary key, run_id text, tenant_id text, finding_json text not null)")

    def append(self, run_id: str, tenant_id: str, action: str, metadata: dict[str, object]) -> None:
        payload = {"action": action, "metadata": metadata}
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute("select record_hash from audit order by seq desc limit 1").fetchone()
            previous = prior[0] if prior else "0" * 64
            connection.execute("insert into audit(run_id, tenant_id, payload, prior_hash, record_hash) values (?, ?, ?, ?, ?)", (run_id, tenant_id, json.dumps(payload, sort_keys=True), previous, _hash(previous, payload)))

    def save_finding(self, finding: dict[str, object]) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("insert or replace into findings(finding_id, run_id, tenant_id, finding_json) values (?, ?, ?, ?)", (finding["finding_id"], finding["run_id"], finding["tenant_id"], json.dumps(finding, sort_keys=True)))

    def verify(self) -> bool:
        previous = "0" * 64
        with sqlite3.connect(self.path) as connection:
            for prior_hash, payload, record_hash in connection.execute("select prior_hash, payload, record_hash from audit order by seq"):
                if prior_hash != previous or _hash(previous, json.loads(payload)) != record_hash:
                    return False
                previous = record_hash
        return True

    def findings_for(self, tenant_id: str) -> list[dict[str, object]]:
        with sqlite3.connect(self.path) as connection:
            return [json.loads(row[0]) for row in connection.execute("select finding_json from findings where tenant_id = ? order by finding_id", (tenant_id,))]

    def finding_for(self, tenant_id: str, finding_id: str) -> dict[str, object] | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("select finding_json from findings where tenant_id = ? and finding_id = ?", (tenant_id, finding_id)).fetchone()
        return json.loads(row[0]) if row else None
