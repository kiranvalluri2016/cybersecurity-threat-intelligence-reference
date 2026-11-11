from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z]+$")
    observed_at_utc: datetime
    source_type: Literal["identity", "endpoint", "network"]
    event_type: str
    principal_ref: str | None = Field(default=None, pattern=r"^principal-[a-z0-9-]+$")
    host_ref: str | None = Field(default=None, pattern=r"^host-[a-z0-9-]+$")
    payload: dict[str, float | str | bool]
    schema_version: Literal["telemetry-v1"] = "telemetry-v1"

    @field_validator("observed_at_utc")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at_utc must include a timezone")
        return value

    def canonical_digest(self) -> str:
        payload = self.model_dump(mode="json")
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


TRUSTED_CALLERS = {"analyst-alpha": "tenant-alpha", "analyst-beta": "tenant-beta"}


def authorize(caller: str, tenant_id: str) -> None:
    if TRUSTED_CALLERS.get(caller) != tenant_id:
        raise PermissionError("trusted caller is not authorized for the requested tenant")
