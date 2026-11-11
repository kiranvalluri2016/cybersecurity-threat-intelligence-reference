from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Mapping


SAFE_CONTEXT_FIELDS = frozenset({"run_id", "tenant_id", "finding_id", "event_count", "finding_count", "outcome"})


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("threat_intelligence_reference")
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def log_event(logger: logging.Logger, event: str, context: Mapping[str, object]) -> None:
    """Emit only bounded operational metadata; raw telemetry is never accepted."""
    safe_context = {key: value for key, value in context.items() if key in SAFE_CONTEXT_FIELDS}
    record = {"timestamp_utc": datetime.now(UTC).isoformat(), "event": event, **safe_context}
    logger.info(json.dumps(record, sort_keys=True, separators=(",", ":")))
