"""Canonical runtime ingestion contract for AEGIS.

This module is intentionally framework-free. Streamlit, REST APIs, SDKs, or
event-stream consumers can call the same functions to normalize external app
runtime signals into the AEGIS canonical event contract.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


SCHEMA_VERSION = "AEGIS-RUNTIME-EVENT-2026.07"
REQUIRED_EVENT_FIELDS = (
    "runtime_id",
    "app_id",
    "agent_id",
    "agent_name",
    "event_type",
    "status",
    "timestamp",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, default: str = "-") -> str:
    text = str(value).strip() if value is not None else ""
    return text or default


def _safe_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def event_hash(event: Dict[str, Any]) -> str:
    payload = json.dumps(event, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_runtime_event(event: Dict[str, Any], defaults: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Return one canonical runtime event emitted by an onboarded app or AEGIS agent."""
    defaults = defaults or {}
    source = event if isinstance(event, dict) else {}
    runtime_id = source.get("runtime_id") or defaults.get("runtime_id") or "UNKNOWN_RUNTIME"
    agent_name = source.get("agent_name") or source.get("agent") or defaults.get("agent_name") or "UNKNOWN_AGENT"
    agent_id = source.get("agent_id") or source.get("id") or str(agent_name).lower().replace(" ", "_")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "runtime_id": _safe_text(runtime_id),
        "app_id": _safe_text(source.get("app_id") or defaults.get("app_id") or "AEGIS_DEMO_APP"),
        "app_name": _safe_text(source.get("app_name") or defaults.get("app_name") or "Customer 360 AI App"),
        "agent_id": _safe_text(agent_id),
        "agent_name": _safe_text(agent_name),
        "agent_type": _safe_text(source.get("agent_type") or defaults.get("agent_type") or "APPLICATION_AGENT"),
        "event_type": _safe_text(source.get("event_type") or source.get("status") or "AGENT_EVENT").upper(),
        "status": _safe_text(source.get("status") or "RECORDED").upper(),
        "phase": _safe_text(source.get("phase") or defaults.get("phase")),
        "timestamp": _safe_text(source.get("timestamp") or source.get("created_at") or _now()),
        "started_at": source.get("started_at"),
        "completed_at": source.get("completed_at"),
        "execution_order": source.get("execution_order") or source.get("order"),
        "execution_time_ms": _safe_number(
            source.get("execution_time_ms")
            or source.get("duration_ms")
            or source.get("latency_ms")
        ),
        "retry_count": int(_safe_number(source.get("retry_count"), 0)),
        "max_retries": int(_safe_number(source.get("max_retries") or defaults.get("max_retries"), 3)),
        "retry_reason": _safe_text(source.get("retry_reason"), ""),
        "receives_from": source.get("receives_from") or source.get("previous_agents") or [],
        "passes_to": source.get("passes_to") or source.get("next_agents") or [],
        "tool_name": source.get("tool_name") or source.get("tool") or source.get("tool_used"),
        "evidence_ids": source.get("evidence_ids") or [],
        "policy_ids": source.get("policy_ids") or [],
        "tokens": source.get("tokens") or source.get("total_tokens"),
        "cost_usd": source.get("cost_usd") or source.get("estimated_cost_usd"),
        "error_code": source.get("error_code"),
        "error_message": source.get("error_message") or source.get("error"),
        "audit_id": source.get("audit_id") or defaults.get("audit_id"),
    }
    normalized["event_hash"] = event_hash(normalized)
    normalized["contract_status"] = "VALID" if validate_runtime_event(normalized)["valid"] else "INVALID"
    return normalized


def validate_runtime_event(event: Dict[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_EVENT_FIELDS if not event.get(field)]
    return {
        "valid": not missing,
        "missing_fields": missing,
        "schema_version": SCHEMA_VERSION,
    }


def ingest_runtime_events(events: Iterable[Dict[str, Any]], defaults: Dict[str, Any] | None = None) -> Dict[str, Any]:
    normalized = [normalize_runtime_event(event, defaults) for event in events or []]
    invalid = [event for event in normalized if event.get("contract_status") != "VALID"]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ACCEPTED" if not invalid else "ACCEPTED_WITH_CONTRACT_GAPS",
        "event_count": len(normalized),
        "invalid_count": len(invalid),
        "events": normalized,
        "required_fields": list(REQUIRED_EVENT_FIELDS),
        "created_at": _now(),
    }


def events_from_agent_trace(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    defaults = {
        "runtime_id": runtime_state.get("runtime_id"),
        "app_id": runtime_state.get("app_id") or "CUSTOMER_360_AI_APP",
        "app_name": runtime_state.get("app_name") or "Customer 360 AI App",
        "max_retries": runtime_state.get("max_retries", 3),
    }
    rows: List[Dict[str, Any]] = []
    for row in runtime_state.get("agent_trace", []) or []:
        if isinstance(row, dict):
            rows.append(row)
    return ingest_runtime_events(rows, defaults)
