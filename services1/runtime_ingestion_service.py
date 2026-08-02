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
LIFECYCLE_PHASES = {
    "BEFORE_STARTING": {
        "label": "Before Starting",
        "event_types": {"RUNTIME_CREATED", "RUNTIME_STARTING", "RUNTIME_STARTED", "REQUEST_RECEIVED", "INPUT_VALIDATED"},
    },
    "DURING_RUNTIME": {
        "label": "During Runtime",
        "event_types": {"AGENT_STARTED", "AGENT_COMPLETED", "CONTROL_CHECK", "EVIDENCE_ATTACHED", "EVIDENCE_FOUND", "TOOL_CALLED", "LLM_CALLED"},
    },
    "BEFORE_COMPLETION": {
        "label": "Before Completion",
        "event_types": {"DECISION_PROPOSED", "RUNTIME_COMPLETING", "FINAL_CANONICAL_OBJECTS", "PRE_COMPLETION_CHECK"},
    },
    "AFTER_COMPLETION": {
        "label": "After Completion",
        "event_types": {"RUNTIME_COMPLETED", "RUNTIME_FAILED", "AUDIT_WRITTEN", "POST_COMPLETION_AUDIT"},
    },
}


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
    event_type = _safe_text(source.get("event_type") or source.get("status") or "AGENT_EVENT").upper()
    lifecycle_phase = normalize_lifecycle_phase(source.get("lifecycle_phase") or source.get("phase"), event_type)
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "runtime_id": _safe_text(runtime_id),
        "app_id": _safe_text(source.get("app_id") or defaults.get("app_id") or "AEGIS_DEMO_APP"),
        "app_name": _safe_text(source.get("app_name") or defaults.get("app_name") or "Customer 360 AI App"),
        "agent_id": _safe_text(agent_id),
        "agent_name": _safe_text(agent_name),
        "agent_type": _safe_text(source.get("agent_type") or defaults.get("agent_type") or "APPLICATION_AGENT"),
        "event_type": event_type,
        "status": _safe_text(source.get("status") or "RECORDED").upper(),
        "lifecycle_phase": lifecycle_phase,
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


def normalize_lifecycle_phase(value: Any, event_type: str = "") -> str:
    text = _safe_text(value, "").upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "START": "BEFORE_STARTING",
        "STARTING": "BEFORE_STARTING",
        "BEFORE_START": "BEFORE_STARTING",
        "PLANNING": "BEFORE_STARTING",
        "RUNTIME": "DURING_RUNTIME",
        "DURING": "DURING_RUNTIME",
        "EXECUTION": "DURING_RUNTIME",
        "RETRIEVAL": "DURING_RUNTIME",
        "DECISION": "BEFORE_COMPLETION",
        "PRE_COMPLETION": "BEFORE_COMPLETION",
        "COMPLETING": "BEFORE_COMPLETION",
        "COMPLETION": "AFTER_COMPLETION",
        "POST_COMPLETION": "AFTER_COMPLETION",
        "AFTER_COMPLETION": "AFTER_COMPLETION",
    }
    if text in LIFECYCLE_PHASES:
        return text
    if text in aliases:
        return aliases[text]
    event = _safe_text(event_type, "").upper()
    for phase, meta in LIFECYCLE_PHASES.items():
        if event in meta["event_types"]:
            return phase
    if event.endswith("_STARTED") or event in {"STARTED", "RUNNING"}:
        return "DURING_RUNTIME"
    if event.endswith("_COMPLETED") or event in {"COMPLETED", "FAILED"}:
        return "AFTER_COMPLETION"
    return "DURING_RUNTIME"


def lifecycle_summary(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {phase: [] for phase in LIFECYCLE_PHASES}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        phase = normalize_lifecycle_phase(event.get("lifecycle_phase") or event.get("phase"), event.get("event_type"))
        grouped.setdefault(phase, []).append(event)
    rows = []
    for phase, meta in LIFECYCLE_PHASES.items():
        phase_events = grouped.get(phase, [])
        statuses = {str(event.get("status") or "").upper() for event in phase_events}
        event_types = sorted({str(event.get("event_type") or "").upper() for event in phase_events if event.get("event_type")})
        rows.append({
            "Lifecycle Phase": meta["label"],
            "Phase Key": phase,
            "Event Count": len(phase_events),
            "Status": "MISSING" if not phase_events else "FAILED" if "FAILED" in statuses or "ERROR" in statuses else "RUNNING" if "RUNNING" in statuses else "OBSERVED",
            "Event Types": ", ".join(event_types) if event_types else "-",
            "AEGIS Interpretation": "No event emitted for this lifecycle phase." if not phase_events else "AEGIS observed canonical runtime events for this phase.",
        })
    return rows


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
        "lifecycle_summary": lifecycle_summary(normalized),
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
