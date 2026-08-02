"""Adapter that ingests canonical runtime events from a JSONL log file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from services1.agentic_app_adapters.base import AgenticAppAdapterInfo, AgenticAppRequest
from services1.control_tower_canonical_service import attach_control_tower_measurements
from services1.runtime_ingestion_service import ingest_runtime_events


class JsonlRuntimeLogAdapter:
    info = AgenticAppAdapterInfo(
        app_id="JSONL_RUNTIME_LOG",
        name="Canonical JSONL Runtime Log",
        kind="EXTERNAL_EVENT_LOG",
        description="Ingests canonical runtime parameters emitted by an external agentic system.",
        emits=[
            "runtime_events",
            "agent_trace",
            "recommendation",
            "risk_level",
            "trust_score",
            "confidence",
            "evidence_ids",
            "tokens",
            "cost_usd",
        ],
    )

    def execute(self, request: AgenticAppRequest) -> Dict[str, Any]:
        path = Path(str(request.metadata.get("path") or request.metadata.get("log_path") or "runtime_events.jsonl"))
        events = _read_jsonl_events(path)
        defaults = {
            "runtime_id": request.metadata.get("runtime_id"),
            "app_id": request.metadata.get("app_id") or self.info.app_id,
            "app_name": request.metadata.get("app_name") or self.info.name,
        }
        contract = ingest_runtime_events(events, defaults)
        final = _latest_final_event(events)
        runtime_id = final.get("runtime_id") or defaults["runtime_id"] or _first_value(events, "runtime_id") or "UNKNOWN_RUNTIME"
        app_id = final.get("app_id") or defaults["app_id"] or _first_value(events, "app_id") or self.info.app_id
        user_query = (
            final.get("user_query")
            or final.get("original_query")
            or final.get("query")
            or _first_value(events, "user_query")
            or _first_value(events, "original_query")
            or _first_value(events, "query")
            or request.user_query
        )
        evidence_ids = _collect_values(events, "evidence_ids")
        evidence_pack = [{"evidence_id": evidence_id, "source": "external_runtime_log"} for evidence_id in evidence_ids]
        emitted_final_fields = {key for key, value in final.items() if value not in (None, "")}
        runtime_state: Dict[str, Any] = {
            "runtime_id": runtime_id,
            "app_id": app_id,
            "app_name": final.get("app_name") or defaults["app_name"],
            "app_kind": self.info.kind,
            "agentic_app_adapter": self.info.app_id,
            "status": str(final.get("status") or "COMPLETED").upper(),
            "runtime_status": str(final.get("status") or "COMPLETED").upper(),
            "customer_id": request.customer_id,
            "query": user_query,
            "user_query": user_query,
            "original_query": user_query,
            "runtime_ingestion": contract,
            "canonical_runtime_event_contract": contract,
            "canonical_runtime_events": contract.get("events", []),
            "agent_trace": _events_to_agent_trace(contract.get("events", [])),
            "evidence_pack": evidence_pack,
            "retrieved_chunks": evidence_pack,
            "proposed_recommendation": str(final.get("recommendation") or request.metadata.get("recommendation") or "").upper(),
            "emitted_canonical_fields": sorted(emitted_final_fields),
            "token_metrics": {
                "total_tokens": final.get("tokens") or final.get("total_tokens") or 0,
                "estimated_cost_usd": final.get("cost_usd") or final.get("estimated_cost_usd") or 0,
            },
            "onboarded_app_contract": {
                "app_id": app_id,
                "app_kind": self.info.kind,
                "source_log_path": str(path),
                "emits": list(self.info.emits),
            },
            "segregation_model": "EXTERNAL_APP_EMITS_CANONICAL_JSONL_TO_AEGIS",
        }
        for field in ("risk_level", "trust_score", "confidence", "control_status", "error_code", "findings"):
            if field in emitted_final_fields:
                runtime_state[field] = final.get(field)
        return attach_control_tower_measurements(runtime_state)


def _read_jsonl_events(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Canonical runtime log not found: {path}")
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                event = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL event at {path}:{line_number}: {exc}") from exc
            if isinstance(event, dict):
                events.append(event)
    return events


def _latest_final_event(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    final_types = {"FINAL_CANONICAL_OBJECTS", "DECISION_EMITTED", "COMPLETED"}
    for event in reversed(events):
        event_type = str(event.get("event_type") or "").upper()
        status = str(event.get("status") or "").upper()
        if event_type in final_types or status == "COMPLETED":
            if any(key in event for key in ("recommendation", "risk_level", "trust_score", "confidence")):
                return event
    return events[-1] if events else {}


def _first_value(events: List[Dict[str, Any]], key: str) -> Any:
    for event in events:
        if event.get(key) not in (None, ""):
            return event.get(key)
    return None


def _collect_values(events: List[Dict[str, Any]], key: str) -> List[Any]:
    values: List[Any] = []
    for event in events:
        raw = event.get(key)
        if isinstance(raw, list):
            values.extend(item for item in raw if item not in values)
        elif raw not in (None, "") and raw not in values:
            values.append(raw)
    return values


def _events_to_agent_trace(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for event in events:
        rows.append({
            "agent": event.get("agent_name") or event.get("agent_id") or "External Agent",
            "agent_name": event.get("agent_name") or event.get("agent_id") or "External Agent",
            "status": event.get("status") or event.get("event_type") or "RECORDED",
            "duration_ms": event.get("execution_time_ms"),
            "phase": event.get("phase"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
        })
    return rows
