"""File-backed operational controls for independent AEGIS Control Tower."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from services1.policy_as_code_service import DEFAULT_POLICY


BASE_DIR = Path(__file__).resolve().parents[1]
RUNTIME_HISTORY_PATH = BASE_DIR / "runtime_history" / "runs.jsonl"
DECISION_OUTBOX_DIR = BASE_DIR / "decision_outbox"
HITL_QUEUE_PATH = BASE_DIR / "hitl_queue" / "reviews.jsonl"
AGENT_REGISTRY_PATH = BASE_DIR / "runtime_registry" / "agent_registry.json"
PROMPT_REGISTRY_PATH = BASE_DIR / "runtime_registry" / "prompt_registry.json"
POLICY_CONFIG_PATH = BASE_DIR / "config" / "aegis_policy.json"
ALERTS_PATH = BASE_DIR / "alerts" / "alerts.jsonl"
API_SPEC_PATH = BASE_DIR / "docs1" / "aegis_decision_api_contract.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")


def _read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        return default
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except Exception:
        return default


def _read_jsonl(path: Path, limit: int = 100) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows[-limit:]


def final_decision_packet(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    state = runtime_state if isinstance(runtime_state, dict) else {}
    arbitration = _safe_dict(state.get("final_arbitration"))
    return {
        "schema_version": "AEGIS-FINAL-DECISION-2026.08",
        "created_at": _now(),
        "runtime_id": state.get("runtime_id"),
        "app_id": state.get("app_id"),
        "aegis_final_decision": arbitration.get("aegis_final_decision"),
        "aegis_final_recommendation": state.get("final_recommendation") or arbitration.get("aegis_final_decision"),
        "app_recommendation": state.get("app_recommendation") or state.get("recommendation") or _safe_dict(state.get("canonical_display")).get("recommendation"),
        "required_action": arbitration.get("required_action"),
        "retry_reason": arbitration.get("retry_reason"),
        "hitl_required": bool(arbitration.get("hitl_required") or state.get("hitl_required")),
        "risk_level": state.get("risk_level") or _safe_dict(state.get("canonical_display")).get("risk_level"),
        "trust_score": state.get("trust_score") or _safe_dict(state.get("canonical_display")).get("trust_score"),
        "confidence": state.get("confidence") or _safe_dict(state.get("canonical_display")).get("confidence"),
        "control_status": state.get("control_status") or _safe_dict(state.get("canonical_display")).get("control_status"),
        "decision_source": arbitration.get("decision_source"),
        "llm_used": arbitration.get("llm_used"),
        "llm_provider": arbitration.get("llm_provider"),
        "llm_model": arbitration.get("llm_model"),
        "fallback_used": arbitration.get("fallback_used"),
        "provider_attempts": arbitration.get("provider_attempts", []),
        "deterministic_guardrail_action": arbitration.get("deterministic_guardrail_action"),
        "rationale": arbitration.get("rationale"),
    }


def write_decision_response(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    packet = final_decision_packet(runtime_state)
    runtime_id = str(packet.get("runtime_id") or "UNKNOWN_RUNTIME")
    app_id = str(packet.get("app_id") or "UNKNOWN_APP")
    path = DECISION_OUTBOX_DIR / app_id / f"{runtime_id}_decision.json"
    _write_json(path, packet)
    packet["response_path"] = str(path)
    return packet


def append_runtime_history(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    row = final_decision_packet(runtime_state)
    row.update({
        "history_type": "RUNTIME_DECISION",
        "ragas_status": _safe_dict(runtime_state.get("ragas_scores")).get("status"),
        "owasp_status": _safe_dict(runtime_state.get("owasp_ai")).get("status"),
        "policy_status": _safe_dict(runtime_state.get("policy_as_code")).get("status"),
    })
    _append_jsonl(RUNTIME_HISTORY_PATH, row)
    return row


def enqueue_hitl_if_required(runtime_state: Dict[str, Any]) -> Dict[str, Any] | None:
    packet = final_decision_packet(runtime_state)
    if not packet.get("hitl_required") and packet.get("aegis_final_decision") != "HITL":
        return None
    row = dict(packet)
    row.update({
        "review_id": f"HITL-{datetime.now().strftime('%Y%m%d%H%M%S')}-{packet.get('runtime_id')}",
        "queue_status": "PENDING_REVIEW",
        "reviewer": "",
        "review_comment": "",
        "override_decision": "",
    })
    _append_jsonl(HITL_QUEUE_PATH, row)
    return row


def emit_alerts(runtime_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    state = runtime_state if isinstance(runtime_state, dict) else {}
    checks = [
        ("HITL_REQUIRED", state.get("hitl_required") or _safe_dict(state.get("final_arbitration")).get("aegis_final_decision") == "HITL"),
        ("OWASP_FAIL", _safe_dict(state.get("owasp_ai")).get("status") in {"FAIL", "REVIEW"}),
        ("RAGAS_FAIL", _safe_dict(state.get("ragas_scores")).get("status") in {"FAIL", "REVIEW"}),
        ("POLICY_BLOCK", _safe_dict(state.get("policy_as_code")).get("status") in {"BLOCK", "REVIEW"}),
    ]
    alerts = []
    for alert_type, active in checks:
        if not active:
            continue
        row = {
            "alert_id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{alert_type}",
            "created_at": _now(),
            "alert_type": alert_type,
            "runtime_id": state.get("runtime_id"),
            "app_id": state.get("app_id"),
            "severity": "CRITICAL" if "FAIL" in alert_type or "BLOCK" in alert_type else "HIGH",
            "status": "OPEN",
        }
        _append_jsonl(ALERTS_PATH, row)
        alerts.append(row)
    return alerts


def seed_agent_registry(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    registry = _read_json(AGENT_REGISTRY_PATH, {"schema_version": "AEGIS-AGENT-REGISTRY-2026.08", "agents": []})
    existing = {(row.get("app_id"), row.get("agent_id")) for row in _safe_list(registry.get("agents")) if isinstance(row, dict)}
    agents = _safe_list(registry.get("agents"))
    for event in _safe_list(runtime_state.get("canonical_runtime_events")):
        if not isinstance(event, dict):
            continue
        key = (event.get("app_id"), event.get("agent_id"))
        if key in existing:
            continue
        existing.add(key)
        agents.append({
            "app_id": event.get("app_id"),
            "agent_id": event.get("agent_id"),
            "agent_name": event.get("agent_name"),
            "agent_type": event.get("agent_type"),
            "expected_phase": event.get("phase"),
            "allowed_tools": [],
            "model": event.get("model"),
            "status": "ACTIVE",
            "updated_at": _now(),
        })
    registry["agents"] = agents
    registry["updated_at"] = _now()
    _write_json(AGENT_REGISTRY_PATH, registry)
    return registry


def seed_prompt_registry(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    registry = _read_json(PROMPT_REGISTRY_PATH, {"schema_version": "AEGIS-PROMPT-REGISTRY-2026.08", "prompts": []})
    existing = {(row.get("app_id"), row.get("prompt_template_id"), row.get("prompt_hash")) for row in _safe_list(registry.get("prompts")) if isinstance(row, dict)}
    prompts = _safe_list(registry.get("prompts"))
    for event in _safe_list(runtime_state.get("canonical_runtime_events")):
        if not isinstance(event, dict) or not (event.get("prompt_template_id") or event.get("prompt_hash")):
            continue
        key = (event.get("app_id"), event.get("prompt_template_id"), event.get("prompt_hash"))
        if key in existing:
            continue
        existing.add(key)
        prompts.append({
            "app_id": event.get("app_id"),
            "prompt_template_id": event.get("prompt_template_id"),
            "prompt_hash": event.get("prompt_hash"),
            "status": "OBSERVED",
            "approved": False,
            "updated_at": _now(),
        })
    registry["prompts"] = prompts
    registry["updated_at"] = _now()
    _write_json(PROMPT_REGISTRY_PATH, registry)
    return registry


def save_policy_config(policy: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(DEFAULT_POLICY)
    payload.update(policy if isinstance(policy, dict) else {})
    payload["updated_at"] = _now()
    _write_json(POLICY_CONFIG_PATH, payload)
    return payload


def load_policy_config() -> Dict[str, Any]:
    return _read_json(POLICY_CONFIG_PATH, dict(DEFAULT_POLICY))


def write_api_contract() -> Dict[str, Any]:
    payload = {
        "name": "AEGIS Decision API Contract",
        "endpoints": [
            {"method": "POST", "path": "/runtime-events", "purpose": "Onboarded app submits JSONL-equivalent events."},
            {"method": "GET", "path": "/decision/{app_id}/{runtime_id}", "purpose": "Onboarded app reads final AEGIS decision packet."},
            {"method": "POST", "path": "/hitl/{review_id}", "purpose": "Reviewer submits HITL outcome."},
        ],
        "decision_values": ["ACCEPT", "REJECT", "RETRY", "HITL"],
        "generated_at": _now(),
    }
    _write_json(API_SPEC_PATH, payload)
    return payload


def complete_operational_cycle(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    response = write_decision_response(runtime_state)
    history = append_runtime_history(runtime_state)
    hitl = enqueue_hitl_if_required(runtime_state)
    alerts = emit_alerts(runtime_state)
    agents = seed_agent_registry(runtime_state)
    prompts = seed_prompt_registry(runtime_state)
    api = write_api_contract()
    result = {
        "decision_response": response,
        "runtime_history": history,
        "hitl_queue_item": hitl,
        "alerts": alerts,
        "agent_registry_count": len(_safe_list(agents.get("agents"))),
        "prompt_registry_count": len(_safe_list(prompts.get("prompts"))),
        "api_contract_path": str(API_SPEC_PATH),
    }
    runtime_state["control_tower_operations"] = result
    return result


def operation_rows() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "Runtime History": _read_jsonl(RUNTIME_HISTORY_PATH, 50),
        "HITL Queue": _read_jsonl(HITL_QUEUE_PATH, 50),
        "Alerts": _read_jsonl(ALERTS_PATH, 50),
        "Agent Registry": _safe_list(_read_json(AGENT_REGISTRY_PATH, {"agents": []}).get("agents")),
        "Prompt Registry": _safe_list(_read_json(PROMPT_REGISTRY_PATH, {"prompts": []}).get("prompts")),
        "Policy Config": [load_policy_config()],
    }
