"""LLM final arbitration for AEGIS accept/reject/retry/HITL decisions."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


LOCAL_ENV_FILE = Path(__file__).resolve().parents[1] / ".env.local"
VALID_ACTIONS = {"ACCEPT", "REJECT", "RETRY", "HITL"}


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _local_env_value(key: str, default: str = "") -> str:
    value = os.getenv(key)
    if value:
        return value.strip().strip('"').strip("'")
    if not LOCAL_ENV_FILE.exists():
        return default
    try:
        for raw_line in LOCAL_ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, raw_value = line.split("=", 1)
            if name.strip() == key:
                return raw_value.strip().strip('"').strip("'")
    except Exception:
        return default
    return default


def _control_packet(state: Dict[str, Any]) -> Dict[str, Any]:
    assurance = _safe_dict(state.get("llm_judge_assurance"))
    policy = _safe_dict(state.get("policy_as_code"))
    ragas = _safe_dict(state.get("ragas_scores"))
    query_security = _safe_dict(state.get("query_security"))
    display = _safe_dict(state.get("canonical_display"))
    return {
        "runtime_id": state.get("runtime_id"),
        "app_id": state.get("app_id"),
        "user_query": state.get("user_query") or state.get("query") or state.get("original_query"),
        "app_recommendation": state.get("recommendation") or display.get("recommendation"),
        "deterministic_final_recommendation": state.get("final_recommendation") or display.get("final_recommendation"),
        "risk_level": state.get("risk_level") or display.get("risk_level"),
        "trust_score": state.get("trust_score") or display.get("trust_score"),
        "confidence": state.get("confidence") or display.get("confidence"),
        "control_status": state.get("control_status") or display.get("control_status"),
        "error_code": state.get("error_code") or display.get("error_code"),
        "hitl_required": bool(state.get("hitl_required") or assurance.get("hitl_required")),
        "ragas": {
            "status": ragas.get("status"),
            "overall_score": ragas.get("overall_score"),
            "faithfulness": ragas.get("faithfulness"),
            "answer_relevancy": ragas.get("answer_relevancy"),
            "context_precision": ragas.get("context_precision"),
            "context_recall": ragas.get("context_recall"),
            "llm_success": bool(state.get("ragas_success")),
        },
        "query_security": {
            "status": query_security.get("status"),
            "score": query_security.get("score"),
            "findings": query_security.get("findings", []),
        },
        "llm_judge": {
            "final_verdict": assurance.get("final_verdict"),
            "final_rationale": assurance.get("final_rationale"),
            "verdicts": assurance.get("judge_verdicts", []),
        },
        "policy_as_code": {
            "status": policy.get("status"),
            "release_allowed": policy.get("release_allowed"),
            "failed_count": policy.get("failed_count"),
            "critical_failed_count": policy.get("critical_failed_count"),
            "failed_checks": [row for row in _safe_list(policy.get("checks")) if isinstance(row, dict) and not row.get("passed")],
        },
        "lifecycle_summary": _safe_dict(state.get("canonical_runtime_event_contract")).get("lifecycle_summary", []),
        "missing_variables": [row for row in _safe_list(state.get("canonical_consistency_audit")) if isinstance(row, dict) and row.get("Status") == "MISMATCH"],
    }


def _guardrail_action(packet: Dict[str, Any]) -> str | None:
    if _safe_dict(packet.get("policy_as_code")).get("critical_failed_count", 0):
        return "REJECT"
    if _safe_dict(packet.get("query_security")).get("status") == "FAIL":
        return "REJECT"
    if _safe_dict(packet.get("ragas")).get("status") == "FAIL":
        return "RETRY"
    if packet.get("hitl_required"):
        return "HITL"
    return None


def _fallback_decision(packet: Dict[str, Any], error: str) -> Dict[str, Any]:
    action = _guardrail_action(packet) or "HITL"
    return {
        "decision_id": f"AEGIS-FINAL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "created_at": datetime.now().isoformat(),
        "aegis_final_decision": action,
        "decision_source": "AEGIS_LLM_ARBITRATION_REQUIRED_FALLBACK",
        "llm_used": False,
        "llm_provider": "UNAVAILABLE",
        "llm_model": "UNAVAILABLE",
        "deterministic_guardrail_action": _guardrail_action(packet),
        "rationale": f"Final arbitration LLM could not run: {error}",
        "required_action": "Route to HITL." if action == "HITL" else "Reject response." if action == "REJECT" else "Return to onboarded app for retry.",
        "retry_reason": "Mandatory RAGAS/control failure or LLM arbitration unavailable." if action == "RETRY" else None,
        "hitl_required": action == "HITL",
        "control_packet": packet,
        "error": error,
    }


def run_final_arbitration(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Use an LLM to choose ACCEPT, REJECT, RETRY, or HITL for the final action."""
    state = runtime_state if isinstance(runtime_state, dict) else {}
    packet = _control_packet(state)
    groq_key = _local_env_value("GROQ_API_KEY")
    if not groq_key:
        result = _fallback_decision(packet, "GROQ_API_KEY_REQUIRED_FOR_FINAL_ARBITRATION")
        state["final_arbitration"] = result
        return result
    try:
        from groq import Groq
    except Exception as exc:
        result = _fallback_decision(packet, f"GROQ_PACKAGE_UNAVAILABLE: {exc}")
        state["final_arbitration"] = result
        return result

    model = _local_env_value("AEGIS_GROQ_FINAL_ARBITRATION_MODEL", _local_env_value("AEGIS_GROQ_JUDGE_MODEL", "llama-3.1-8b-instant"))
    prompt = (
        "You are the AEGIS Final Arbitration Judge. Decide the final action for an onboarded agentic app response.\n"
        "Allowed actions: ACCEPT, REJECT, RETRY, HITL.\n"
        "Non-bypassable guardrails: critical policy failure or unsafe query means REJECT; mandatory RAGAS failure means RETRY unless unsafe; HITL is required for unresolved review.\n"
        "Return ONLY JSON with fields: aegis_final_decision, rationale, required_action, retry_reason, hitl_required, confidence.\n\n"
        f"Control packet:\n{json.dumps(packet, default=str)[:12000]}"
    )
    try:
        response = Groq(api_key=groq_key, timeout=int(os.getenv("AEGIS_FINAL_ARBITRATION_TIMEOUT_SECONDS", "20"))).chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "AEGIS Final Arbitration Judge. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=700,
            response_format={"type": "json_object"},
        )
        parsed = json.loads(response.choices[0].message.content or "{}")
        action = str(parsed.get("aegis_final_decision") or "").upper()
        if action not in VALID_ACTIONS:
            action = _guardrail_action(packet) or "HITL"
        guardrail = _guardrail_action(packet)
        if guardrail in {"REJECT", "RETRY"} and action == "ACCEPT":
            action = guardrail
        result = {
            "decision_id": f"AEGIS-FINAL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "created_at": datetime.now().isoformat(),
            "aegis_final_decision": action,
            "decision_source": "AEGIS_LLM_FINAL_ARBITRATION",
            "llm_used": True,
            "llm_provider": "GROQ",
            "llm_model": model,
            "deterministic_guardrail_action": guardrail,
            "rationale": parsed.get("rationale") or "LLM arbitration completed.",
            "required_action": parsed.get("required_action") or action,
            "retry_reason": parsed.get("retry_reason"),
            "hitl_required": bool(parsed.get("hitl_required") or action == "HITL"),
            "confidence": parsed.get("confidence"),
            "control_packet": packet,
        }
    except Exception as exc:
        result = _fallback_decision(packet, str(exc))
    state["final_arbitration"] = result
    state["aegis_final_decision"] = result["aegis_final_decision"]
    return result
