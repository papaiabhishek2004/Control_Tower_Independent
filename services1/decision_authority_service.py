"""Shared AEGIS final-decision authority normalization."""

from __future__ import annotations

from typing import Any, Dict


VALID_ACTIONS = {"ACCEPT", "REJECT", "RETRY", "HITL"}


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def decision_route(action: str) -> Dict[str, Any]:
    normalized = str(action or "").upper()
    route = {
        "ACCEPT": "RELEASE",
        "REJECT": "BLOCKED",
        "RETRY": "RETURN_FOR_RETRY",
        "HITL": "PENDING_HITL",
    }.get(normalized, "PENDING_HITL")
    control_status = {
        "ACCEPT": "PASS",
        "REJECT": "BLOCKED",
        "RETRY": "RETRY_REQUIRED",
        "HITL": "REVIEW",
    }.get(normalized, "REVIEW")
    return {
        "aegis_final_decision": normalized,
        "final_recommendation": normalized,
        "effective_release_route": route,
        "control_status": control_status,
        "hitl_required": normalized == "HITL",
        "release_allowed": normalized == "ACCEPT",
    }


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", "-", [], {}):
            return value
    return None


def _update_projection(projection: Dict[str, Any], authority: Dict[str, Any], app_recommendation: Any) -> None:
    projection["aegis_final_decision"] = authority["aegis_final_decision"]
    projection["final_recommendation"] = authority["final_recommendation"]
    projection["recommendation"] = authority["final_recommendation"]
    projection["app_recommendation"] = app_recommendation
    projection["effective_release_route"] = authority["effective_release_route"]
    projection["release_route"] = authority["effective_release_route"]
    projection["control_status"] = authority["control_status"]
    projection["hitl_required"] = authority["hitl_required"]
    projection["human_review_required"] = authority["hitl_required"]
    projection["release_allowed"] = authority["release_allowed"]


def apply_decision_authority(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Make every AEGIS display object obey final_arbitration.aegis_final_decision."""
    state = runtime_state if isinstance(runtime_state, dict) else {}
    arbitration = _safe_dict(state.get("final_arbitration"))
    action = str(arbitration.get("aegis_final_decision") or state.get("aegis_final_decision") or "").upper()
    if action not in VALID_ACTIONS:
        return state

    display = _safe_dict(state.get("canonical_display"))
    packet = _safe_dict(arbitration.get("control_packet"))
    app_recommendation = _first_present(
        state.get("app_recommendation"),
        display.get("app_recommendation"),
        packet.get("app_recommendation"),
        state.get("source_app_recommendation"),
        state.get("recommendation"),
        display.get("recommendation"),
    )
    if app_recommendation:
        state["app_recommendation"] = str(app_recommendation).upper()

    authority = decision_route(action)
    if arbitration.get("hitl_required"):
        authority["hitl_required"] = True
        authority["human_review_required"] = True
        if action == "HITL":
            authority["control_status"] = "REVIEW"
            authority["effective_release_route"] = "PENDING_HITL"

    state["aegis_final_decision"] = authority["aegis_final_decision"]
    state["final_recommendation"] = authority["final_recommendation"]
    state["recommendation"] = authority["final_recommendation"]
    state["effective_release_route"] = authority["effective_release_route"]
    state["control_status"] = authority["control_status"]
    state["hitl_required"] = bool(authority["hitl_required"])
    state["human_review_required"] = bool(authority["hitl_required"])
    state["release_allowed"] = bool(authority["release_allowed"])
    state["final_decision_consistency"] = {
        "status": "PASS",
        "authority": "final_arbitration.aegis_final_decision",
        "aegis_final_decision": authority["aegis_final_decision"],
        "final_recommendation": authority["final_recommendation"],
        "app_recommendation": state.get("app_recommendation"),
        "effective_release_route": authority["effective_release_route"],
        "hitl_required": bool(authority["hitl_required"]),
        "control_status": authority["control_status"],
    }

    display.update({
        "app_recommendation": state.get("app_recommendation"),
        "recommendation": authority["final_recommendation"],
        "final_recommendation": authority["final_recommendation"],
        "aegis_final_decision": authority["aegis_final_decision"],
        "control_status": authority["control_status"],
        "release_route": authority["effective_release_route"],
        "effective_release_route": authority["effective_release_route"],
        "hitl_required": bool(authority["hitl_required"]),
    })
    state["canonical_display"] = display

    measurements = _safe_dict(state.get("canonical_control_tower_measurements"))
    release = _safe_dict(measurements.get("release_assessment"))
    if release or measurements:
        release.update({
            "recommendation": authority["final_recommendation"],
            "final_recommendation": authority["final_recommendation"],
            "app_recommendation": state.get("app_recommendation"),
            "release_route": authority["effective_release_route"],
            "review_required": bool(authority["hitl_required"]),
            "hitl_required": bool(authority["hitl_required"]),
            "release_allowed": bool(authority["release_allowed"]),
            "governance_status": authority["control_status"],
            "control_status": authority["control_status"],
            "rationale": arbitration.get("rationale") or release.get("rationale"),
        })
        measurements["release_assessment"] = release
        state["canonical_control_tower_measurements"] = measurements

    for key in (
        "runtime_summary",
        "decision_snapshot",
        "recommendation_package",
        "executive_package",
        "executive_narrative",
        "control_tower_summary",
        "runtime_health",
        "runtime_health_v2",
        "runtime_telemetry",
        "telemetry",
        "publication_gate",
        "hitl_workflow",
        "human_review_authority",
        "governance",
        "compliance",
        "canonical_values",
    ):
        projection = state.get(key)
        if isinstance(projection, dict):
            _update_projection(projection, authority, state.get("app_recommendation"))

    return state
