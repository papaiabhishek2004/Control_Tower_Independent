"""AEGIS Persona and Decision Tower.

Lightweight Streamlit UI for leaders and reviewers who only need persona
metrics plus the final AEGIS decision, not the full Control Tower dashboard.

Run:
    streamlit run app_persona_decision_tower.py
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services1.agentic_app_adapters import JSONL_RUNTIME_LOG_APP_ID, execute_onboarded_agentic_app
from services1.control_tower_operations_service import (
    complete_operational_cycle,
    load_policy_config,
    operation_rows,
    save_policy_config,
)
from services1.decision_authority_service import apply_decision_authority
from services1.final_arbitration_service import run_final_arbitration
from services1.llm_judge_assurance_service import run_llm_judge_assurance
from services1.onboarded_app_registry_service import app_record, register_app, registry_rows
from services1.policy_as_code_service import evaluate_policy_as_code
from services1.query_security_service import validate_user_queries
from services1.ragas_service import evaluate_rag_quality
from services1.runtime_intelligence_ui_loader import load_runtime_intelligence_ui


st.set_page_config(page_title="AEGIS Persona Decision Tower", page_icon="", layout="wide")


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _metric_value(value: Any) -> str:
    if value in (None, "", "-", [], {}):
        return "-"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def _clean_model_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text or text.lower() == "none":
        return "-"
    normalized = text.replace("\\", "/")
    if "models--" in normalized:
        after = normalized.split("models--", 1)[1]
        model_part = after.split("/snapshots/", 1)[0]
        pieces = [part for part in model_part.split("--") if part]
        if len(pieces) >= 2:
            return f"{pieces[0]}/{'/'.join(pieces[1:])}"
        return model_part.replace("--", "/")
    if normalized.upper() in {"QWEN_LOCAL", "LOCAL_QWEN"}:
        return "Qwen/Qwen2.5-0.5B-Instruct"
    return text


def _model_revision(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if "/snapshots/" in text:
        revision = text.split("/snapshots/", 1)[1].split("/", 1)[0]
        return revision[:12] if revision else "-"
    clean = _clean_model_name(value)
    if clean.startswith("Qwen/Qwen2.5-0.5B-Instruct"):
        return "2.5-0.5B-Instruct"
    if clean.startswith("Qwen/Qwen2.5-1.5B-Instruct"):
        return "2.5-1.5B-Instruct"
    if clean.startswith("Qwen/Qwen2.5-3B-Instruct"):
        return "2.5-3B-Instruct"
    if clean.startswith("llama-"):
        return clean
    return "-"


def _display_provider(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"LOCAL", "QWEN", "QWEN_LOCAL", "LOCAL_QWEN"}:
        return "LOCAL_QWEN"
    if text == "GROQ":
        return "GROQ"
    if not text or text == "NONE":
        return "-"
    return text


def _state_default_model(state: Dict[str, Any]) -> str:
    return (
        state.get("model_version")
        or state.get("model")
        or _safe_dict(state.get("runtime_telemetry")).get("model")
        or _safe_dict(state.get("llm_telemetry")).get("model")
        or "Qwen/Qwen2.5-0.5B-Instruct"
    )


def _policy_signal(policy_id: Any, value: Any, passed: bool) -> Any:
    text = str(value or "").strip()
    if passed and str(policy_id) == "POLICY_OWASP_BLOCK" and text.lower() in {"no blocking finding", "no blocking owasp/security finding"}:
        return "CLEAR - no OWASP/security blocker detected"
    if passed and str(policy_id) == "POLICY_PII_BLOCK" and text.lower() in {"no blocking pii", "no blocking pii finding", "no pii leakage signal"}:
        return "CLEAR - no PII leakage detected"
    return value


def _nested_value(state: Dict[str, Any], source: str) -> Any:
    value: Any = state
    for part in source.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _emitted_fields(state: Dict[str, Any]) -> set:
    return {str(item).casefold() for item in _safe_list(state.get("emitted_canonical_fields"))}


AEGIS_AUTHORED_PREFIXES = (
    "final_arbitration.",
    "final_decision_consistency.",
    "canonical_control_tower_measurements.",
    "release_assessment.",
    "policy_as_code.",
    "ragas_scores.",
    "llm_judge_assurance.",
    "owasp_ai.",
    "query_security.",
    "security_analysis.",
    "customer_health.",
)

AEGIS_AUTHORED_FIELDS = {
    "aegis_final_decision",
    "control_status",
    "effective_release_route",
    "hitl_required",
    "human_review_required",
    "hitl_reasons",
    "error_code",
    "final_recommendation",
    "agentic_app_adapter",
    "customer_health",
    "canonical_consistency_audit",
    "canonical_runtime_event_contract",
}


def _source_parts(source: str) -> List[str]:
    return [
        part.strip().casefold()
        for chunk in str(source or "").replace("+", ",").split(",")
        for part in [chunk.strip()]
        if part
    ]


def _is_aegis_authored(source: str) -> bool:
    parts = _source_parts(source)
    if not parts:
        return False
    return all(part in AEGIS_AUTHORED_FIELDS or any(part.startswith(prefix) for prefix in AEGIS_AUTHORED_PREFIXES) for part in parts)


def _was_emitted(state: Dict[str, Any], source: str) -> bool:
    if _is_aegis_authored(source):
        return False
    emitted = _emitted_fields(state)
    parts = _source_parts(source)
    return bool(parts) and all(part in emitted for part in parts)


def _render_table(title: str, rows: List[Dict[str, Any]]) -> None:
    st.subheader(title)
    if not rows:
        st.info("No data available.")
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _legacy_security_analysis(query_security: Dict[str, Any]) -> Dict[str, Any]:
    findings = _safe_list(query_security.get("findings"))
    status = str(query_security.get("status") or "PASS").upper()
    score = query_security.get("score", 100 if status == "PASS" else 60)
    failed = [str(row.get("finding") or row.get("category")) for row in findings if isinstance(row, dict) and row.get("severity") == "CRITICAL"]
    review = [str(row.get("finding") or row.get("category")) for row in findings if isinstance(row, dict) and row.get("severity") != "CRITICAL"]
    text = json.dumps(findings, default=str).lower()
    prompt_detected = any(term in text for term in ("prompt injection", "system prompt", "developer prompt", "jailbreak"))
    pii_detected = any(term in text for term in ("pii", "sensitive data", "secret", "credential"))
    tool_detected = any(term in text for term in ("tool", "exfiltration", "network", "delete"))
    control_status = "FAIL" if status == "FAIL" else "REVIEW" if status == "REVIEW" else "PASS"
    return {
        "status": control_status,
        "security_status": control_status,
        "security_score": score,
        "risk_level": "HIGH" if status == "FAIL" else "REVIEW" if status == "REVIEW" else "LOW",
        "security_grade": "A" if control_status == "PASS" else "C" if control_status == "REVIEW" else "D",
        "findings": findings,
        "failed_controls": failed,
        "review_controls": review,
        "rationale": query_security.get("rationale"),
        "prompt_injection": {"status": "FAIL" if prompt_detected else "PASS", "detected": prompt_detected},
        "jailbreak_detection": {"status": "FAIL" if prompt_detected else "PASS", "detected": prompt_detected},
        "pii_exposure": {"status": "FAIL" if pii_detected else "PASS", "sensitive_fields": findings if pii_detected else []},
        "data_leakage": {"status": "FAIL" if pii_detected else "PASS", "detected": pii_detected},
        "tool_security": {"status": "FAIL" if tool_detected else "PASS", "unauthorized_tools": findings if tool_detected else []},
        "checks": [
            {"Control": "Prompt Injection", "Status": "FAIL" if prompt_detected else "PASS", "Detected": prompt_detected},
            {"Control": "Jailbreak Detection", "Status": "FAIL" if prompt_detected else "PASS", "Detected": prompt_detected},
            {"Control": "Sensitive Data Exposure", "Status": "FAIL" if pii_detected else "PASS", "Detected": len(findings) if pii_detected else 0},
            {"Control": "Data Leakage", "Status": "FAIL" if pii_detected else "PASS", "Detected": pii_detected},
            {"Control": "Tool Security", "Status": "FAIL" if tool_detected else "PASS", "Detected": len(findings) if tool_detected else 0},
        ],
    }


def _sync_final_decision_authority(state: Dict[str, Any]) -> Dict[str, Any]:
    return apply_decision_authority(state)


def _apply_control_tower_assurance(state: Dict[str, Any]) -> Dict[str, Any]:
    query_security = validate_user_queries(state)
    state["query_security"] = query_security
    state["security_analysis"] = _legacy_security_analysis(query_security)
    state["ragas_scores"] = evaluate_rag_quality(state)
    assurance = run_llm_judge_assurance(state, use_llm=True)
    state["llm_judge_assurance"] = assurance
    security = next((row for row in assurance.get("judge_verdicts", []) if row.get("judge_id") == "security_owasp"), {})
    state["owasp_ai"] = {
        "status": security.get("verdict", "UNKNOWN"),
        "security_score": security.get("score", 0),
        "risk_level": "LOW" if security.get("verdict") == "PASS" else "HIGH" if security.get("verdict") == "FAIL" else "REVIEW",
        "findings": security.get("evidence_refs", []),
        "rationale": security.get("rationale", "-"),
    }
    state["policy_as_code"] = evaluate_policy_as_code(state)
    state["final_arbitration"] = run_final_arbitration(state)
    _sync_final_decision_authority(state)
    complete_operational_cycle(state)
    return state


def _load_runtime(log_path: str, app_id: str, runtime_label: str, objective: str) -> Dict[str, Any]:
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Runtime log not found: {path}")
    state = execute_onboarded_agentic_app(
        customer_id=runtime_label.strip() or app_id.strip() or "EXTERNAL_APP",
        user_query=objective,
        app_id=JSONL_RUNTIME_LOG_APP_ID,
        metadata={
            "path": str(path),
            "app_id": app_id.strip() or "EXTERNAL_AGENTIC_APP",
            "app_name": app_id.strip() or "External Agentic App",
        },
    )
    return _apply_control_tower_assurance(state)


def _jsonl_app_ids(path: Path) -> set:
    app_ids = set()
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if not text:
                    continue
                event = json.loads(text)
                if isinstance(event, dict) and event.get("app_id"):
                    app_ids.add(str(event.get("app_id")).casefold())
    except (OSError, json.JSONDecodeError):
        return set()
    return app_ids


def _latest_jsonl_file(folder_path: str, app_id: str = "") -> Path | None:
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        return None
    files = [path for path in folder.glob("*.jsonl") if path.is_file()]
    clean_app_id = str(app_id or "").strip().casefold()
    if clean_app_id:
        files = [path for path in files if clean_app_id in _jsonl_app_ids(path)]
    if not files:
        return None
    return max(files, key=lambda path: path.stat().st_mtime)


def _file_signature(path: Path) -> str:
    stat = path.stat()
    return f"{path.resolve()}::{stat.st_mtime_ns}::{stat.st_size}"


def _load_watched_runtime(folder_path: str, app_id: str, runtime_label: str, objective: str) -> str:
    latest = _latest_jsonl_file(folder_path, app_id)
    if latest is None:
        return f"No .jsonl runtime log found for app_id={app_id} in watched folder."
    signature = _file_signature(latest)
    if st.session_state.get("watched_runtime_signature") == signature:
        return f"Watching {latest.name}; no new changes."
    st.session_state.persona_decision_state = _load_runtime(str(latest), app_id, runtime_label, objective)
    st.session_state.watched_runtime_signature = signature
    st.session_state.watched_runtime_path = str(latest)
    return f"Loaded {latest.name}."


def _registry_context(app_id: str) -> Dict[str, Any]:
    return app_record(app_id)


def _decision_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    _sync_final_decision_authority(state)
    display = _safe_dict(state.get("canonical_display"))
    arbitration = _safe_dict(state.get("final_arbitration"))
    final_action = str(arbitration.get("aegis_final_decision") or state.get("aegis_final_decision") or "").upper()
    final_recommendation = final_action if final_action in {"ACCEPT", "REJECT", "RETRY", "HITL"} else state.get("final_recommendation") or display.get("final_recommendation")
    app_recommendation = state.get("app_recommendation") or display.get("app_recommendation")
    release = _safe_dict(_safe_dict(state.get("canonical_control_tower_measurements")).get("release_assessment"))
    health = _safe_dict(state.get("customer_health"))
    rows = [
        ("AEGIS Final Decision", final_action or state.get("aegis_final_decision"), "final_arbitration.aegis_final_decision"),
        ("AEGIS Final Recommendation", final_recommendation, "final_recommendation"),
        ("Onboarded App Recommendation", app_recommendation, "recommendation"),
        ("Required Action", arbitration.get("required_action"), "final_arbitration.required_action"),
        ("LLM Arbitration Used", "YES" if arbitration.get("llm_used") else "NO", "final_arbitration.llm_used"),
        ("Risk Level", state.get("risk_level") or display.get("risk_level"), "risk_level"),
        ("Control Status", state.get("control_status") or display.get("control_status"), "control_status"),
        ("HITL Required", "YES" if state.get("hitl_required") else "NO", "hitl_required"),
        ("Effective Release Route", state.get("effective_release_route") or release.get("release_route"), "final_decision_consistency.effective_release_route"),
        ("Decision Consistency", _safe_dict(state.get("final_decision_consistency")).get("status"), "final_decision_consistency.status"),
        ("Trust Score", state.get("trust_score") or display.get("trust_score"), "trust_score"),
        ("Confidence", state.get("confidence") or display.get("confidence"), "confidence"),
        ("Relationship Score", health.get("relationship_score"), "customer_health.relationship_score"),
        ("Overall Health", health.get("health_score"), "customer_health.health_score"),
    ]
    return [_variable_row(state, "Decision Object", label, value, source) for label, value, source in rows]


def _source_label(state: Dict[str, Any], field: str) -> str:
    return "App emitted, AEGIS normalized" if _was_emitted(state, field) else "AEGIS calculated"


def _variable_row(state: Dict[str, Any], label_col: str, label: str, value: Any, source: str) -> Dict[str, Any]:
    emitted = _was_emitted(state, source)
    has_value = value not in (None, "", "-", [], {})
    aegis_authored = _is_aegis_authored(source)
    return {
        label_col: label,
        "Variable Name": source,
        "Value": _metric_value(value),
        "Emitted by Onboarded App": "YES" if emitted else "NO",
        "AEGIS System Calculated": "YES" if aegis_authored or (has_value and not emitted) else "NO",
        "Status": "AEGIS CALCULATED" if aegis_authored and has_value else "APP EMITTED" if emitted else "AEGIS CALCULATED" if has_value else "MISSING",
        "Guidance": "AEGIS-derived control value." if aegis_authored and has_value else "Received from onboarded app." if emitted else "Not emitted by Onboarded App; AEGIS calculated it." if has_value else f"Required variable not emitted from Onboarded App: {source}",
    }


def _persona_rows(state: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    display = _safe_dict(state.get("canonical_display"))
    release = _safe_dict(_safe_dict(state.get("canonical_control_tower_measurements")).get("release_assessment"))
    health = _safe_dict(state.get("customer_health"))
    contract = _safe_dict(state.get("canonical_runtime_event_contract"))
    consistency = _safe_list(state.get("canonical_consistency_audit"))
    mismatches = [row for row in consistency if isinstance(row, dict) and row.get("Status") == "MISMATCH"]
    evidence_count = state.get("evidence_count", display.get("evidence_count", 0))
    cost = state.get("estimated_cost_usd", display.get("estimated_cost_usd", 0))

    return {
        "Executive": [
            _persona_metric("Governed outcome", state.get("final_recommendation") or display.get("final_recommendation"), "Can the app outcome be consumed?", "final_recommendation"),
            _persona_metric("App proposed recommendation", state.get("app_recommendation") or display.get("app_recommendation") or display.get("recommendation"), "What the onboarded app requested before AEGIS controls.", "recommendation"),
            _persona_metric("Release route", release.get("release_route"), "Shows release, monitor, or HITL path.", "release_assessment.release_route"),
            _persona_metric("Trust and confidence", f"Trust {_metric_value(state.get('trust_score'))} | Confidence {_metric_value(state.get('confidence'))}", "Reliability of the decision.", "trust_score, confidence"),
            _persona_metric("Business health", f"Relationship {_metric_value(health.get('relationship_score'))} | Health {_metric_value(health.get('health_score'))}", "AEGIS executive score-card signal.", "customer_health"),
            _persona_metric("Cost", cost, "Current run cost for value tracking.", "estimated_cost_usd"),
        ],
        "Risk / Governance": [
            _persona_metric("Risk level", state.get("risk_level") or display.get("risk_level"), "Final AEGIS risk classification.", "risk_level"),
            _persona_metric("Control status", state.get("control_status") or display.get("control_status"), "Mandatory control outcome.", "control_status"),
            _persona_metric("HITL required", "YES" if state.get("hitl_required") else "NO", "Manual review routing decision.", "hitl_required"),
            _persona_metric("HITL reasons", "; ".join(str(item) for item in _safe_list(state.get("hitl_reasons"))) or "-", "Why review is required.", "hitl_reasons"),
            _persona_metric("Consistency mismatches", len(mismatches), "Canonical projection mismatch count.", "canonical_consistency_audit"),
        ],
        "AI Platform": [
            _persona_metric("Runtime", state.get("runtime_id"), "Runtime being governed.", "runtime_id"),
            _persona_metric("App ID", state.get("app_id"), "Onboarded app identity.", "app_id"),
            _persona_metric("Events received", contract.get("event_count", 0), "JSONL event volume ingested by AEGIS.", "canonical_runtime_event_contract.events"),
            _persona_metric("Evidence count", evidence_count, "Evidence objects available to audit.", "evidence_count"),
            _persona_metric("Telemetry source", state.get("agentic_app_adapter"), "Adapter used to onboard the app.", "agentic_app_adapter"),
        ],
        "Audit / Regulator": [
            _persona_metric("Audit status", "READY" if not mismatches else "REVIEW", "Whether canonical display is internally consistent.", "canonical_consistency_audit"),
            _persona_metric("Mismatch count", len(mismatches), "Number of canonical mismatches.", "canonical_consistency_audit"),
            _persona_metric("Evidence count", evidence_count, "Evidence available for review.", "evidence_pack"),
            _persona_metric("Event contract status", contract.get("status"), "Runtime event contract acceptance status.", "canonical_runtime_event_contract.status"),
            _persona_metric("Schema version", contract.get("schema_version"), "AEGIS runtime event schema.", "canonical_runtime_event_contract.schema_version"),
        ],
    }


def _persona_metric(metric: str, value: Any, meaning: str, source: str) -> Dict[str, Any]:
    return {
        "Metric": metric,
        "Live Value": _metric_value(value),
        "Why It Matters": meaning,
        "Source Variable": source,
    }


def _persona_value_audit_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    final_decision = str(state.get("aegis_final_decision") or _safe_dict(state.get("final_arbitration")).get("aegis_final_decision") or "").upper()
    route = str(state.get("effective_release_route") or "").upper()
    control_status = str(state.get("control_status") or "").upper()
    hitl_required = bool(state.get("hitl_required") or final_decision == "HITL")
    for persona, metrics in _persona_rows(state).items():
        for row in metrics:
            source = str(row.get("Source Variable") or "")
            value = row.get("Live Value")
            emitted = _was_emitted(state, source)
            aegis_authored = _is_aegis_authored(source)
            issue = "PASS"
            guidance = "Value source is clear."
            if source == "hitl_reasons" and not hitl_required and value in (None, "", "-", [], {}):
                issue = "NOT_REQUIRED"
                guidance = "HITL is not required for this run, so HITL reasons are not applicable."
            elif value in (None, "", "-"):
                issue = "MISSING"
                guidance = f"Required persona value is not available from source: {source}"
            elif aegis_authored and emitted:
                issue = "SOURCE_ERROR"
                guidance = "AEGIS-authored value was incorrectly marked as app-emitted."
            elif "Release route" in str(row.get("Metric")) and final_decision == "REJECT" and "RELEASE" in str(value).upper():
                issue = "CONFLICT"
                guidance = "Rejected decisions must not show RELEASE route."
            elif "Control status" in str(row.get("Metric")) and final_decision == "REJECT" and control_status != "BLOCKED":
                issue = "CONFLICT"
                guidance = "Rejected decisions must have BLOCKED control status."
            elif "HITL required" in str(row.get("Metric")) and final_decision == "HITL" and str(value).upper() != "YES":
                issue = "CONFLICT"
                guidance = "HITL final decision must show HITL required."
            rows.append({
                "Persona": persona,
                "Metric": row.get("Metric"),
                "Displayed Value": value,
                "Source Variable": source,
                "App Emitted": "YES" if emitted else "NO",
                "AEGIS Calculated": "YES" if aegis_authored or (value not in (None, "", "-") and not emitted and issue != "NOT_REQUIRED") else "NO",
                "Audit Status": issue,
                "Guidance": guidance,
            })
    rows.append({
        "Persona": "Decision Authority",
        "Metric": "Final route consistency",
        "Displayed Value": f"{final_decision} -> {route or '-'} / {control_status or '-'}",
        "Source Variable": "final_arbitration + final_decision_consistency",
        "App Emitted": "NO",
        "AEGIS Calculated": "YES",
        "Audit Status": "PASS" if _safe_dict(state.get("final_decision_consistency")).get("status") == "PASS" else "REVIEW",
        "Guidance": "Final arbitration is the authority for route and control status.",
    })
    return rows


def _missing_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    required = [
        ("Runtime ID", "runtime_id"),
        ("App ID", "app_id"),
        ("Agent ID", "agent_id"),
        ("Agent Name", "agent_name"),
        ("Event Type", "event_type"),
        ("Status", "status"),
        ("Timestamp", "timestamp"),
        ("Final Recommendation", "final_recommendation"),
        ("Recommendation", "recommendation"),
        ("Risk Level", "risk_level"),
        ("Trust Score", "trust_score"),
        ("Confidence", "confidence"),
        ("Control Status", "control_status"),
        ("Error Code", "error_code"),
        ("HITL Required", "hitl_required"),
        ("HITL Reasons", "hitl_reasons"),
        ("Release Route", "canonical_control_tower_measurements.release_assessment.release_route"),
        ("Relationship Score", "customer_health.relationship_score"),
        ("Engagement Score", "customer_health.engagement_score"),
        ("Portfolio Score", "customer_health.portfolio_score"),
        ("Overall Health", "customer_health.health_score"),
        ("Evidence Count", "evidence_count"),
        ("Estimated Cost USD", "estimated_cost_usd"),
    ]
    events = _safe_list(_safe_dict(state.get("canonical_runtime_event_contract")).get("events"))
    display = _safe_dict(state.get("canonical_display"))
    rows = []
    for label, source in required:
        value = _nested_value(state, source)
        if value in (None, "", "-", [], {}) and "." not in source:
            value = display.get(source)
        if source in {"agent_id", "agent_name", "event_type", "status", "timestamp"}:
            value = value or next((event.get(source) for event in events if isinstance(event, dict) and event.get(source) not in (None, "", "-")), None)
        rows.append(_variable_row(state, "Control Tower Variable", label, value, source))
    return rows


def _lifecycle_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    contract = _safe_dict(state.get("canonical_runtime_event_contract"))
    rows = _safe_list(contract.get("lifecycle_summary"))
    if rows:
        return rows
    return [
        {
            "Lifecycle Phase": label,
            "Phase Key": key,
            "Event Count": 0,
            "Status": "MISSING",
            "Event Types": "-",
            "AEGIS Interpretation": "No event emitted for this lifecycle phase.",
        }
        for key, label in [
            ("BEFORE_STARTING", "Before Starting"),
            ("DURING_RUNTIME", "During Runtime"),
            ("BEFORE_COMPLETION", "Before Completion"),
            ("AFTER_COMPLETION", "After Completion"),
        ]
    ]


def _llm_judge_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    assurance = _safe_dict(state.get("llm_judge_assurance"))
    default_model = _state_default_model(state)
    rows = []
    for row in _safe_list(assurance.get("judge_verdicts")):
        if not isinstance(row, dict):
            continue
        raw_model = row.get("judge_model") or row.get("model") or _safe_dict(row.get("telemetry")).get("model") or default_model
        rows.append({
            "Judge": row.get("judge_name") or row.get("judge_id"),
            "Verdict": row.get("verdict"),
            "Score": row.get("score"),
            "Confidence": row.get("confidence"),
            "Engine": row.get("judge_engine") or row.get("engine"),
            "Provider": _display_provider(row.get("provider") or row.get("judge_engine") or row.get("engine")),
            "Model": _clean_model_name(raw_model),
            "Model Version / Revision": _model_revision(raw_model),
            "Rationale": row.get("rationale"),
        })
    return rows


def _owasp_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    owasp = _safe_dict(state.get("owasp_ai"))
    return [
        {
            "OWASP AI Control": "Security / OWASP Judge",
            "Status": owasp.get("status"),
            "Score": owasp.get("security_score"),
            "Risk Level": owasp.get("risk_level"),
            "Findings": "; ".join(str(item) for item in _safe_list(owasp.get("findings"))) or "-",
            "Rationale": owasp.get("rationale"),
        }
    ]


def _query_security_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    query_security = _safe_dict(state.get("query_security"))
    findings = _safe_list(query_security.get("findings"))
    if not findings:
        return [{
            "Source": "runtime query/events",
            "Status": query_security.get("status", "PASS"),
            "Severity": "-",
            "OWASP Category": "User Query Validation",
            "Finding": query_security.get("rationale", "No unsafe user-query patterns detected."),
            "Query Excerpt": "-",
        }]
    return [
        {
            "Source": row.get("source"),
            "Status": "FAIL" if row.get("severity") == "CRITICAL" else "REVIEW",
            "Severity": row.get("severity"),
            "OWASP Category": row.get("category"),
            "Finding": row.get("finding"),
            "Query Excerpt": row.get("query_excerpt"),
        }
        for row in findings
        if isinstance(row, dict)
    ]


def _policy_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    policy = _safe_dict(state.get("policy_as_code"))
    rows = []
    for row in _safe_list(policy.get("checks")):
        if not isinstance(row, dict):
            continue
        passed = bool(row.get("passed"))
        rows.append({
            "Policy ID": row.get("policy_id"),
            "Gate Result": "PASS" if passed else "FAIL",
            "Severity": row.get("severity"),
            "Observed Signal": _policy_signal(row.get("policy_id"), row.get("actual"), passed),
            "Required Condition": row.get("expected"),
            "Action If Failed": row.get("action"),
        })
    return rows


def _ragas_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    ragas = _safe_dict(state.get("ragas_scores") or state.get("ragas"))
    return [
        {"RAGAS Metric": "Overall Score", "Value": ragas.get("overall_score"), "Status": ragas.get("status"), "Source": "AEGIS RAGAS LLM evaluation"},
        {"RAGAS Metric": "Faithfulness", "Value": ragas.get("faithfulness"), "Status": ragas.get("status"), "Source": "Evidence + trust"},
        {"RAGAS Metric": "Answer Relevancy", "Value": ragas.get("answer_relevancy"), "Status": ragas.get("status"), "Source": "Validated/retrieved chunks"},
        {"RAGAS Metric": "Context Precision", "Value": ragas.get("context_precision"), "Status": ragas.get("status"), "Source": "Evidence pack"},
        {"RAGAS Metric": "Context Recall", "Value": ragas.get("context_recall"), "Status": ragas.get("status"), "Source": "Validated/retrieved chunks"},
        {"RAGAS Metric": "LLM Confidence", "Value": ragas.get("confidence"), "Status": "COMPLETED" if state.get("ragas_success") else "FAILED", "Source": _safe_dict(ragas.get("ragas_llm")).get("provider", "LLM runtime")},
    ]


def _final_arbitration_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    arbitration = _safe_dict(state.get("final_arbitration"))
    return [
        {"Decision Field": "AEGIS Final Decision", "Value": arbitration.get("aegis_final_decision"), "Meaning": "Final action for onboarded app response"},
        {"Decision Field": "Decision Source", "Value": arbitration.get("decision_source"), "Meaning": "LLM arbitration or mandatory fallback"},
        {"Decision Field": "LLM Used", "Value": "YES" if arbitration.get("llm_used") else "NO", "Meaning": "Whether final action came from LLM call"},
        {"Decision Field": "LLM Provider", "Value": arbitration.get("llm_provider"), "Meaning": "Final arbitration provider"},
        {"Decision Field": "LLM Model", "Value": arbitration.get("llm_model"), "Meaning": "Final arbitration model"},
        {"Decision Field": "Guardrail Action", "Value": arbitration.get("deterministic_guardrail_action"), "Meaning": "Non-bypassable deterministic guardrail"},
        {"Decision Field": "Required Action", "Value": arbitration.get("required_action"), "Meaning": "What AEGIS sends back or routes next"},
        {"Decision Field": "Retry Reason", "Value": arbitration.get("retry_reason"), "Meaning": "Reason when response is returned for retry"},
        {"Decision Field": "HITL Required", "Value": "YES" if arbitration.get("hitl_required") else "NO", "Meaning": "Human review routing"},
        {"Decision Field": "Rationale", "Value": arbitration.get("rationale"), "Meaning": "Evidence-backed arbitration rationale"},
    ]


def _llm_execution_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    ragas = _safe_dict(state.get("ragas_scores"))
    ragas_llm = _safe_dict(ragas.get("ragas_llm") or state.get("ragas_llm"))
    assurance = _safe_dict(state.get("llm_judge_assurance"))
    verdicts = [row for row in _safe_list(assurance.get("judge_verdicts")) if isinstance(row, dict)]
    llm_judge_used = any(not row.get("fallback_used") and str(row.get("provider") or "").upper() not in {"", "AEGIS_DETERMINISTIC"} for row in verdicts)
    fallback_count = sum(1 for row in verdicts if row.get("fallback_used"))
    providers = sorted({_display_provider(row.get("provider") or row.get("judge_engine") or row.get("engine")) for row in verdicts if row.get("provider") or row.get("judge_engine") or row.get("engine")})
    default_model = _state_default_model(state)
    judge_models = [
        row.get("judge_model") or row.get("model") or _safe_dict(row.get("telemetry")).get("model") or default_model
        for row in verdicts
    ]
    models = sorted({_clean_model_name(model) for model in judge_models if _clean_model_name(model) != "-"})
    model_revisions = sorted({_model_revision(model) for model in judge_models if _model_revision(model) != "-"})
    arbitration = _safe_dict(state.get("final_arbitration"))
    ragas_model = ragas_llm.get("model") or default_model
    arbitration_model = arbitration.get("llm_model") or default_model
    return [
        {
            "LLM Component": "RAGAS Evaluation",
            "Executed Successfully": "YES" if ragas_llm.get("success") else "NO",
            "Provider": _display_provider(ragas_llm.get("provider", "-")),
            "Model": _clean_model_name(ragas_model),
            "Model Version / Revision": _model_revision(ragas_model),
            "Status": ragas.get("status", "-"),
            "Fallback Used": "NO",
            "Error / Reason": ragas_llm.get("error", "-"),
        },
        {
            "LLM Component": "LLM Judge Committee",
            "Executed Successfully": "YES" if llm_judge_used else "NO",
            "Provider": ", ".join(providers) or "-",
            "Model": ", ".join(models) or "-",
            "Model Version / Revision": ", ".join(model_revisions) or "-",
            "Status": assurance.get("final_verdict", "-"),
            "Fallback Used": "YES" if fallback_count else "NO",
            "Error / Reason": f"{fallback_count} deterministic fallback judge(s)" if fallback_count else assurance.get("final_rationale", "-"),
        },
        {
            "LLM Component": "Final Arbitration Judge",
            "Executed Successfully": "YES" if arbitration.get("llm_used") else "NO",
            "Provider": _display_provider(arbitration.get("llm_provider", "-")),
            "Model": _clean_model_name(arbitration_model),
            "Model Version / Revision": _model_revision(arbitration_model),
            "Status": arbitration.get("aegis_final_decision", "-"),
            "Fallback Used": "NO" if arbitration.get("llm_used") else "YES",
            "Error / Reason": arbitration.get("error") or arbitration.get("rationale", "-"),
        },
    ]


def _operations_summary_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    ops = _safe_dict(state.get("control_tower_operations"))
    decision = _safe_dict(ops.get("decision_response"))
    hitl = _safe_dict(ops.get("hitl_queue_item"))
    return [
        {
            "Capability": "Response Return File",
            "Status": "WRITTEN" if decision.get("response_path") else "NOT WRITTEN",
            "Location / Value": decision.get("response_path", "-"),
            "Purpose": "Final ACCEPT / REJECT / RETRY / HITL packet for onboarded app.",
        },
        {
            "Capability": "HITL Review Queue",
            "Status": hitl.get("queue_status", "NOT REQUIRED"),
            "Location / Value": hitl.get("review_id", "-"),
            "Purpose": "Manual review queue when AEGIS routes the run to HITL.",
        },
        {
            "Capability": "Agent Registry",
            "Status": "UPDATED",
            "Location / Value": ops.get("agent_registry_count", 0),
            "Purpose": "Observed agents maintained for onboarding governance.",
        },
        {
            "Capability": "Prompt Template Registry",
            "Status": "UPDATED",
            "Location / Value": ops.get("prompt_registry_count", 0),
            "Purpose": "Observed prompt templates and hashes tracked for optimization.",
        },
        {
            "Capability": "Runtime History Store",
            "Status": "APPENDED",
            "Location / Value": "runtime_history/runs.jsonl",
            "Purpose": "Persistent execution history across apps and runs.",
        },
        {
            "Capability": "Decision Webhook/API Contract",
            "Status": "AVAILABLE",
            "Location / Value": ops.get("api_contract_path", "docs1/aegis_decision_api_contract.json"),
            "Purpose": "Contract for submit events, read decision, and HITL callback.",
        },
        {
            "Capability": "Alerting",
            "Status": f"{len(_safe_list(ops.get('alerts')))} emitted",
            "Location / Value": "alerts/alerts.jsonl",
            "Purpose": "Open alerts for HITL, OWASP, RAGAS, and policy blockers.",
        },
    ]


def _render_policy_editor() -> None:
    policy = load_policy_config()
    st.subheader("Control Policy")
    c1, c2, c3 = st.columns(3)
    trust_min = c1.number_input("Auto-approval trust minimum", min_value=0.0, max_value=100.0, value=float(policy.get("trust_min_for_auto_approval", 70.0)), step=1.0)
    confidence_min = c2.number_input("Auto-approval confidence minimum", min_value=0.0, max_value=100.0, value=float(policy.get("confidence_min_for_auto_approval", 60.0)), step=1.0)
    evidence_min = c3.number_input("Minimum evidence count", min_value=0, max_value=100, value=int(policy.get("minimum_evidence_count", 1)), step=1)
    c1, c2, c3 = st.columns(3)
    block_owasp = c1.toggle("Block on OWASP fail", value=bool(policy.get("block_on_owasp_fail", True)))
    block_pii = c2.toggle("Block on PII", value=bool(policy.get("block_on_pii", True)))
    max_retries = c3.number_input("Max retries", min_value=0, max_value=10, value=int(policy.get("max_retries", 3)), step=1)
    risk_text = st.text_input(
        "Risk levels requiring HITL",
        value=", ".join(str(item) for item in _safe_list(policy.get("require_hitl_for_risk_levels"))),
    )
    if st.button("Save Control Policy", use_container_width=True):
        save_policy_config({
            "trust_min_for_auto_approval": trust_min,
            "confidence_min_for_auto_approval": confidence_min,
            "minimum_evidence_count": evidence_min,
            "max_retries": max_retries,
            "block_on_owasp_fail": block_owasp,
            "block_on_pii": block_pii,
            "require_hitl_for_risk_levels": [item.strip().upper() for item in risk_text.split(",") if item.strip()],
        })
        st.success("Control policy saved.")


@st.cache_resource
def _runtime_ui():
    return load_runtime_intelligence_ui()


st.title("AEGIS Persona Decision Tower")
st.caption("Persona-specific view plus AEGIS final decision for onboarded agentic applications.")

with st.sidebar:
    st.header("External App Runtime")
    app_id = st.text_input("External App ID", value="EXT_APP")
    app_name = st.text_input("External App Name", value="External Agentic App")
    app_owner = st.text_input("Owner / Team", value="")
    runtime_label = st.text_input("Runtime / Entity Label", value="APP-RUN-001")
    objective = st.text_area("Run Objective", value="External agentic app execution", height=90)
    mode = st.radio("Ingestion Mode", ["Manual Log File", "Watch Folder"], horizontal=False)
    if mode == "Manual Log File":
        log_path = st.text_input("Canonical JSONL Log Path", value="runtime_events.jsonl")
        selected_log_folder = str(Path(log_path).parent)
        if st.button("Load Persona Decision View", use_container_width=True):
            try:
                st.session_state.persona_decision_state = _load_runtime(log_path, app_id, runtime_label, objective)
                st.session_state.watched_runtime_path = str(Path(log_path))
                st.success("Runtime loaded.")
            except Exception as exc:
                st.error(str(exc))
    else:
        watch_folder = st.text_input("Watched Log Folder", value="runtime_logs")
        selected_log_folder = watch_folder
        refresh_seconds = st.number_input("Refresh Seconds", min_value=2, max_value=60, value=5, step=1)
        watch_enabled = st.toggle("AEGIS Always-On Watcher", value=True)
        if st.button("Scan Now", use_container_width=True) or watch_enabled:
            try:
                message = _load_watched_runtime(watch_folder, app_id, runtime_label, objective)
                st.info(message)
            except Exception as exc:
                st.error(str(exc))
        if watch_enabled:
            st.caption("AEGIS is watching for new or updated JSONL runtime logs.")
    if st.button("Register / Update App", use_container_width=True):
        register_app(app_id=app_id, app_name=app_name, owner=app_owner, log_folder=selected_log_folder)
        st.success("Onboarded app registry updated.")

watched_path = st.session_state.get("watched_runtime_path")
if watched_path:
    st.caption(f"Loaded runtime log: {watched_path}")

state = st.session_state.get("persona_decision_state")
if not isinstance(state, dict) or not state:
    st.info("Load a canonical JSONL runtime log from the sidebar.")
    st.code("python tools1\\emit_canonical_runtime_log.py --output runtime_events.jsonl --runtime-id RUN-001 --app-id EXT_APP")
    st.stop()

_sync_final_decision_authority(state)
st.session_state.persona_decision_state = state
display = _safe_dict(state.get("canonical_display"))
arbitration = _safe_dict(state.get("final_arbitration"))
release = _safe_dict(_safe_dict(state.get("canonical_control_tower_measurements")).get("release_assessment"))
effective_decision = state.get("aegis_final_decision") or arbitration.get("aegis_final_decision", "-")
effective_route = state.get("effective_release_route") or release.get("release_route", "-")

c1, c2, c3, c4 = st.columns(4)
c1.metric("AEGIS Final Decision", effective_decision)
c2.metric("Risk", state.get("risk_level") or display.get("risk_level", "-"))
c3.metric("HITL", "YES" if state.get("hitl_required") else "NO")
c4.metric("Effective Route", effective_route)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Trust", _metric_value(state.get("trust_score") or display.get("trust_score")))
c1.caption(_source_label(state, "trust_score"))
c2.metric("Confidence", _metric_value(state.get("confidence") or display.get("confidence")))
c2.caption(_source_label(state, "confidence"))
c3.metric("Control Status", state.get("control_status") or display.get("control_status", "-"))
c3.caption("AEGIS derived")
c4.metric("Error Code", state.get("error_code") or display.get("error_code", "-"))
c4.caption("AEGIS normalized")

tabs = st.tabs(["Decision", "Lifecycle", "RAGAS", "LLM Judge", "OWASP AI", "Registry", "Operations", "Personas", "Missing Required Variables", "Consistency"])

with tabs[0]:
    consistency = _safe_dict(state.get("final_decision_consistency"))
    if consistency.get("status") == "PASS":
        message = f"Decision authority aligned: {consistency.get('aegis_final_decision')} -> {consistency.get('effective_release_route')}."
        if consistency.get("aegis_final_decision") == "ACCEPT":
            st.success(message)
        else:
            st.warning(message)
    else:
        st.warning("Decision authority alignment is unavailable for this runtime.")
    _render_table("AEGIS Decision Objects", _decision_rows(state))
    _render_table("LLM Final Arbitration", _final_arbitration_rows(state))
    _render_table("LLM Execution Audit", _llm_execution_rows(state))
    reasons = _safe_list(state.get("hitl_reasons"))
    if reasons:
        _render_table("HITL Reasons", [{"Reason": str(reason)} for reason in reasons])

with tabs[1]:
    lifecycle = _lifecycle_rows(state)
    missing_phases = [row for row in lifecycle if isinstance(row, dict) and row.get("Status") == "MISSING"]
    if missing_phases:
        st.warning(f"{len(missing_phases)} lifecycle phase(s) have no emitted events.")
    else:
        st.success("All lifecycle phases observed.")
    _render_table("Runtime Lifecycle Segregation", lifecycle)

with tabs[2]:
    ragas = _safe_dict(state.get("ragas_scores"))
    c1, c2, c3 = st.columns(3)
    c1.metric("RAGAS Overall", _metric_value(ragas.get("overall_score")))
    c2.metric("RAGAS Status", ragas.get("status", "-"))
    c3.metric("RAGAS LLM", "COMPLETED" if state.get("ragas_success") else "FAILED")
    st.caption(ragas.get("executive_summary", "-"))
    _render_table("RAGAS Quality Evaluation", _ragas_rows(state))

with tabs[3]:
    assurance = _safe_dict(state.get("llm_judge_assurance"))
    c1, c2, c3 = st.columns(3)
    c1.metric("Final Judge Verdict", assurance.get("final_verdict", "-"))
    c2.metric("HITL From Judge", "YES" if assurance.get("hitl_required") else "NO")
    c3.metric("LLM Judge Required", "YES")
    st.caption(assurance.get("final_rationale", "-"))
    _render_table("LLM Execution Audit", _llm_execution_rows(state))
    _render_table("LLM Judge Committee", _llm_judge_rows(state))

with tabs[4]:
    _render_table("User Query OWASP Validation", _query_security_rows(state))
    _render_table("OWASP AI Controls", _owasp_rows(state))
    _render_table("Policy-as-Code Security Gates", _policy_rows(state))

with tabs[5]:
    registry = _registry_context(str(state.get("app_id") or app_id))
    rows = registry_rows()
    if registry:
        st.success(f"Active registry record found for {registry.get('app_id')}.")
    else:
        st.warning("This runtime app_id is not registered in AEGIS registry.")
    _render_table("Onboarded Agentic Apps Registry", rows)

with tabs[6]:
    _render_table("Operational Control Outputs", _operations_summary_rows(state))
    rows_by_name = operation_rows()
    st.caption("Runtime History, Alerts, Agent Registry, Prompt Registry, and Policy Config are persistent operational stores. They can include previous runs for the same app/runtime.")
    for title in ["Runtime History", "HITL Queue", "Alerts", "Agent Registry", "Prompt Registry", "Policy Config"]:
        if title in {"Runtime History", "Alerts"}:
            st.caption(f"{title}: latest persisted records, not only the currently selected runtime.")
        _render_table(title, rows_by_name.get(title, []))
    _render_policy_editor()

with tabs[7]:
    audit_rows = _persona_value_audit_rows(state)
    issues = [row for row in audit_rows if row.get("Audit Status") not in {"PASS"}]
    if issues:
        st.warning(f"{len(issues)} persona value audit issue(s) found.")
    else:
        st.success("All Persona Decision Tower values passed source and consistency audit.")
    _render_table("Persona Value Audit", audit_rows)
    _runtime_ui().render_persona_operating_model(state)

with tabs[8]:
    _render_table("Required Event Envelope", _missing_rows(state))

with tabs[9]:
    rows = _safe_list(state.get("canonical_consistency_audit"))
    mismatch_rows = [row for row in rows if isinstance(row, dict) and row.get("Status") == "MISMATCH"]
    if mismatch_rows:
        st.warning(f"{len(mismatch_rows)} canonical mismatch row(s) found.")
        _render_table("Canonical Consistency Mismatches", mismatch_rows)
    else:
        st.success("No canonical consistency mismatches found.")
    _render_table("Canonical Consistency Audit", rows)

if mode == "Watch Folder" and watch_enabled:
    time.sleep(int(refresh_seconds))
    st.rerun()
