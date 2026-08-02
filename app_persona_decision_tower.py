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
from services1.llm_judge_assurance_service import run_llm_judge_assurance
from services1.onboarded_app_registry_service import app_record, register_app, registry_rows
from services1.policy_as_code_service import evaluate_policy_as_code
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


def _nested_value(state: Dict[str, Any], source: str) -> Any:
    value: Any = state
    for part in source.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _emitted_fields(state: Dict[str, Any]) -> set:
    return {str(item).casefold() for item in _safe_list(state.get("emitted_canonical_fields"))}


def _was_emitted(state: Dict[str, Any], source: str) -> bool:
    emitted = _emitted_fields(state)
    parts = [part.casefold() for part in source.split(".")]
    return source.casefold() in emitted or any(part in emitted for part in parts)


def _render_table(title: str, rows: List[Dict[str, Any]]) -> None:
    st.subheader(title)
    if not rows:
        st.info("No data available.")
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _apply_control_tower_assurance(state: Dict[str, Any]) -> Dict[str, Any]:
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
    display = _safe_dict(state.get("canonical_display"))
    release = _safe_dict(_safe_dict(state.get("canonical_control_tower_measurements")).get("release_assessment"))
    health = _safe_dict(state.get("customer_health"))
    rows = [
        ("Final Recommendation", state.get("final_recommendation") or display.get("final_recommendation") or display.get("recommendation"), "final_recommendation"),
        ("Risk Level", state.get("risk_level") or display.get("risk_level"), "risk_level"),
        ("Control Status", state.get("control_status") or display.get("control_status"), "control_status"),
        ("HITL Required", "YES" if state.get("hitl_required") else "NO", "hitl_required"),
        ("Release Route", release.get("release_route"), "canonical_control_tower_measurements.release_assessment.release_route"),
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
    return {
        label_col: label,
        "Variable Name": source,
        "Value": _metric_value(value),
        "Emitted by Onboarded App": "YES" if emitted else "NO",
        "AEGIS System Calculated": "NO" if emitted else "YES" if has_value else "NO",
        "Status": "APP EMITTED" if emitted else "AEGIS CALCULATED" if has_value else "MISSING",
        "Guidance": "Received from onboarded app." if emitted else "Not emitted by Onboarded App; AEGIS calculated it." if has_value else f"Required variable not emitted from Onboarded App: {source}",
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
            _persona_metric("Governed outcome", state.get("final_recommendation") or display.get("recommendation"), "Can the app outcome be consumed?", "final_recommendation"),
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
    rows = []
    for row in _safe_list(assurance.get("judge_verdicts")):
        if not isinstance(row, dict):
            continue
        rows.append({
            "Judge": row.get("judge_name") or row.get("judge_id"),
            "Verdict": row.get("verdict"),
            "Score": row.get("score"),
            "Confidence": row.get("confidence"),
            "Engine": row.get("judge_engine") or row.get("engine"),
            "Model": row.get("judge_model"),
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


def _policy_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    policy = _safe_dict(state.get("policy_as_code"))
    rows = []
    for row in _safe_list(policy.get("checks")):
        if not isinstance(row, dict):
            continue
        rows.append({
            "Policy ID": row.get("policy_id"),
            "Passed": "YES" if row.get("passed") else "NO",
            "Severity": row.get("severity"),
            "Actual": row.get("actual"),
            "Expected": row.get("expected"),
            "Action": row.get("action"),
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

display = _safe_dict(state.get("canonical_display"))
release = _safe_dict(_safe_dict(state.get("canonical_control_tower_measurements")).get("release_assessment"))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Final Recommendation", state.get("final_recommendation") or display.get("recommendation", "-"))
c2.metric("Risk", state.get("risk_level") or display.get("risk_level", "-"))
c3.metric("HITL", "YES" if state.get("hitl_required") else "NO")
c4.metric("Release Route", release.get("release_route", "-"))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Trust", _metric_value(state.get("trust_score") or display.get("trust_score")))
c1.caption(_source_label(state, "trust_score"))
c2.metric("Confidence", _metric_value(state.get("confidence") or display.get("confidence")))
c2.caption(_source_label(state, "confidence"))
c3.metric("Control Status", state.get("control_status") or display.get("control_status", "-"))
c3.caption("AEGIS derived")
c4.metric("Error Code", state.get("error_code") or display.get("error_code", "-"))
c4.caption("AEGIS normalized")

tabs = st.tabs(["Decision", "Lifecycle", "RAGAS", "LLM Judge", "OWASP AI", "Registry", "Personas", "Missing Required Variables", "Consistency"])

with tabs[0]:
    _render_table("AEGIS Decision Objects", _decision_rows(state))
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
    _render_table("LLM Judge Committee", _llm_judge_rows(state))

with tabs[4]:
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
    _runtime_ui().render_persona_operating_model(state)

with tabs[7]:
    _render_table("Required Event Envelope", _missing_rows(state))

with tabs[8]:
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
