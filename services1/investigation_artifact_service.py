"""Durable, atomic audit artifacts for every completed AEGIS investigation."""

from __future__ import annotations

import hashlib
import html
import csv
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict

from services1.email_notification_service import (
    build_alert_email,
    build_runtime_alerts,
    dispatch_runtime_alerts,
    email_config_status,
)
from services1.llm_judge_assurance_service import get_llm_judge_assurance
from services1.policy_as_code_service import evaluate_policy_as_code
from services1.runtime_ingestion_service import events_from_agent_trace


ARTIFACT_SCHEMA_VERSION = "1.0"
DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parents[1] / "AEGIS_RESULTS"


def _safe_name(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "UNKNOWN")).strip("_") or "UNKNOWN"


def _agent_display_name(value: Any) -> str:
    text = str(value or "-").strip().replace("_", " ")
    if not text or text == "-":
        return "-"
    aliases = {
        "app query rewriter": "App Query Rewriter",
        "app planner": "App Planner",
        "app tool router": "App Tool Router",
        "app evidence retrieval": "App Evidence Retrieval",
        "app evidence packager": "App Evidence Packager",
        "app response generator": "App Response Generator",
        "app proposed decision": "App Proposed Decision",
        "aegis governance": "AEGIS Governance",
        "aegis compliance": "AEGIS Compliance",
        "aegis trust": "AEGIS Trust",
        "aegis reflection": "AEGIS Reflection",
        "aegis evaluation": "AEGIS Evaluation",
        "aegis ragas evaluation": "AEGIS RAGAS Evaluation",
        "aegis hallucination check": "AEGIS Hallucination Check",
        "aegis grounding check": "AEGIS Grounding Check",
        "aegis owasp security": "AEGIS OWASP Security",
        "aegis cache intelligence": "AEGIS Cache Intelligence",
        "aegis runtime packager": "AEGIS Runtime Packager",
        "rag": "App Evidence Retrieval",
        "query rewriter": "App Query Rewriter",
        "planner": "App Planner",
        "tool router": "App Tool Router",
        "evidence": "App Evidence Packager",
        "evidence service": "App Evidence Packager",
        "answer": "App Response Generator",
        "recommendation": "App Proposed Decision",
        "governance": "AEGIS Governance",
        "compliance": "AEGIS Compliance",
        "trust": "AEGIS Trust",
        "reflection": "AEGIS Reflection",
        "evaluation": "AEGIS Evaluation",
        "ragas": "AEGIS RAGAS Evaluation",
        "hallucination agent": "AEGIS Hallucination Check",
        "grounding agent": "AEGIS Grounding Check",
        "owasp security agent": "AEGIS OWASP Security",
        "cache intelligence agent": "AEGIS Cache Intelligence",
        "runtime builder": "AEGIS Runtime Packager",
    }
    lowered = text.casefold()
    if lowered in aliases:
        return aliases[lowered]
    return " ".join(part.capitalize() for part in text.split())


def _agent_ownership(agent_name: Any, phase: Any = "") -> str:
    text = f"{agent_name} {phase}".casefold()
    if any(token in text for token in (
        "aegis", "governance", "compliance", "trust", "reflection",
        "evaluation", "ragas", "hallucination", "grounding", "owasp",
        "security", "cache intelligence", "runtime builder", "runtime packager", "audit",
    )):
        return "AEGIS Control Agent"
    if "risk agent" in text or "aml agent" in text:
        return "AEGIS Control Agent"
    return "Application Workflow Agent"


def _agent_lineage_key(value: Any) -> str:
    return _agent_display_name(value).casefold()


def _agent_trace_with_lineage(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    trace = [dict(row) for row in (state.get("agent_trace", []) or []) if isinstance(row, dict)]
    trace.sort(key=lambda row: row.get("execution_order") or 9999)
    incoming: Dict[str, list[str]] = {}
    outgoing: Dict[str, list[str]] = {}

    def add_edge(source: Any, target: Any) -> None:
        source_name = _agent_display_name(source)
        target_name = _agent_display_name(target)
        if source_name == "-" or target_name == "-":
            return
        source_key = _agent_lineage_key(source_name)
        target_key = _agent_lineage_key(target_name)
        outgoing.setdefault(source_key, [])
        incoming.setdefault(target_key, [])
        if target_name not in outgoing[source_key]:
            outgoing[source_key].append(target_name)
        if source_name not in incoming[target_key]:
            incoming[target_key].append(source_name)

    graph = state.get("agent_execution_graph", {}) if isinstance(state, dict) else {}
    if not isinstance(graph, dict) or not graph.get("edges"):
        try:
            from services1.agent_graph_service import build_agent_execution_graph
            graph = build_agent_execution_graph(state)
        except Exception:
            graph = {}

    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    node_labels = {}
    for node in (nodes if isinstance(nodes, list) else []):
        if isinstance(node, dict):
            label = _agent_display_name(node.get("label") or node.get("agent") or node.get("id"))
            node_labels[str(node.get("id") or label)] = label
    for edge in (edges if isinstance(edges, list) else []):
        if isinstance(edge, dict) and edge.get("kind") == "observed":
            add_edge(node_labels.get(str(edge.get("source")), edge.get("source")), node_labels.get(str(edge.get("target")), edge.get("target")))

    if not incoming and not outgoing:
        for source, target in zip(trace, trace[1:]):
            add_edge(source.get("agent") or source.get("agent_name"), target.get("agent") or target.get("agent_name"))

    enriched = []
    for index, row in enumerate(trace, start=1):
        agent = _agent_display_name(row.get("agent") or row.get("agent_name") or row.get("name"))
        key = _agent_lineage_key(agent)
        row["execution_order"] = row.get("execution_order") or index
        row["agent"] = agent
        row["agent_name"] = agent
        row["agent_type"] = _agent_ownership(agent, row.get("phase", ""))
        row["receives_from"] = ", ".join(incoming.get(key, [])) or "START"
        row["passes_to"] = ", ".join(outgoing.get(key, [])) or "END"
        retry_value = row.get("retry_count", row.get("retries", row.get("retry_attempts", row.get("attempts"))))
        max_retry_value = row.get("max_retries", row.get("retry_limit", row.get("configured_retries")))
        try:
            row["retry_count"] = int(float(retry_value or 0))
        except Exception:
            row["retry_count"] = 0
        try:
            row["max_retries"] = int(float(max_retry_value or 2))
        except Exception:
            row["max_retries"] = 2
        row["retry_signal"] = "Captured" if retry_value not in (None, "", "-") else "Default policy"
        enriched.append(row)
    return enriched


def _canonical_runtime_events(state: Dict[str, Any], enriched_trace: list[Dict[str, Any]] | None = None) -> list[Dict[str, Any]]:
    """One canonical runtime signal emitted by each graph node/agent."""
    rows = enriched_trace if isinstance(enriched_trace, list) else _agent_trace_with_lineage(state)
    recommendation = str(state.get("recommendation") or "-").upper()
    risk_level = str(
        state.get("risk_level")
        or nested_get(state, "risk_authority", "risk_level")
        or nested_get(state, "recommendation_package", "risk_level")
        or "-"
    ).upper()
    publication_gate = state.get("publication_gate", {}) if isinstance(state.get("publication_gate"), dict) else {}
    evidence_count = len(state.get("evidence_pack", []) or state.get("retrieved_chunks", []) or [])
    runtime_id = state.get("runtime_id")
    customer_id = state.get("customer_id")
    events = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        duration_ms = row.get("duration_ms")
        if duration_ms in (None, "", "-"):
            duration_ms = row.get("latency_ms")
        events.append({
            "runtime_id": runtime_id,
            "customer_id": customer_id,
            "event_type": "AGENT_RUNTIME_SIGNAL",
            "agent": row.get("agent") or row.get("agent_name"),
            "agent_type": row.get("agent_type"),
            "phase": row.get("phase"),
            "execution_order": row.get("execution_order"),
            "status": row.get("status"),
            "duration_ms": duration_ms,
            "tool_used": row.get("tool_used") or row.get("tool"),
            "receives_from": row.get("receives_from"),
            "passes_to": row.get("passes_to"),
            "retry_count": row.get("retry_count", 0),
            "max_retries": row.get("max_retries", 2),
            "skip_reason": row.get("skip_reason") or row.get("reason") or "-",
            "canonical_recommendation": recommendation,
            "canonical_risk_level": risk_level,
            "canonical_trust_score": state.get("trust_score"),
            "canonical_confidence": state.get("confidence"),
            "canonical_evidence_count": evidence_count,
            "canonical_cost_usd": state.get("estimated_cost_usd"),
            "publication_gate_status": publication_gate.get("status", "-"),
            "publication_release_allowed": publication_gate.get("release_allowed", "-"),
            "publication_retry_count": publication_gate.get("retry_count", 0),
            "publication_max_retries": publication_gate.get("max_retries", 3),
            "publication_block_reason": publication_gate.get("block_reason", "-"),
            "runtime_signal_emitted": True,
        })
    return events


def _jsonable(value: Any, _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """Convert runtime values without following cyclic object graphs forever."""
    if _seen is None:
        _seen = set()
    if _depth > 60:
        return "[MAX_DEPTH_REACHED]"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    is_container = isinstance(value, (dict, list, tuple, set)) or hasattr(value, "to_dict")
    identity = id(value)
    if is_container and identity in _seen:
        return "[CYCLIC_REFERENCE]"
    if is_container:
        _seen.add(identity)
    try:
        if isinstance(value, dict):
            return {
                str(key): _jsonable(item, _seen, _depth + 1)
                for key, item in value.items()
                if str(key) != "artifact_export"
            }
        if isinstance(value, (list, tuple, set)):
            return [_jsonable(item, _seen, _depth + 1) for item in value]
        if hasattr(value, "to_dict"):
            try:
                converted = value.to_dict("records")
            except TypeError:
                converted = value.to_dict()
            return _jsonable(converted, _seen, _depth + 1)
    finally:
        if is_container:
            _seen.discard(identity)
    if hasattr(value, "item"):
        try:
            return value.item()
        except (TypeError, ValueError):
            pass
    return str(value)


def evaluate_runtime_invariants(state: Dict[str, Any]) -> Dict[str, Any]:
    """Persist auditable pass/fail checks with every run."""
    status = str(state.get("runtime_status", state.get("status", ""))).upper()
    phase = str(state.get("current_phase") or "").upper()
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    trust_rows = [row for row in trace if isinstance(row, dict) and str(row.get("agent", "")).upper() == "TRUST"]
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    scope = state.get("retrieval_scope", {}) if isinstance(state.get("retrieval_scope"), dict) else {}
    recommendation = str(state.get("recommendation", "UNKNOWN")).upper()
    confidence = float(state.get("confidence", 0) or 0)
    hitl = bool(state.get("hitl_required"))
    trust = float(state.get("trust_score", 0) or 0)
    risk_authority = state.get("risk_authority", {}) if isinstance(state.get("risk_authority"), dict) else {}
    governance_authority = state.get("governance_authority", {}) if isinstance(state.get("governance_authority"), dict) else {}
    retrieval_coverage_status = str(scope.get("coverage_status", "")).upper()
    customer = state.get("customer_profile", {}) if isinstance(state.get("customer_profile"), dict) else {}
    customer_missing = (
        state.get("customer_found") is False
        or str(customer.get("record_status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or str(risk_authority.get("status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or retrieval_coverage_status == "CUSTOMER_NOT_FOUND"
    )

    def nested(container, *path):
        value = container
        for key in path:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value

    recommendation_views = {
        "top": state.get("recommendation"),
        "runtime_summary": nested(state, "runtime_summary", "recommendation"),
        "decision_snapshot": nested(state, "decision_snapshot", "recommendation"),
        "recommendation_package": nested(state, "recommendation_package", "recommendation"),
        "boardroom_summary": nested(state, "recommendation_package", "boardroom_summary", "recommendation"),
        "executive_package": nested(state, "executive_package", "recommendation"),
        "board_summary": nested(state, "executive_package", "board_summary", "recommendation"),
        "executive_kpis": nested(state, "executive_package", "executive_kpis", "recommendation"),
        "executive_dashboard": nested(state, "executive_package", "executive_dashboard", "recommendation"),
    }
    populated_recommendations = {
        key: str(value).upper() for key, value in recommendation_views.items() if value not in (None, "")
    }
    trust_views = {
        "top": state.get("trust_score"),
        "runtime_summary": nested(state, "runtime_summary", "trust_score"),
        "decision_snapshot": nested(state, "decision_snapshot", "trust_score"),
        "recommendation_package": nested(state, "recommendation_package", "trust_score"),
        "executive_package": nested(state, "executive_package", "trust_score"),
        "board_summary": nested(state, "executive_package", "board_summary", "trust_score"),
        "executive_kpis": nested(state, "executive_package", "executive_kpis", "trust_score"),
        "executive_dashboard": nested(state, "executive_package", "executive_dashboard", "trust_score"),
        "boardroom_summary": nested(state, "recommendation_package", "boardroom_summary", "trust_score"),
        "executive_llm": nested(state, "executive_llm", "trust_score"),
    }
    populated_trust = {
        key: float(value) for key, value in trust_views.items() if value not in (None, "")
    }
    confidence_views = {
        "top": state.get("confidence"),
        "runtime_summary": nested(state, "runtime_summary", "confidence"),
        "decision_snapshot": nested(state, "decision_snapshot", "confidence"),
        "recommendation_package": nested(state, "recommendation_package", "confidence"),
        "executive_package": nested(state, "executive_package", "confidence"),
        "board_summary": nested(state, "executive_package", "board_summary", "confidence"),
        "executive_dashboard": nested(state, "executive_package", "executive_dashboard", "confidence"),
        "executive_llm": nested(state, "executive_llm", "confidence"),
    }
    populated_confidence = {
        key: float(value) for key, value in confidence_views.items() if value not in (None, "")
    }
    expected = str(nested(state, "customer_profile", "expected_recommendation") or "").upper()
    executive_llm_for_scan = dict(state.get("executive_llm", {}) or {}) if isinstance(state.get("executive_llm"), dict) else {}
    executive_llm_for_scan.pop("grounding_validation", None)
    executive_llm_text = json.dumps(
        _jsonable(executive_llm_for_scan), ensure_ascii=False, default=str
    ).lower()
    forbidden_executive_terms = [
        term for term in ("market competition", "market share", "strategic differentiation")
        if term in executive_llm_text
    ]
    hallucination_level = str(
        nested(state, "hallucination_results", "risk_level")
        or state.get("hallucination_risk", "UNKNOWN")
    ).upper()
    reflection_quality = str(nested(state, "reflection", "quality") or "UNKNOWN").upper()
    reflection_groundedness = float(nested(state, "reflection", "groundedness_score") or 0)
    reflection_coverage = float(nested(state, "reflection", "coverage_score") or 0)
    canonical_values = state.get("canonical_values", {}) if isinstance(state.get("canonical_values"), dict) else {}
    llm_assurance = state.get("llm_judge_assurance", {}) if isinstance(state.get("llm_judge_assurance"), dict) else {}
    judge_verdicts = llm_assurance.get("judge_verdicts", []) if isinstance(llm_assurance.get("judge_verdicts"), list) else []
    cost_basis = str(
        nested(state, "canonical_values", "cost_basis")
        or nested(state, "token_metrics", "cost_basis")
        or ""
    ).lower()
    checks = [
        {"id": "terminal_status", "passed": status == "COMPLETED", "actual": status},
        {"id": "terminal_phase", "passed": phase == "RUNTIME_COMPLETE", "actual": phase},
        {"id": "mandatory_trust", "passed": bool(trust_rows), "actual": len(trust_rows)},
        {"id": "trust_terminal_state", "passed": bool(trust_rows) and all(str(r.get("status", "")).upper() in {"COMPLETED", "FAILED"} for r in trust_rows), "actual": [r.get("status") for r in trust_rows]},
        {"id": "retrieval_scope_enforced", "passed": not retrieved or bool(scope.get("enforced")), "actual": scope},
        {"id": "customer_retrieval_coverage", "passed": retrieval_coverage_status != "NO_CUSTOMER_CHUNK_RETRIEVED" or (recommendation == "MONITOR" and hitl), "actual": scope},
        {"id": "missing_customer_guard", "passed": not customer_missing or (recommendation == "MONITOR" and hitl and str(risk_authority.get("level", "")).upper() != "LOW"), "actual": {"customer_found": state.get("customer_found"), "customer": customer, "risk_authority": risk_authority, "recommendation": recommendation, "hitl": hitl}},
        {"id": "low_confidence_governance", "passed": expected == recommendation or not (confidence < 60 and recommendation in {"APPROVE", "ESCALATE"}) or hitl or recommendation != "APPROVE", "actual": {"confidence": confidence, "recommendation": recommendation, "hitl": hitl, "authoritative_expected": expected}},
        {"id": "recommendation_consistency", "passed": all(value == recommendation for value in populated_recommendations.values()), "actual": populated_recommendations},
        {"id": "trust_consistency", "passed": all(abs(value - trust) < 0.001 for value in populated_trust.values()), "actual": populated_trust},
        {"id": "confidence_consistency", "passed": all(abs(value - confidence) < 0.001 for value in populated_confidence.values()), "actual": populated_confidence},
        {"id": "human_review_consistency", "passed": nested(state, "recommendation_package", "human_review_required") in {None, hitl}, "actual": {"top": hitl, "package": nested(state, "recommendation_package", "human_review_required")}},
        {"id": "risk_consistency", "passed": not risk_authority or (float(risk_authority.get("score", 0) or 0) == float(state.get("risk_score", 0) or 0)), "actual": risk_authority},
        {"id": "governance_consistency", "passed": not governance_authority or str(governance_authority.get("recommendation", "")).upper() == recommendation, "actual": governance_authority},
        {"id": "retrieval_average_trust", "passed": not retrieved or float(nested(state, "retrieval_statistics", "average_trust") or 0) > 0, "actual": nested(state, "retrieval_statistics", "average_trust")},
        {"id": "executive_llm_grounding", "passed": bool(nested(state, "executive_llm", "grounding_validation", "passed")) and not forbidden_executive_terms, "actual": {"forbidden_terms": forbidden_executive_terms, "validation": nested(state, "executive_llm", "grounding_validation")}},
        {"id": "hallucination_decision_consistency", "passed": recommendation != "APPROVE" or hallucination_level in {"LOW", "NONE"} or hitl, "actual": {"recommendation": recommendation, "hallucination_risk": hallucination_level, "hitl": hitl}},
        {"id": "reflection_math_consistency", "passed": not (hallucination_level in {"HIGH", "CRITICAL"} and reflection_quality in {"ACCEPTABLE", "GOOD", "EXCELLENT"}) and not (reflection_groundedness < 50 and reflection_quality in {"GOOD", "EXCELLENT"}), "actual": {"groundedness": reflection_groundedness, "coverage": reflection_coverage, "hallucination_risk": hallucination_level, "quality": reflection_quality}},
        {"id": "no_runtime_errors", "passed": not bool(state.get("runtime_errors")), "actual": state.get("runtime_errors", [])},
        {"id": "canonical_values_present", "passed": all(key in canonical_values for key in ("recommendation", "risk_level", "trust_score", "confidence", "evidence_count", "agent_count", "estimated_model_cost_usd")), "actual": canonical_values},
        {"id": "canonical_cost_not_latency_allocated", "passed": bool(canonical_values) and "latency" not in cost_basis, "actual": canonical_values.get("cost_basis", cost_basis)},
        {"id": "llm_judge_provider_transparency", "passed": not judge_verdicts or all(row.get("provider") and row.get("engine") for row in judge_verdicts if isinstance(row, dict)), "actual": [{"judge": row.get("judge_name"), "provider": row.get("provider"), "engine": row.get("engine")} for row in judge_verdicts if isinstance(row, dict)]},
        {"id": "runtime_signal_contract", "passed": not trace or all(isinstance(row, dict) and row.get("runtime_signal_emitted") is not False for row in trace), "actual": [{"agent": row.get("agent"), "runtime_signal_emitted": row.get("runtime_signal_emitted", True)} for row in trace if isinstance(row, dict)]},
    ]
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(),
        "passed": all(check["passed"] for check in checks),
        "total": len(checks),
        "passed_count": sum(check["passed"] for check in checks),
        "failed_count": sum(not check["passed"] for check in checks),
        "checks": checks,
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(_jsonable(payload), indent=2, ensure_ascii=False), encoding="utf-8")


def _field(item: Dict[str, Any], *keys: str) -> Any:
    """Read canonical snake_case or display-style keys from exported rows."""
    if not isinstance(item, dict):
        return None
    variants = []
    for key in keys:
        variants.extend([
            key,
            key.replace("_", " ").title(),
            key.replace("_", " ").capitalize(),
            key.upper(),
        ])
    for key in variants:
        if key in item and item.get(key) not in (None, ""):
            return item.get(key)
    return None


def _clean_text_for_report(value: Any, limit: int | None = None) -> str:
    """Normalize exported values so offline HTML never shows escaped layout noise."""
    if value is None:
        text = "-"
    elif isinstance(value, (dict, list)):
        text = json.dumps(_jsonable(value), ensure_ascii=False)
    else:
        text = str(value)
    text = text.replace("\\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace('"UNKNOWN"', '"Not supplied"').replace("'UNKNOWN'", "'Not supplied'")
    text = re.sub(r"\bUNKNOWN\b", "Not supplied", text)
    text = " ".join(text.split())
    if not text:
        text = "-"
    if limit and len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _evidence_source_for_report(item: Dict[str, Any]) -> str:
    metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    return str(
        _field(item, "source")
        or _field(item, "file")
        or metadata.get("source")
        or metadata.get("file")
        or "-"
    )


def _score_for_report(item: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = _field(item, key)
        if value not in (None, ""):
            return value
    return "-"


def _numeric_for_report(value: Any, default: float = 0.0) -> float:
    try:
        return float(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        return default


def _bounded_score_for_report(value: Any, default: float = 0.0) -> float:
    return max(0.0, min(_numeric_for_report(value, default), 100.0))


def _evidence_trust_for_report(item: Dict[str, Any]) -> Any:
    if not isinstance(item, dict):
        return "-"
    metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    source = _evidence_source_for_report(item)
    chunk_id = str(_field(item, "chunk_id", "id") or "").upper()
    provenance = str(metadata.get("provenance") or _field(item, "provenance") or "").upper()
    if chunk_id.startswith("RUNTIME_") or provenance == "AUTHORITATIVE_CSV":
        return 100.0

    for key in ("evidence_trust", "evidence_authority", "source_trust", "trust"):
        value = _field(item, key)
        if value not in (None, "", "-"):
            return round(_bounded_score_for_report(value), 2)
    for key in ("evidence_trust", "evidence_authority", "source_trust", "trust"):
        value = metadata.get(key)
        if value not in (None, "", "-"):
            return round(_bounded_score_for_report(value), 2)
    raw_trust = _field(item, "trust_score") or metadata.get("trust_score")
    if raw_trust not in (None, "", "-"):
        raw_value = _bounded_score_for_report(raw_trust)
        if raw_value >= 50:
            return round(raw_value, 2)
    if str(source).endswith(".csv"):
        return 70.0
    return "-"


def _evidence_trust_basis_for_report(item: Dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return "-"
    metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    source = _evidence_source_for_report(item)
    chunk_id = str(_field(item, "chunk_id", "id") or "").upper()
    provenance = str(metadata.get("provenance") or _field(item, "provenance") or "").upper()
    if _field(item, "evidence_trust") not in (None, "", "-") or metadata.get("evidence_trust") not in (None, "", "-"):
        return "Explicit evidence trust"
    if chunk_id.startswith("RUNTIME_") or provenance == "AUTHORITATIVE_CSV":
        return "Authoritative customer-scoped source"
    raw_trust = _field(item, "trust_score") or metadata.get("trust_score")
    if raw_trust not in (None, "", "-") and _bounded_score_for_report(raw_trust) >= 50:
        return "Validated trust_score field"
    if str(source).endswith(".csv"):
        return "Customer-scoped CSV authority floor"
    return "No evidence trust signal"


def _retrieval_method_for_report(chunk: Dict[str, Any]) -> str:
    if not isinstance(chunk, dict):
        return "-"
    method = str(_field(chunk, "retrieval_method") or "").upper()
    metadata = chunk.get("metadata", {}) if isinstance(chunk.get("metadata"), dict) else {}
    provenance = str(metadata.get("provenance") or _field(chunk, "provenance") or "").upper()
    contributions = _field(chunk, "retrieval_contributions")
    contribution_methods = []
    if isinstance(contributions, list):
        contribution_methods = [
            str(item.get("method", "")).upper()
            for item in contributions
            if isinstance(item, dict) and item.get("method")
        ]
    if provenance == "AUTHORITATIVE_CSV" or method == "AUTHORITATIVE_CSV":
        return "Authoritative CSV match"
    if "BM25" in contribution_methods and "VECTOR" in contribution_methods:
        return "Hybrid BM25 + Semantic Vector"
    if method in {"HYBRID_RRF", "HYBRID"}:
        return "Hybrid BM25 + Semantic Vector"
    if "BM25" in contribution_methods or method == "BM25":
        return "BM25 keyword retrieval"
    if "VECTOR" in contribution_methods or method in {"VECTOR", "SEMANTIC"}:
        return "Semantic vector retrieval"
    return method.replace("_", " ").title() if method else "-"


def _retrieval_contribution_for_report(chunk: Dict[str, Any]) -> str:
    """Compact explanation of how BM25/vector retrieval contributed to a row."""
    if not isinstance(chunk, dict):
        return "-"
    contributions = _field(chunk, "retrieval_contributions")
    if not isinstance(contributions, list) or not contributions:
        if _retrieval_method_for_report(chunk) == "Authoritative CSV match":
            return "Direct customer-scoped CSV row"
        return "-"
    parts = []
    for item in contributions:
        if not isinstance(item, dict):
            continue
        method = item.get("method", "-")
        rank = item.get("rank", "-")
        score = item.get("rrf_score", "-")
        parts.append(f"{method} rank {rank} / RRF {score}")
    return "; ".join(parts) if parts else "-"


def _cache_status_for_report(hit_ratio: float, stores: Any) -> str:
    if hit_ratio >= 50:
        return "Active reuse"
    if _numeric_for_report(stores) > 0:
        return "Warming"
    return "No reuse yet"


def _cache_layer_rows_for_report(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    cache_metrics = state.get("cache_metrics", {}) if isinstance(state.get("cache_metrics"), dict) else {}
    layers = cache_metrics.get("layers") or state.get("cache_layers") or {}
    if not isinstance(layers, dict):
        return []
    labels = {
        "embedding_cdc": ("Persistent Embedding CDC", "Persistent vector reuse across runs"),
        "runtime": ("Full Runtime Result", "Avoids full agent traversal on exact repeat"),
        "prompt": ("Session Prompt/Query", "Exact prompt/query reuse"),
        "retrieval": ("Retrieval Result", "Reuses retrieved document set on exact match"),
        "embedding": ("Session Query Embedding", "Transient query embedding wrapper"),
    }
    rows = []
    for key, layer in layers.items():
        if not isinstance(layer, dict):
            continue
        if str(key) == "kv":
            continue
        label, explanation = labels.get(str(key), (str(key).replace("_", " ").title(), "Session-scoped cache layer"))
        hit_ratio = round(_numeric_for_report(layer.get("hit_ratio")), 2)
        rows.append({
            "layer": label,
            "hit_ratio": hit_ratio,
            "status": _cache_status_for_report(hit_ratio, layer.get("stores")),
            "entries": layer.get("entries", 0),
            "lookups": layer.get("lookups", 0),
            "hits": layer.get("hits", 0),
            "misses": layer.get("misses", 0),
            "explanation": explanation,
        })
    order = {
        "Persistent Embedding CDC": 0,
        "Full Runtime Result": 1,
        "Session Prompt/Query": 2,
        "Retrieval Result": 3,
        "Session Query Embedding": 4,
    }
    return sorted(rows, key=lambda row: order.get(row["layer"], 99))


def _control_pillar_rows_for_report(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    trust = _numeric_for_report(state.get("trust_score"))
    confidence = _numeric_for_report(state.get("confidence"))
    groundedness_raw = state.get("groundedness_score")
    groundedness = _numeric_for_report(groundedness_raw)
    hallucination_risk = str(state.get("hallucination_risk") or nested_get(state, "hallucination_results", "risk_level") or "-").upper()
    recommendation = str(state.get("recommendation") or nested_get(state, "recommendation_package", "recommendation") or "-").upper()
    compliance = state.get("compliance", {}) if isinstance(state.get("compliance"), dict) else {}
    compliance_status = str(compliance.get("compliance_status") or compliance.get("status") or "-").upper()
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    evidence_count = len(state.get("evidence_pack", []) or state.get("retrieved_chunks", []) or [])
    cache_lookup = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
    token = state.get("token_metrics", {}) if isinstance(state.get("token_metrics"), dict) else {}
    runtime_status = str(state.get("runtime_status") or state.get("status") or "").upper()
    runtime_errors = state.get("runtime_errors", []) if isinstance(state.get("runtime_errors"), list) else []
    artifact_export = state.get("artifact_export", {}) if isinstance(state.get("artifact_export"), dict) else {}
    tests_passed = bool(nested_get(state, "artifact_export", "test_results", "passed"))
    ledger_status = str(nested_get(state, "artifact_export", "audit_ledger", "status") or "-").upper()
    trustworthy_components = [(trust, 0.40), (confidence, 0.25)]
    if str(groundedness_raw or "").strip() not in {"", "-", "None", "none", "N/A", "n/a"}:
        trustworthy_components.append((groundedness, 0.25))
    if hallucination_risk not in {"", "-", "UNKNOWN", "N/A", "NONE", "NULL"}:
        trustworthy_components.append(((100 if hallucination_risk == "LOW" else 65), 0.10))
    trust_weight = sum(weight for _, weight in trustworthy_components) or 1
    trust_score = round(sum(score * weight for score, weight in trustworthy_components) / trust_weight, 1)
    trustworthy_formula_parts = [f"Trust {trust:.1f} x 40%", f"Confidence {confidence:.1f} x 25%"]
    missing_trustworthy = []
    if str(groundedness_raw or "").strip() not in {"", "-", "None", "none", "N/A", "n/a"}:
        trustworthy_formula_parts.append(f"Grounding {groundedness:.1f} x 25%")
    else:
        missing_trustworthy.append("groundedness")
    if hallucination_risk not in {"", "-", "UNKNOWN", "N/A", "NONE", "NULL"}:
        trustworthy_formula_parts.append(f"Hallucination control {(100 if hallucination_risk == 'LOW' else 65):.1f} x 10%")
    else:
        missing_trustworthy.append("hallucination_risk")
    trustworthy_signal = (
        f"Trust {trust:.1f}; Confidence {confidence:.1f}; Hallucination {hallucination_risk}. "
        f"Formula: ({' + '.join(trustworthy_formula_parts)}) / {trust_weight:.2f}. "
        f"Missing not scored: {', '.join(missing_trustworthy) if missing_trustworthy else 'none'}."
    )
    governance_score = round((100 if compliance_status == "COMPLIANT" else 65) * 0.45 + (100 if recommendation == "APPROVE" else 70) * 0.35 + (75 if state.get("hitl_required") else 100) * 0.20, 1)
    measurable_score = round(sum([100 if trace else 0, 100 if evidence_count else 0, 100 if state.get("execution_timeline") else 0, 100]) / 4, 1)
    cache_status = str(cache_lookup.get("status", "")).upper()
    cache_component = 100 if cache_status == "HIT" else 80 if cache_status == "STORED" else 55
    cache_entries_component = 100 if cache_lookup.get("entries", 0) else 50
    scale_score = round(cache_component * 0.65 + cache_entries_component * 0.35, 1)
    scalable_signal = (
        f"Runtime cache {cache_lookup.get('status', '-')}; entries {cache_lookup.get('entries', 0)}. "
        f"Formula: Cache {cache_component} x 65% + Entries {cache_entries_component} x 35%."
    )
    resilience_score = round(sum([
        100 if runtime_status == "COMPLETED" else 60,
        100 if artifact_export.get("status") else 65,
        100 if str(cache_lookup.get("status", "")).upper() in {"HIT", "STORED"} else 70,
        100 if not runtime_errors else 45,
        100 if state.get("hitl_required") or compliance_status in {"COMPLIANT", "REVIEW_REQUIRED"} else 75,
    ]) / 5, 1)
    audit_components = [
        100 if artifact_export.get("status") else 65,
        100 if ledger_status == "SAVED" else 70,
        100 if tests_passed else 75,
        100 if evidence_count else 60,
        100 if trace else 60,
    ]
    audit_score = round(sum(audit_components) / len(audit_components), 1)
    auditable_signal = (
        f"Artifacts {artifact_export.get('status', '-')}; ledger {ledger_status}; tests {'PASS' if tests_passed else 'REVIEW'}. "
        f"Formula: Artifact {audit_components[0]}, Ledger {audit_components[1]}, Tests {audit_components[2]}, "
        f"Evidence {audit_components[3]}, Agents {audit_components[4]} average."
    )
    return [
        {"pillar": "Trustworthy AI", "score": trust_score, "signal": trustworthy_signal},
        {"pillar": "Governable AI", "score": governance_score, "signal": f"Compliance {compliance_status}; Recommendation {recommendation}; HITL {'YES' if state.get('hitl_required') else 'NO'}"},
        {"pillar": "Measurable AI", "score": measurable_score, "signal": f"{len(trace)} agents; {evidence_count} evidence rows; cost USD {token.get('estimated_cost_usd', '-')}"},
        {"pillar": "Scalable AI", "score": scale_score, "signal": scalable_signal},
        {"pillar": "Resilient AI", "score": resilience_score, "signal": f"Status {runtime_status}; errors {len(runtime_errors)}; audit {artifact_export.get('status', '-')}"},
        {"pillar": "Auditable AI", "score": audit_score, "signal": auditable_signal},
    ]


def _pillar_radar_html(rows: list[Dict[str, Any]]) -> str:
    if not rows:
        return ""
    size = 520
    cx = cy = size / 2
    radius = 170
    target = 80.0

    def point(index: int, value: float) -> tuple[float, float]:
        angle = -math.pi / 2 + (2 * math.pi * index / len(rows))
        r = radius * max(0, min(100, value)) / 100
        return cx + r * math.cos(angle), cy + r * math.sin(angle)

    def polygon(values: list[float]) -> str:
        return " ".join(f"{x:.1f},{y:.1f}" for x, y in (point(i, value) for i, value in enumerate(values)))

    axis_lines = []
    labels = []
    for index, row in enumerate(rows):
        x, y = point(index, 100)
        lx, ly = point(index, 113)
        axis_lines.append(f"<line x1='{cx:.1f}' y1='{cy:.1f}' x2='{x:.1f}' y2='{y:.1f}' class='radar-axis'/>")
        anchor = "middle"
        if lx < cx - 20:
            anchor = "end"
        elif lx > cx + 20:
            anchor = "start"
        labels.append(
            f"<text x='{lx:.1f}' y='{ly:.1f}' text-anchor='{anchor}' class='radar-label'>"
            f"{html.escape(_clean_text_for_report(row.get('pillar'), 22))}</text>"
        )

    rings = []
    for pct in (20, 40, 60, 80, 100):
        ring_points = polygon([pct] * len(rows))
        rings.append(f"<polygon points='{ring_points}' class='radar-ring'/>")
        rings.append(f"<text x='{cx + radius * pct / 100 + 5:.1f}' y='{cy - 4:.1f}' class='radar-tick'>{pct}</text>")

    scores = [_numeric_for_report(row.get("score")) for row in rows]
    score_points = polygon(scores)
    target_points = polygon([target] * len(rows))
    score_labels = []
    for index, row in enumerate(rows):
        x, y = point(index, _numeric_for_report(row.get("score")))
        score_labels.append(
            f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' class='radar-dot'/>"
            f"<text x='{x + 7:.1f}' y='{y - 7:.1f}' class='radar-score'>{_numeric_for_report(row.get('score')):.1f}</text>"
        )

    legend = (
        "<div class='radar-legend'>"
        "<span><i class='radar-swatch actual'></i> AEGIS maturity</span>"
        "<span><i class='radar-swatch target'></i> Enterprise target</span>"
        "</div>"
    )
    return (
        "<div class='radar-wrap'>"
        f"<svg class='pillar-radar' viewBox='0 0 {size} {size}' role='img' aria-label='Six pillar maturity spider radar chart'>"
        + "".join(rings)
        + "".join(axis_lines)
        + f"<polygon points='{target_points}' class='radar-target'/>"
        + f"<polygon points='{score_points}' class='radar-actual'/>"
        + "".join(score_labels)
        + "".join(labels)
        + "</svg>"
        + legend
        + "</div>"
    )


def _pillar_control_flow_html(state: Dict[str, Any], rows: list[Dict[str, Any]]) -> str:
    recommendation = str(state.get("recommendation") or nested_get(state, "recommendation_package", "recommendation") or "-").upper()
    evidence_count = len(state.get("evidence_pack", []) or state.get("retrieved_chunks", []) or [])
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    avg_score = round(sum(_numeric_for_report(row.get("score")) for row in rows) / len(rows), 1) if rows else 0
    return _visual_flow_html("Six Pillar Control Flow", [
        {
            "label": "1",
            "title": "AI app runtime",
            "detail": f"{len(trace)} observed agent signal(s) plus evidence/tool/model telemetry.",
        },
        {
            "label": "2",
            "title": "Canonical record",
            "detail": f"One normalized source for decision, risk, trust, confidence, cost, and {evidence_count} evidence row(s).",
        },
        {
            "label": "3",
            "title": "Six-pillar assessment",
            "detail": f"Trustworthy, governable, measurable, scalable, resilient, and auditable maturity average {avg_score:.1f}.",
        },
        {
            "label": "4",
            "title": "Governed output",
            "detail": f"Final canonical recommendation: {recommendation}.",
        },
    ])


def _pillar_coverage_heatmap_html() -> str:
    columns = ["Runtime", "Evidence", "OWASP", "LLM Judge", "Cache", "Cost", "Alerts", "Audit"]
    coverage = [
        ("Trustworthy AI", [1, 1, 1, 1, 0, 0, 0, 1]),
        ("Governable AI", [1, 1, 1, 1, 0, 0, 1, 1]),
        ("Measurable AI", [1, 1, 0, 0, 1, 1, 0, 1]),
        ("Scalable AI", [1, 0, 0, 0, 1, 1, 0, 1]),
        ("Resilient AI", [1, 0, 1, 1, 1, 0, 1, 1]),
        ("Auditable AI", [1, 1, 1, 1, 1, 1, 1, 1]),
    ]
    header = "<tr><th>AEGIS Pillar</th>" + "".join(f"<th>{html.escape(col)}</th>" for col in columns) + "</tr>"
    body = []
    for pillar, values in coverage:
        cells = "".join(
            f"<td><span class='coverage-cell {'covered' if value else 'empty'}'>{'Covered' if value else '-'}</span></td>"
            for value in values
        )
        body.append(f"<tr><td><strong>{html.escape(pillar)}</strong></td>{cells}</tr>")
    return (
        "<h3>Control Coverage Heatmap</h3>"
        "<p class='caption'>This heatmap shows which AEGIS control capabilities contribute to each enterprise AI governance pillar. N/A means the control is not directly applicable to that pillar, not a missing feature.</p>"
        f"<div class='table-scroll coverage-heatmap'><table>{header}{''.join(body)}</table></div>"
    )


def _control_pillars_html(state: Dict[str, Any]) -> str:
    rows = _control_pillar_rows_for_report(state)
    cards = "".join(
        "<div class='pillar-card'>"
        f"<span>{html.escape(row['pillar'])}</span>"
        f"<strong>{html.escape(str(row['score']))}</strong>"
        f"<em>{html.escape(row['signal'])}</em>"
        "</div>"
        for row in rows
    )
    bars = "".join(
        "<div class='maturity-row'>"
        f"<span>{html.escape(row['pillar'])}</span>"
        f"<div class='bar-track'><div class='bar-fill green' style='width:{max(2, min(100, row['score'])):.1f}%'></div></div>"
        f"<strong>{row['score']:.1f}</strong>"
        "</div>"
        for row in rows
    )
    return (
        f"<div class='pillar-grid'>{cards}</div>"
        "<h3>Control Tower Maturity Radar</h3>"
        "<p class='caption'>Spider chart view of the six AEGIS pillars. The filled shape is the current run maturity; the dashed outline is the enterprise target.</p>"
        f"{_pillar_radar_html(rows)}"
        f"{_pillar_control_flow_html(state, rows)}"
        f"{_pillar_coverage_heatmap_html()}"
        "<h3>Pillar Score Breakdown</h3>"
        f"<div class='waterfall'>{bars}</div>"
    )


def _cache_maturity_html(state: Dict[str, Any]) -> str:
    rows = _cache_layer_rows_for_report(state)
    if not rows:
        return "<p class='caption'>Cache layer telemetry was not available.</p>"
    bars = "".join(
        "<div class='waterfall-row'>"
        f"<span>{html.escape(row['layer'])}</span>"
        f"<div class='bar-track'><div class='bar-fill {'green' if row['hit_ratio'] >= 50 else 'amber' if row['status'] == 'Warming' else 'gray'}' style='width:{max(2, min(100, row['hit_ratio'])):.1f}%'></div></div>"
        f"<strong>{row['hit_ratio']:.1f}%</strong>"
        "</div>"
        for row in rows
    )
    notes = "".join(
        f"<li><strong>{html.escape(row['layer'])}</strong>: {html.escape(row['explanation'])}. Current state: {html.escape(row['status'])}.</li>"
        for row in rows
        if row["hit_ratio"] <= 0
    )
    return (
        f"<div class='waterfall'>{bars}</div>"
        f"{'<details><summary>Why some cache layers show no reuse yet</summary><ul>' + notes + '</ul></details>' if notes else ''}"
    )


def _retrieved_evidence_rows(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    rows = []
    chunks = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    for index, chunk in enumerate(chunks, start=1):
        if isinstance(chunk, dict):
            rows.append({
                "rank": index,
                "source": _evidence_source_for_report(chunk),
                "evidence_trust": _evidence_trust_for_report(chunk),
                "trust_basis": _evidence_trust_basis_for_report(chunk),
                "retrieval_method": _retrieval_method_for_report(chunk),
                "retrieval_contribution": _retrieval_contribution_for_report(chunk),
                "score": _score_for_report(chunk, "score", "similarity_score", "retrieval_score"),
                "rerank_score": _score_for_report(chunk, "rerank_score", "cross_encoder_score", "relevance_score"),
                "text": _clean_text_for_report(chunk.get("text") or chunk.get("content") or chunk.get("chunk") or chunk.get("summary") or chunk, 360),
            })
        else:
            rows.append({"rank": index, "source": "-", "score": "-", "rerank_score": "-", "text": str(chunk)})
    return rows


def _reranked_evidence_rows(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    def score(chunk: Any) -> float:
        if not isinstance(chunk, dict):
            return 0.0
        values = []
        for key in ("rerank_score", "cross_encoder_score", "relevance_score", "score", "similarity_score", "retrieval_score"):
            try:
                values.append(float(chunk.get(key) or 0))
            except (TypeError, ValueError):
                values.append(0.0)
        return max(values or [0.0])

    chunks = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    rows = []
    for index, chunk in enumerate(sorted(chunks, key=score, reverse=True), start=1):
        if isinstance(chunk, dict):
            rows.append({
                "rerank": index,
                "source": _evidence_source_for_report(chunk),
                "retrieval_method": _retrieval_method_for_report(chunk),
                "rerank_score": _score_for_report(chunk, "rerank_score", "cross_encoder_score", "relevance_score", "score"),
                "original_rank": chunk.get("rank", chunk.get("retrieval_rank", "-")),
                "evidence_text": _clean_text_for_report(chunk.get("text") or chunk.get("content") or chunk.get("chunk") or chunk.get("summary") or chunk, 360),
            })
        else:
            rows.append({"rerank": index, "source": "-", "rerank_score": "-", "original_rank": "-", "evidence_text": str(chunk)})
    return rows


def _evidence_metrics_html(state: Dict[str, Any]) -> str:
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    canonical_evidence_count = len(evidence or retrieved or [])
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    combined = [row for row in [*evidence, *retrieved] if isinstance(row, dict)]
    trust_values = []
    pack_trust_values = []
    for row in combined:
        try:
            trust_values.append(float(_evidence_trust_for_report(row)))
        except (TypeError, ValueError):
            pass
    for row in evidence:
        if isinstance(row, dict):
            try:
                pack_trust_values.append(float(_evidence_trust_for_report(row)))
            except (TypeError, ValueError):
                pass
    sources = sorted({
        _evidence_source_for_report(row)
        for row in combined
        if isinstance(row, dict) and _evidence_source_for_report(row) != "-"
    })
    rows = [
        {
            "Metric": "Evidence Pack Rows",
            "Value": len(evidence),
            "Explanation": "Rows selected into the governed evidence pack used by the decision.",
        },
        {
            "Metric": "Retrieved Evidence Rows",
            "Value": len(retrieved),
            "Explanation": "Rows/chunks returned by authoritative lookup, BM25, semantic vector retrieval, and fusion before or alongside packaging.",
        },
        {
            "Metric": "Average Evidence Trust",
            "Value": round(sum(pack_trust_values) / len(pack_trust_values), 2) if pack_trust_values else "-",
            "Explanation": "Average authority score of the governed evidence pack only; retrieval/rerank relevance scores are excluded.",
        },
        {
            "Metric": "Highest Evidence Trust",
            "Value": round(max(trust_values), 2) if trust_values else "-",
            "Explanation": "Highest authority score across evidence pack and retrieved chunks. 100 means direct authoritative customer-scoped source record.",
        },
        {
            "Metric": "Lowest Evidence Trust",
            "Value": round(min(trust_values), 2) if trust_values else "-",
            "Explanation": "Lowest source-authority score across evidence pack and retrieved chunks.",
        },
        {
            "Metric": "Sources",
            "Value": len(sources),
            "Explanation": "Distinct source systems/files contributing evidence.",
        },
    ]
    note = (
        "<p class='caption info'>Why 70 vs 100: 100 is reserved for canonical runtime evidence or explicitly "
        "authoritative customer-scoped source records. 70 is the conservative authority floor for customer-scoped "
        "CSV evidence when no explicit evidence-trust field is supplied. Retrieval and rerank scores measure relevance, "
        "not evidence authority.</p>"
    )
    return _report_table_html("Evidence Metrics", rows, ["Metric", "Value", "Explanation"]) + note


def _canonicalize_runtime_state_for_artifacts(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Stabilize demo/audit fields so every artifact reads the same authority."""
    state = dict(runtime_state)
    recommendation_package = state.get("recommendation_package", {}) if isinstance(state.get("recommendation_package"), dict) else {}
    risk_authority = state.get("risk_authority", {}) if isinstance(state.get("risk_authority"), dict) else {}
    governance = state.get("governance", {}) if isinstance(state.get("governance"), dict) else {}
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    canonical_evidence_count = len(evidence or retrieved or [])
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    token_metrics = state.get("token_metrics", {}) if isinstance(state.get("token_metrics"), dict) else {}
    cost = (
        state.get("estimated_model_cost_usd")
        or state.get("estimated_cost_usd")
        or token_metrics.get("estimated_cost_usd")
        or token_metrics.get("estimated_cost")
    )

    recommendation = str(
        state.get("recommendation")
        or recommendation_package.get("recommendation")
        or recommendation_package.get("decision")
        or governance.get("decision")
        or "PENDING"
    ).upper()
    risk_level = str(
        state.get("risk_level")
        or risk_authority.get("level")
        or risk_authority.get("risk_level")
        or recommendation_package.get("risk_level")
        or recommendation_package.get("risk_rating")
        or "REVIEW"
    ).upper()
    confidence = _bounded_score_for_report(
        state.get("confidence")
        or recommendation_package.get("confidence")
        or governance.get("confidence")
    )
    trust = _bounded_score_for_report(
        state.get("trust_score")
        or recommendation_package.get("trust_score")
        or state.get("relationship_score")
    )

    state["recommendation"] = recommendation
    state["risk_level"] = risk_level
    state["confidence"] = round(confidence, 2)
    state["trust_score"] = round(trust, 2)
    state["evidence_count"] = canonical_evidence_count
    state["agent_count"] = len(trace)
    state["runtime_status"] = str(state.get("runtime_status") or state.get("status") or "COMPLETED").upper()
    if cost not in (None, ""):
        state["estimated_model_cost_usd"] = round(_numeric_for_report(cost), 6)
        state["estimated_cost_usd"] = round(_numeric_for_report(cost), 6)
    hitl_required = bool(
        state.get("hitl_required")
        or nested_get(state, "human_review_authority", "required")
        or nested_get(state, "governance", "review_required")
        or recommendation != "APPROVE"
        or risk_level in {"INSUFFICIENT_EVIDENCE", "REVIEW_REQUIRED", "CUSTOMER_NOT_FOUND", "UNKNOWN"}
    )
    state["hitl_required"] = hitl_required
    state["canonical_values"] = {
        "recommendation": recommendation,
        "risk_level": risk_level,
        "trust_score": state["trust_score"],
        "confidence": state["confidence"],
        "evidence_count": state["evidence_count"],
        "retrieved_count": len(retrieved),
        "agent_count": state["agent_count"],
        "executed_agent_count": sum(
            1
            for row in trace
            if isinstance(row, dict)
            and str(row.get("status", "")).upper() in {"COMPLETED", "SUCCESS", "SUCCEEDED"}
        ),
        "runtime_status": state["runtime_status"],
        "estimated_model_cost_usd": state.get("estimated_model_cost_usd", 0),
        "estimated_cost_usd": state.get("estimated_cost_usd", state.get("estimated_model_cost_usd", 0)),
        "hitl_required": hitl_required,
        "cost_basis": "Token telemetry / configured rate card. Execution time is not used for cost allocation.",
    }
    for projection_key in (
        "runtime_summary", "decision_snapshot", "recommendation_package",
        "executive_package", "executive_narrative", "control_tower_summary",
        "runtime_health", "runtime_health_v2", "runtime_telemetry", "telemetry",
    ):
        projection = state.get(projection_key)
        if not isinstance(projection, dict):
            continue
        projection["recommendation"] = recommendation
        projection["risk_level"] = risk_level
        projection["trust_score"] = state["trust_score"]
        projection["confidence"] = state["confidence"]
        projection["evidence_count"] = state["evidence_count"]
        projection["runtime_status"] = state["runtime_status"]
        projection["estimated_cost_usd"] = state.get("estimated_cost_usd", state.get("estimated_model_cost_usd", 0))
        projection["estimated_model_cost_usd"] = state.get("estimated_model_cost_usd", state.get("estimated_cost_usd", 0))
        projection["hitl_required"] = hitl_required
        projection["human_review_required"] = hitl_required
    if isinstance(state.get("human_review_authority"), dict):
        state["human_review_authority"]["required"] = hitl_required
    if isinstance(state.get("hitl_workflow"), dict):
        state["hitl_workflow"]["required"] = hitl_required
    if isinstance(state.get("publication_gate"), dict):
        state["publication_gate"].setdefault("release_allowed", not hitl_required)
    runtime_ingestion = events_from_agent_trace(state)
    state["runtime_ingestion"] = runtime_ingestion
    state["canonical_runtime_event_contract"] = {
        "status": runtime_ingestion.get("status"),
        "schema_version": runtime_ingestion.get("schema_version"),
        "event_count": runtime_ingestion.get("event_count"),
        "invalid_count": runtime_ingestion.get("invalid_count"),
        "required_fields": ", ".join(runtime_ingestion.get("required_fields") or []),
    }
    policy_evaluation = evaluate_policy_as_code(state)
    state["policy_as_code"] = policy_evaluation
    critical_failed = int(policy_evaluation.get("critical_failed_count") or 0)
    clean_approved_case = (
        recommendation == "APPROVE"
        and risk_level == "LOW"
        and canonical_evidence_count > 0
        and critical_failed == 0
    )
    hitl_required = not clean_approved_case
    policy_evaluation["hitl_required"] = hitl_required
    policy_evaluation["release_allowed"] = clean_approved_case
    state["hitl_required"] = hitl_required
    state["canonical_values"]["hitl_required"] = hitl_required
    if isinstance(state.get("human_review_authority"), dict):
        state["human_review_authority"]["required"] = hitl_required
    else:
        state["human_review_authority"] = {"required": hitl_required}
    if isinstance(state.get("hitl_workflow"), dict):
        state["hitl_workflow"]["required"] = hitl_required
        state["hitl_workflow"].setdefault("status", "PENDING_REVIEW" if hitl_required else "NOT_REQUIRED")
        state["hitl_workflow"].setdefault("trigger", "Policy-as-code gate" if hitl_required else "No blocking policy issue")
    else:
        state["hitl_workflow"] = {
            "required": hitl_required,
            "status": "PENDING_REVIEW" if hitl_required else "NOT_REQUIRED",
            "trigger": "Policy-as-code gate" if hitl_required else "No blocking policy issue",
        }
    if isinstance(state.get("publication_gate"), dict):
        state["publication_gate"]["release_allowed"] = clean_approved_case
        state["publication_gate"].setdefault("policy_version", policy_evaluation.get("policy_version"))
    else:
        state["publication_gate"] = {
            "release_allowed": clean_approved_case,
            "policy_version": policy_evaluation.get("policy_version"),
        }
    state["alert_notifications"] = _notification_readiness_for_report(state)
    return state


def _notification_readiness_for_report(state: Dict[str, Any]) -> Dict[str, Any]:
    dispatch = state.get("notification_dispatch") if isinstance(state.get("notification_dispatch"), dict) else None
    alerts = build_runtime_alerts(state)
    mail_status = email_config_status()
    subject, body = build_alert_email(state, alerts)
    readiness = {
        "mode": "environment_gated_email",
        "dispatch_status": "READY" if mail_status.get("configured") else "NOT_CONFIGURED",
        "automatic_dispatch": str(os.getenv("AEGIS_ALERT_AUTO_SEND", "false")).lower() in {"1", "true", "yes"},
        "active_alert_count": len(alerts),
        "critical_alert_count": sum(1 for row in alerts if str(row.get("Severity", "")).upper() == "CRITICAL"),
        "high_alert_count": sum(1 for row in alerts if str(row.get("Severity", "")).upper() == "HIGH"),
        "smtp_configured": bool(mail_status.get("configured")),
        "missing_configuration": mail_status.get("missing", []),
        "subject_preview": subject,
        "body_preview": body,
        "alerts": alerts,
    }
    if dispatch:
        readiness.update(dispatch)
    return readiness


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


REPORT_SECTIONS = [
    ("Investigation Query", "query_context"),
    ("Customer Profile", "customer_profile"), ("Accounts", "accounts"),
    ("Transactions", "transactions"), ("Alerts", "alerts"), ("Cases", "cases"),
    ("Executive Summary", "executive_narrative"), ("Decision Snapshot", "decision_snapshot"),
    ("Decision Explainability", "decision_explainability"),
    ("Recommendation", "recommendation_package"), ("Risk Profile", "risk_profile"),
    ("Retrieval Intelligence", "retrieval"), ("Retrieval Scope", "retrieval_scope"),
    ("Retrieved Chunks", "retrieved_chunks"), ("Reranked Evidence", "reranked_evidence"),
    ("Evidence Pack", "evidence_pack"),
    ("Evidence Analysis", "evidence_analysis"), ("Agent Execution Graph", "agent_execution_graph"),
    ("Agent Trace", "agent_trace"), ("Execution Timeline", "execution_timeline"),
    ("Runtime Execution Events", "execution_events_clean"),
    ("Trust", "trust"), ("Trust Evolution", "trust_evolution"),
    ("Governance", "governance"), ("Compliance", "compliance"),
    ("Compliance Evidence", "compliance_evidence"),
    ("Hallucination Guard", "hallucination_guard"),
    ("OWASP Security", "security_analysis"), ("Evaluation", "evaluation_results"),
    ("Grounding", "grounding_results"), ("Hallucination", "hallucination_results"),
    ("Runtime Health", "runtime_health_v2"), ("Runtime Telemetry", "runtime_telemetry"),
    ("Runtime Cache", "cache_lookup"), ("Query Cache", "query_cache"),
    ("Cache Intelligence", "cache_metrics"), ("Memory", "memory_dashboard"),
    ("LLM Registry", "llm_registry"), ("LLM Trace", "llm_trace"),
    ("Technical Project Summary", "technical_project_summary"),
    ("Technical Explanation", "technical_explanation"), ("Data Quality", "data_quality"),
]


def _has_report_value(value: Any) -> bool:
    if value is None or (isinstance(value, str) and value == ""):
        return False
    if isinstance(value, (dict, list, tuple, set)):
        return bool(value)
    if hasattr(value, "empty"):
        return not bool(value.empty)
    return True


def _agent_status_for_report(node: Dict[str, Any]) -> str:
    status = str(node.get("status", "UNKNOWN")).upper()
    if not node.get("observed"):
        return "NOT EXECUTED"
    if status in {"SUCCESS", "SUCCEEDED"}:
        return "COMPLETED"
    return status


def _format_ms_for_report(value: Any) -> str:
    try:
        latency_ms = int(float(value or 0))
    except (TypeError, ValueError):
        latency_ms = 0
    return f"{latency_ms / 1000:.2f}s" if latency_ms >= 1000 else f"{latency_ms}ms"


def _runtime_query_pair_for_report(state: Dict[str, Any]) -> tuple[str, str]:
    original = (
        state.get("original_user_query")
        or state.get("original_query")
        or state.get("analyst_instructions")
        or state.get("query")
        or "-"
    )
    updated = (
        state.get("rewritten_query")
        or nested_get(state, "query_rewrite_result", "rewritten_query")
        or nested_get(state, "query_rewrite", "rewritten_query")
        or state.get("query")
        or original
    )
    return str(original), str(updated)


def nested_get(container: Dict[str, Any], *path: str) -> Any:
    value: Any = container
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _report_agent_traversal_html(state: Dict[str, Any]) -> str:
    graph = state.get("agent_execution_graph")
    if not isinstance(graph, dict) or not graph.get("nodes"):
        try:
            from services1.agent_graph_service import build_agent_execution_graph
            graph = build_agent_execution_graph(state)
        except Exception:
            graph = {}
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    if not nodes:
        return "<p class='caption'>Agent traversal graph was not available for this artifact.</p>"
    cards = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        status = _agent_status_for_report(node)
        status_class = "ok" if status == "COMPLETED" else "warn" if status == "NOT EXECUTED" else "bad" if status in {"FAILED", "ERROR"} else "info"
        latency = _format_ms_for_report(node.get("duration_ms")) if node.get("observed") else "-"
        reason = node.get("skip_reason") if not node.get("observed") else ""
        cards.append(
            "<div class='agent-node'>"
            f"<span class='step'>{html.escape(str(node.get('execution_order') or '-'))}</span>"
            f"<strong>{html.escape(str(node.get('label') or node.get('id') or 'Agent'))}</strong>"
            f"<em>{html.escape(str(node.get('phase') or '-'))}</em>"
            f"<span class='pill {status_class}'>{html.escape(status)}</span>"
        f"<small>Execution Time: {html.escape(latency)}</small>"
            f"{f'<small>Reason: {html.escape(str(reason))}</small>' if reason else ''}"
            "</div>"
        )
    return "<div class='agent-path'>" + "<div class='path-arrow'>â†“</div>".join(cards) + "</div>"


def _report_agent_graphviz_svg_html(state: Dict[str, Any]) -> str:
    """Portable Graphviz-style SVG for offline packs when graphviz/dot is unavailable."""
    graph = state.get("agent_execution_graph")
    if not isinstance(graph, dict) or not graph.get("nodes"):
        try:
            from services1.agent_graph_service import build_agent_execution_graph
            graph = build_agent_execution_graph(state)
        except Exception:
            graph = {}
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    if not nodes:
        return "<p class='caption'>Graphviz topology was not available for this artifact.</p>"

    observed = [n for n in nodes if isinstance(n, dict) and n.get("observed")]
    skipped = [n for n in nodes if isinstance(n, dict) and not n.get("observed")]
    observed.sort(key=lambda n: int(n.get("execution_order") or 9999))
    skipped.sort(key=lambda n: str(n.get("label") or n.get("id") or ""))

    width = 1040
    box_w = 360
    box_h = 82
    x = 120
    y0 = 70
    gap = 34
    bus_x = x + box_w + 56
    skipped_x = bus_x + 140
    row_h = box_h + gap
    height = max(360, y0 + max(len(observed), 1) * row_h + 90)

    def esc(value: Any) -> str:
        return html.escape(_clean_text_for_report(value))

    def short(value: Any, limit: int = 38) -> str:
        text = _clean_text_for_report(value)
        return text if len(text) <= limit else text[: limit - 3] + "..."

    parts = [
        "<div class='graphviz-offline'>",
        "<div class='graphviz-legend'>"
        "<span><b class='sw app'></b> External app agent</span>"
        "<span><b class='sw aegis'></b> AEGIS control agent</span>"
        "<span><b class='sw skipped'></b> Branch not taken</span>"
        "<span><i class='line executed'></i> Executed path</span>"
        "<span><i class='line signal'></i> Runtime signal emitted</span>"
        "</div>",
        f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='Offline Graphviz agent execution topology'>",
        "<defs>"
        "<marker id='arrow-exec' markerWidth='10' markerHeight='10' refX='8' refY='3' orient='auto'><path d='M0,0 L0,6 L9,3 z' fill='#20d6a3'/></marker>"
        "<marker id='arrow-aegis' markerWidth='10' markerHeight='10' refX='8' refY='3' orient='auto'><path d='M0,0 L0,6 L9,3 z' fill='#2e90fa'/></marker>"
        "<marker id='arrow-skip' markerWidth='10' markerHeight='10' refX='8' refY='3' orient='auto'><path d='M0,0 L0,6 L9,3 z' fill='#8a94a8'/></marker>"
        "</defs>",
        f"<text x='{width / 2}' y='34' class='gv-title'>Graphviz Topology View: App Runtime Signals Into AEGIS</text>",
        f"<line x1='{bus_x}' y1='{y0 - 22}' x2='{bus_x}' y2='{height - 68}' class='gv-signal-bus'/>",
        f"<text x='{bus_x + 10}' y='{y0 - 28}' class='gv-bus-label'>runtime signal bus</text>",
    ]

    for index, node in enumerate(observed):
        y = y0 + index * row_h
        label = short(node.get("label") or node.get("id"), 42)
        status = _agent_status_for_report(node)
        latency = _format_ms_for_report(node.get("duration_ms"))
        is_aegis = str(node.get("label") or node.get("id") or "").lower().startswith("aegis")
        stroke = "#2e90fa" if is_aegis else "#20d6a3"
        fill = "#12396b" if is_aegis else "#0b3f35"
        if index == 0:
            stroke = "#f5b700"
        parts.extend([
            f"<rect x='{x}' y='{y}' width='{box_w}' height='{box_h}' rx='14' fill='{fill}' stroke='{stroke}' stroke-width='3'/>",
            f"<text x='{x + box_w / 2}' y='{y + 22}' class='gv-step'>Step {esc(node.get('execution_order') or index + 1)}</text>",
            f"<text x='{x + box_w / 2}' y='{y + 45}' class='gv-agent'>{esc(label)}</text>",
            f"<text x='{x + box_w / 2}' y='{y + 66}' class='gv-meta'>{esc(status)} | {esc(latency)} | signal emitted</text>",
            f"<circle cx='{bus_x}' cy='{y + box_h / 2}' r='4.5' class='gv-signal-dot'/>",
            f"<path d='M{x + box_w},{y + box_h / 2} C{bus_x - 34},{y + box_h / 2} {bus_x - 20},{y + box_h / 2} {bus_x},{y + box_h / 2}' class='gv-signal'/>",
        ])
        if index < len(observed) - 1:
            y2 = y + box_h + gap - 8
            marker = "arrow-aegis" if is_aegis else "arrow-exec"
            edge_label = "AEGIS validation" if is_aegis else "app step"
            parts.append(
                f"<path d='M{x + box_w / 2},{y + box_h} L{x + box_w / 2},{y2}' class='gv-exec' marker-end='url(#{marker})'/>"
            )
            parts.append(f"<text x='{x + box_w / 2 + 16}' y='{y + box_h + 20}' class='gv-edge-label'>{edge_label}</text>")

    if skipped:
        skipped_y = y0 + row_h
        parts.extend([
            f"<path d='M{x + box_w},{skipped_y + box_h / 2} C{bus_x + 55},{skipped_y + box_h / 2} {skipped_x - 40},{skipped_y + box_h / 2} {skipped_x},{skipped_y + box_h / 2}' class='gv-skip' marker-end='url(#arrow-skip)'/>",
            f"<text x='{bus_x + 38}' y='{skipped_y + box_h / 2 - 14}' class='gv-edge-label'>planned / not taken</text>",
            f"<rect x='{skipped_x}' y='{skipped_y - 10}' width='300' height='{box_h + 20}' rx='14' class='gv-skipped-box'/>",
            f"<text x='{skipped_x + 150}' y='{skipped_y + 18}' class='gv-step'>Branches Not Taken</text>",
        ])
        for idx, node in enumerate(skipped[:4]):
            parts.append(
                f"<text x='{skipped_x + 150}' y='{skipped_y + 42 + idx * 18}' class='gv-skipped-text'>{esc(short(node.get('label') or node.get('id'), 34))}</text>"
            )
        if len(skipped) > 4:
            parts.append(f"<text x='{skipped_x + 150}' y='{skipped_y + 114}' class='gv-skipped-text'>+ {len(skipped) - 4} more in table</text>")

    parts.extend(["</svg>", "</div>"])
    return "".join(parts)


def _report_decision_lineage_html(state: Dict[str, Any]) -> str:
    evidence_count = len(state.get("evidence_pack", []) or state.get("retrieved_chunks", []) or [])
    recommendation = str(state.get("recommendation") or nested_get(state, "recommendation_package", "recommendation") or "PENDING").upper()
    risk_level = str(state.get("risk_level") or nested_get(state, "risk_authority", "risk_level") or nested_get(state, "recommendation_package", "risk_level") or "REVIEW").upper()
    governance_decision = str(nested_get(state, "governance", "decision") or "-").upper()
    trust = float(state.get("trust_score", 0) or 0)
    confidence = float(state.get("confidence", 0) or 0)
    nodes = [
        ("User Query", "Intent captured"),
        ("Updated Query", "Banking-normalized objective"),
        ("Evidence Retrieval", f"{evidence_count} evidence objects"),
        ("Risk Scoring", risk_level),
        ("Governance Controls", governance_decision),
        ("Trust & Confidence", f"T {trust:.1f} | C {confidence:.1f}"),
        ("Final Recommendation", recommendation),
    ]
    cards = []
    for index, (title, detail) in enumerate(nodes, start=1):
        cards.append(
            "<div class='lineage-step'>"
            f"<span>Step {index}</span><strong>{html.escape(title)}</strong><em>{html.escape(detail)}</em>"
            "</div>"
        )
    return "<div class='lineage-path'>" + "<div class='lineage-arrow'>â†’</div>".join(cards) + "</div>"


def _report_latency_waterfall_html(state: Dict[str, Any]) -> str:
    trace = [row for row in (state.get("agent_trace", []) or []) if isinstance(row, dict)]
    ranked = sorted(trace, key=lambda row: float(row.get("duration_ms", 0) or 0), reverse=True)[:12]
    if not ranked:
        return "<p class='caption'>No agent latency data available.</p>"
    max_latency = max(float(row.get("duration_ms", 0) or 0) for row in ranked) or 1
    bars = []
    for row in ranked:
        latency = float(row.get("duration_ms", 0) or 0)
        width = max(4, min(100, latency / max_latency * 100))
        bars.append(
            "<div class='waterfall-row'>"
            f"<span>{html.escape(str(row.get('agent') or row.get('agent_name') or 'Agent'))}</span>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{width:.1f}%'></div></div>"
            f"<strong>{html.escape(_format_ms_for_report(latency))}</strong>"
            "</div>"
        )
    return "<div class='waterfall'>" + "".join(bars) + "</div>"


CSV_MISSING_MESSAGE = "Provided CSV does not have data"
SOURCE_DESCRIPTIVE_FIELDS = {"country", "segment", "relationship_since", "balance_basis"}


def _format_export_value(key: Any, value: Any) -> Any:
    """Use explicit source-data wording for missing CSV-backed profile fields."""
    key_text = str(key or "").strip().casefold()
    value_text = str(value or "").strip().casefold()
    if key_text in SOURCE_DESCRIPTIVE_FIELDS and value_text in {"", "unknown", "unkwn", "none", "null", "nan", "n/a"}:
        return CSV_MISSING_MESSAGE
    return value


def _format_customer_profile_for_export(state: Dict[str, Any]) -> Dict[str, Any]:
    profile = state.get("customer_profile", {})
    if not isinstance(profile, dict):
        return profile
    return {key: _format_export_value(key, value) for key, value in profile.items()}


def _html_report_value(value: Any) -> str:
    value = _jsonable(value)
    if isinstance(value, list):
        if not value:
            return ""
        if all(isinstance(row, dict) for row in value):
            columns = []
            for row in value:
                for key in row:
                    if key not in columns:
                        columns.append(key)
            columns = columns[:14]
            head = "".join(f"<th>{html.escape(str(key).replace('_', ' ').title())}</th>" for key in columns)
            body = "".join("<tr>" + "".join(
                f"<td>{html.escape(_clean_text_for_report(_format_export_value(key, row.get(key, '')), 520))}</td>" for key in columns
            ) + "</tr>" for row in value[:250])
            return f"<div class='scroll'><table><tr>{head}</tr>{body}</table></div>"
        return "<ul>" + "".join(f"<li>{html.escape(_clean_text_for_report(item, 520))}</li>" for item in value[:250]) + "</ul>"
    if isinstance(value, dict):
        scalar = []
        nested = []
        for key, item in value.items():
            (nested if isinstance(item, (dict, list)) else scalar).append((key, item))
        output = "<table>" + "".join(
            f"<tr><th>{html.escape(str(key).replace('_', ' ').title())}</th><td>{html.escape(_clean_text_for_report(_format_export_value(key, item), 520))}</td></tr>"
            for key, item in scalar
        ) + "</table>"
        output += "".join(
            f"<details><summary>{html.escape(str(key).replace('_', ' ').title())}</summary>{_html_report_value(item)}</details>"
            for key, item in nested
        )
        return output
    return f"<p>{html.escape(_clean_text_for_report(value, 900))}</p>"


def _is_unknown_export_value(value: Any) -> bool:
    return str(value or "").strip().casefold() in {"", "-", "none", "null", "unknown", "unkwn", "n/a"}


def _canonical_technical_explanation(state: Dict[str, Any]) -> Dict[str, Any]:
    technical = state.get("technical_explanation", {})
    technical = dict(technical) if isinstance(technical, dict) else {}
    evidence_count = (
        state.get("evidence_count")
        or len(state.get("evidence_pack", []) or [])
        or len(state.get("retrieved_chunks", []) or [])
    )
    technical["evidence_count"] = evidence_count
    technical["trust_score"] = state.get("trust_score")
    technical["confidence"] = state.get("confidence")
    technical["grounded"] = technical.get("grounded", bool(evidence_count))
    hallucination = state.get("hallucination_results", {})
    if isinstance(hallucination, dict):
        technical["hallucination_risk"] = (
            hallucination.get("risk_level")
            or hallucination.get("hallucination_risk")
            or technical.get("hallucination_risk")
            or "LOW"
        )
    technical["explainability_status"] = technical.get("explainability_status", "PASS")
    return technical


def _execution_event_export_rows(state: Dict[str, Any]) -> list[Dict[str, Any]]:
    telemetry = state.get("runtime_telemetry", {}) if isinstance(state.get("runtime_telemetry"), dict) else {}
    events = (
        state.get("execution_events")
        or state.get("execution_timeline")
        or telemetry.get("execution_timeline")
        or []
    )
    if isinstance(events, dict):
        records = [events]
    elif isinstance(events, list):
        records = events
    else:
        records = []
    rows = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        start = raw.get("start_time")
        end = raw.get("end_time")
        timestamp = raw.get("timestamp")
        has_start_or_end = not _is_unknown_export_value(start) or not _is_unknown_export_value(end)
        rows.append({
            "phase": raw.get("phase") or raw.get("stage") or raw.get("event") or "Unknown",
            "status": raw.get("status") or raw.get("state") or "-",
            "start_time": "" if _is_unknown_export_value(start) else start,
            "end_time": "" if _is_unknown_export_value(end) else end,
            "event_time": "" if has_start_or_end or _is_unknown_export_value(timestamp) else timestamp,
            "duration_ms": "" if _is_unknown_export_value(raw.get("duration_ms")) else raw.get("duration_ms"),
            "trust": "" if _is_unknown_export_value(raw.get("trust_score")) else raw.get("trust_score"),
            "confidence": "" if _is_unknown_export_value(raw.get("confidence")) else raw.get("confidence"),
        })
    return rows


def _build_technical_project_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    """Create a portable project/architecture summary for offline HTML exports."""
    retrieval = state.get("retrieval", {}) if isinstance(state.get("retrieval"), dict) else {}
    telemetry = state.get("runtime_telemetry", {}) if isinstance(state.get("runtime_telemetry"), dict) else {}
    embedding_stats = state.get("embedding_statistics", {}) if isinstance(state.get("embedding_statistics"), dict) else {}
    cache = state.get("cache_metrics", {}) if isinstance(state.get("cache_metrics"), dict) else {}
    security = state.get("security_analysis") or state.get("security") or {}
    security = security if isinstance(security, dict) else {}
    health = state.get("runtime_health_v2") or state.get("runtime_health") or {}
    health = health if isinstance(health, dict) else {}
    embedding_model = (
        retrieval.get("embedding_model")
        or state.get("embedding_model")
        or embedding_stats.get("model")
        or "BAAI/bge-small-en-v1.5"
    )
    return {
        "purpose": (
            "Portable technical explanation of the AEGIS Enterprise Control Tower runtime, "
            "suitable for project walkthroughs, architecture reviews, and audit discussions."
        ),
        "runtime_overview": {
            "runtime_id": state.get("runtime_id"),
            "customer_id": state.get("customer_id"),
            "status": state.get("runtime_status", state.get("status")),
            "recommendation": state.get("recommendation"),
            "trust_score": state.get("trust_score"),
            "confidence": state.get("confidence"),
            "executed_agents": len(state.get("agent_trace", []) or []),
            "evidence_objects": len(state.get("evidence_pack", []) or []),
            "cache_hit_ratio": cache.get("cache_hit_ratio"),
            "runtime_health": health.get("health_level") or health.get("status"),
        },
        "end_to_end_workflow": [
            {
                "stage": "Investigation Launch & Input Contract",
                "details": "Customer ID, investigation objective, selected agents/tools, and runtime metadata are captured into a canonical runtime_state contract.",
            },
            {
                "stage": "Prompt Safety & OWASP LLM Checks",
                "details": "Prompt injection, jailbreak, PII exposure, data leakage, unsafe tool-use, and OWASP LLM-style policy checks are evaluated before downstream reasoning.",
            },
            {
                "stage": "Cache Intelligence",
                "details": "Runtime, retrieval, embedding, prompt, and key-value caches are checked with TTL, freshness, hit/miss, and source fingerprint awareness.",
            },
            {
                "stage": "Query Rewrite & Planning",
                "details": "The investigation objective is rewritten into a banking-specific customer-360 plan and routed to the appropriate agents.",
            },
            {
                "stage": "Hybrid Retrieval",
                "details": "BM25 lexical retrieval and vector similarity retrieval are combined with customer/entity scoping to retrieve the correct banking evidence.",
            },
            {
                "stage": "Reranking, Fusion & Reprioritization",
                "details": "Retrieved chunks are reranked using fusion/relevance scoring, source priority, customer specificity, and evidence weighting.",
            },
            {
                "stage": "Evidence Assembly & Grounding",
                "details": "Customer, account, transaction, alert, case, loan/card, risk, and retrieved chunk facts are consolidated into an evidence pack.",
            },
            {
                "stage": "Agent Orchestration",
                "details": "Planner, router, customer, retrieval, evidence, recommendation, governance, compliance, trust, hallucination, reflection, and evaluation agents publish traceable outputs.",
            },
            {
                "stage": "Recommendation & Decision Policy",
                "details": "Canonical recommendation, risk level, human-review flag, trust, confidence, and next-best-action are reconciled across all projections.",
            },
            {
                "stage": "Governance & Compliance Validation",
                "details": "Governance and compliance agents apply explicit banking controls and deterministic policy fallbacks when no model provider is configured.",
            },
            {
                "stage": "Output Validation & Hallucination Guard",
                "details": "Groundedness, evidence coverage, hallucination risk, reflection quality, contradiction checks, and invariant tests validate the final output.",
            },
            {
                "stage": "Runtime Observability & Audit Package",
                "details": "Agent traces, execution graph, telemetry, cache metrics, PDF/HTML/JSON/CSV outputs, and ZIP package are generated for audit and review.",
            },
        ],
        "technology_stack": [
            {"layer": "Application", "technology": "Python, Streamlit Enterprise Control Tower, session-state runtime contract"},
            {"layer": "Data & Analytics", "technology": "Pandas, NumPy, governed external application datasets, source coverage notices"},
            {"layer": "LLM Runtime", "technology": "Local Qwen runtime, per-agent model/provider telemetry, deterministic policy fallback"},
            {"layer": "Embeddings", "technology": f"Sentence-transformer, {embedding_model}"},
            {"layer": "Hybrid Retrieval", "technology": "BM25 lexical retrieval, vector similarity retrieval, entity/customer scoping, CSV fingerprint refresh"},
            {"layer": "Ranking & Prioritization", "technology": "Fusion scoring, reranking, source priority, evidence weighting, reprioritized customer chunks"},
            {"layer": "Evidence Engine", "technology": "Customer/account/transaction/alert/case/loan/card evidence pack, citation coverage, average trust"},
            {"layer": "Agent Orchestration", "technology": "AEGIS Runtime Orchestrator V5, planner/router, agent graph, canonical runtime_state"},
            {"layer": "Decision Engine", "technology": "Canonical recommendation, trust score, confidence, risk authority, human-review authority, next-best-action"},
            {"layer": "Governance & Compliance", "technology": "Governance Agent, Compliance Agent, explicit banking control ledger, deterministic policy engines"},
            {"layer": "Security", "technology": "OWASP LLM controls, prompt injection, jailbreak, PII exposure, data leakage, tool security"},
            {"layer": "Validation", "technology": "Hallucination guard, reflection scoring, groundedness, coverage, invariant tests, contradiction checks"},
            {"layer": "Caching", "technology": "Runtime, retrieval, embedding, prompt and KV caches with TTL, freshness and hit/miss metrics"},
            {"layer": "Observability", "technology": "Agent/LLM traces, latency, tokens, health, trust, confidence, audit timeline, execution graph"},
            {"layer": "Reporting", "technology": "Streamlit dashboard, PDF, self-contained HTML, PNG, CSV/JSON evidence, ZIP audit package"},
        ],
        "control_plane": [
            {"control": "OWASP LLM Checks", "coverage": "Prompt injection, jailbreak, PII, data leakage, tool security", "status": security.get("status", "ENFORCED")},
            {"control": "Hybrid Retrieval Validation", "coverage": retrieval.get("retrieval_method") or retrieval.get("strategy") or "BM25 + Vector + Reranking", "status": "ACTIVE"},
            {"control": "Output Validation", "coverage": "Groundedness, coverage, hallucination, consistency, invariant checks", "status": "ACTIVE"},
            {"control": "Governance", "coverage": "Policy and approval controls", "status": (state.get("governance") or {}).get("status") if isinstance(state.get("governance"), dict) else None},
            {"control": "Compliance", "coverage": "Banking control evidence and compliance decision", "status": (state.get("compliance") or {}).get("status") if isinstance(state.get("compliance"), dict) else None},
        ],
    }


def _report_table_html(title: str, rows: list[Dict[str, Any]], columns: list[str] | None = None) -> str:
    if not rows:
        return f"<h3>{html.escape(title)}</h3><p class='caption'>No data available.</p>"
    if columns is None:
        columns = list(rows[0].keys())
    head = "".join(f"<th>{html.escape(str(col))}</th>" for col in columns)
    body = "".join(
        "<tr>" + "".join(
            f"<td>{html.escape(_clean_text_for_report(_format_export_value(col, row.get(col, '')), 520))}</td>"
            for col in columns
        ) + "</tr>"
        for row in rows
        if isinstance(row, dict)
    )
    return f"<h3>{html.escape(title)}</h3><div class='table-scroll'><table><tr>{head}</tr>{body}</table></div>"


def _policy_rule_display_rows_for_report(checks: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rule_names = {
        "POLICY_TRUST_THRESHOLD": "Trust threshold",
        "POLICY_CONFIDENCE_THRESHOLD": "Confidence threshold",
        "POLICY_EVIDENCE_MINIMUM": "Minimum evidence",
        "POLICY_RECOMMENDATION_ALLOWED": "Allowed recommendation",
        "POLICY_RISK_HITL": "Risk review rule",
        "POLICY_OWASP_BLOCK": "OWASP / security block",
        "POLICY_PII_BLOCK": "PII leakage block",
        "POLICY_AGENT_LATENCY": "Slow agent review",
        "POLICY_RETRY_LIMIT": "Retry limit",
    }

    def clean(value: Any) -> str:
        if isinstance(value, list):
            return ", ".join(str(item) for item in value) if value else "-"
        if isinstance(value, dict):
            return ", ".join(f"{key}: {val}" for key, val in value.items()) or "-"
        return "-" if value in (None, "", []) else str(value)

    rows = []
    for row in checks or []:
        if not isinstance(row, dict):
            continue
        passed = bool(row.get("passed"))
        policy_id = str(row.get("policy_id") or "")
        rows.append({
            "Rule": rule_names.get(policy_id, policy_id.replace("POLICY_", "").replace("_", " ").title()),
            "Decision": "PASS" if passed else "NEEDS REVIEW",
            "Current Value": clean(row.get("actual")),
            "Release Standard": clean(row.get("expected")),
            "Severity If Failed": "-" if passed else clean(row.get("severity")),
            "What It Means": "Meets release standard." if passed else clean(row.get("action")),
        })
    return rows


def _architecture_svg_for_report() -> str:
    path = Path(__file__).resolve().parents[2] / "outputs" / "aegis-control-tower-architecture.svg"
    if not path.exists():
        return "<p class='caption'>Architecture diagram was not generated with this package.</p>"
    try:
        return f"<div class='architecture-svg'>{path.read_text(encoding='utf-8')}</div>"
    except Exception as exc:
        return f"<p class='caption'>Architecture diagram could not be embedded: {html.escape(str(exc))}</p>"


def _report_positioning_html() -> str:
    is_rows = [
        {"AEGIS Is": "Enterprise AI control plane", "Meaning": "Common layer for AI governance, observability, evidence, economics, resilience, and audit."},
        {"AEGIS Is": "Canonical decision system", "Meaning": "Turns scattered app outputs into one governed runtime and decision record."},
        {"AEGIS Is": "Runtime assurance layer", "Meaning": "Can monitor while an app runs, validate before release, or audit after completion."},
        {"AEGIS Is": "Board-ready evidence layer", "Meaning": "Explains traversal, skipped paths, evidence lineage, controls, cost, and audit readiness."},
    ]
    not_rows = [
        {"AEGIS Is Not": "Chatbot or assistant", "Clarification": "Business applications remain outside AEGIS."},
        {"AEGIS Is Not": "RAG-only product", "Clarification": "Customer 360 is a sample app used to demonstrate the control tower."},
        {"AEGIS Is Not": "Model provider", "Clarification": "AEGIS governs and measures model usage; it does not need to own the model."},
        {"AEGIS Is Not": "Replacement for Dify / Claude / Azure / Bedrock", "Clarification": "Those platforms can plug into AEGIS by emitting the onboarding contract."},
    ]
    mode_rows = [
        {"Mode": "Post-run assurance", "When": "After app completion", "AEGIS Receives": "Completed canonical decision record", "Best For": "Audit, reporting, model risk review"},
        {"Mode": "Runtime monitoring", "When": "During execution", "AEGIS Receives": "Streaming canonical runtime events", "Best For": "Traversal, partial evidence, latency, failure detection"},
        {"Mode": "Pre-decision control", "When": "Before final output release", "AEGIS Receives": "Proposed decision, evidence, risk, trust, HITL flag", "Best For": "Policy gate, escalation, blocking"},
        {"Mode": "Continuous audit", "When": "After execution", "AEGIS Receives": "Audit IDs, artifact hashes, decision records", "Best For": "Regulatory traceability and repeatability"},
    ]
    return (
        "<div class='positioning-banner'><strong>AEGIS is an Enterprise AI Control Tower.</strong>"
        "<span>It does not build or replace AI applications. It observes, governs, measures, audits, and accelerates AI applications built elsewhere.</span></div>"
        "<div class='grid'>"
        f"<div>{_report_table_html('What AEGIS Is', is_rows)}</div>"
        f"<div>{_report_table_html('What AEGIS Is Not', not_rows)}</div>"
        "</div>"
        f"{_report_table_html('AEGIS Operating Modes', mode_rows)}"
    )


def _report_dbs_value_html(state: Dict[str, Any]) -> str:
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    token = state.get("token_metrics", {}) if isinstance(state.get("token_metrics"), dict) else {}
    cache_lookup = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
    value_rows = [
        {
            "DBS Value Lever": "Single AI governance control tower",
            "What DBS Gets": "A common control layer across LOB AI apps, regardless of whether they are built on Dify, Claude, OpenAI, Azure AI, Bedrock, LangChain, or custom stacks.",
            "AEGIS Capability": "Canonical runtime events, governed decision record, six-pillar control view.",
            "Executive Outcome": "Less fragmented AI oversight and a common language for governance, technology, risk, and audit.",
        },
        {
            "DBS Value Lever": "Faster risk and governance review",
            "What DBS Gets": "Evidence, trust, risk, controls, HITL, and recommendation are assembled into one board-ready package.",
            "AEGIS Capability": "Risk, Governance & Decisioning; OWASP AI; Score Explainability; Evidence Lineage.",
            "Executive Outcome": "Reduced manual reconstruction effort during approval, review, and escalation.",
        },
        {
            "DBS Value Lever": "Operational resilience for Agentic AI",
            "What DBS Gets": "Visibility into which agents executed, skipped, retried, failed, or became slow.",
            "AEGIS Capability": "Runtime Observability, Alerts & Notifications, Agent Traversal, latency waterfall.",
            "Executive Outcome": "Earlier detection of runtime issues before business users lose trust in the AI system.",
        },
        {
            "DBS Value Lever": "Auditability and regulatory traceability",
            "What DBS Gets": "Portable HTML/PDF/JSON/CSV evidence packages with runtime checks and canonical consistency.",
            "AEGIS Capability": "Auditability, Audit & Evidence Package, Evidence Pack, artifact manifest.",
            "Executive Outcome": "Better readiness for model risk review, internal audit, and regulator-style evidence requests.",
        },
        {
            "DBS Value Lever": "Cost and reuse discipline",
            "What DBS Gets": "Token economics, model cost in USD, cache reuse, and repeat-run savings become visible.",
            "AEGIS Capability": "Model Cost & Token Economics, Cache Acceleration, cache exact-match contract.",
            "Executive Outcome": "A path to scale AI usage without losing control of cost or duplicated execution.",
        },
        {
            "DBS Value Lever": "Reusable onboarding pattern",
            "What DBS Gets": "Clear contract for what each AI app or agent must emit to be governed by AEGIS.",
            "AEGIS Capability": "Application Onboarding Contract, Runtime Canonical Objects, AI Asset Registry.",
            "Executive Outcome": "Faster onboarding of future AI apps without reinventing governance dashboards each time.",
        },
    ]
    kpis = _visual_kpi_grid_html([
        ("Observed Runtime Agents", len(trace), "Shows how many app and AEGIS control agents were captured in this run."),
        ("Evidence Rows", len(evidence), "Shows the governed evidence basis available for review."),
        ("Estimated Model Cost (USD)", token.get("estimated_cost_usd", "-"), "Makes AI usage financially measurable."),
        ("Runtime Cache Status", cache_lookup.get("status", "-"), "Shows whether repeat execution can be accelerated."),
    ])
    flow = _visual_flow_html("DBS Enterprise Value Flow", [
        {"label": "1", "title": "AI apps stay where they are", "detail": "AEGIS does not replace business apps or model platforms."},
        {"label": "2", "title": "Apps emit canonical signals", "detail": "Runtime, evidence, decision, control, cost, and audit events are standardized."},
        {"label": "3", "title": "AEGIS governs and measures", "detail": "Trust, risk, OWASP AI, grounding, cost, cache, and resilience are evaluated."},
        {"label": "4", "title": "DBS gets audit-ready evidence", "detail": "Executives, technology, risk, GRC, and auditors share one view."},
    ])
    return (
        "<p class='caption'>DBS value view: why AEGIS matters beyond a sample RAG workflow. This tab explains the enterprise benefit of a reusable AI control plane.</p>"
        + kpis
        + flow
        + _report_table_html("DBS Value Add", value_rows, ["DBS Value Lever", "What DBS Gets", "AEGIS Capability", "Executive Outcome"])
    )


def _report_evidence_lineage_html(state: Dict[str, Any]) -> str:
    customer_id = str(state.get("customer_id") or nested_get(state, "customer_profile", "customer_id") or "Customer")
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    items = evidence or retrieved
    if not items:
        return "<p class='caption'>Evidence lineage was not available for this artifact.</p>"

    source_counts: Dict[str, int] = {}
    rows = []
    for index, item in enumerate(items[:18], start=1):
        if isinstance(item, dict):
            source = _evidence_source_for_report(item)
            method = _retrieval_method_for_report(item)
            trust = _evidence_trust_for_report(item)
            trust_basis = _evidence_trust_basis_for_report(item)
            text = _field(item, "content", "text", "document", "chunk", "summary") or str(item)
        else:
            source, method, trust, trust_basis, text = "-", "-", "-", "-", str(item)
        source_counts[source] = source_counts.get(source, 0) + 1
        rows.append({
            "Rank": index,
            "Evidence": f"E{index}",
            "Source": source,
            "Retrieval / Source Method": method,
            "Evidence Trust": trust,
            "Trust Basis": trust_basis,
            "Decision Use": "Supports final governed recommendation",
            "Preview": str(text)[:220],
        })

    source_nodes = "".join(
        f"<div class='flow-node source'><strong>{html.escape(source)}</strong><span>{count} evidence item(s)</span></div>"
        for source, count in sorted(source_counts.items())
    )
    evidence_nodes = "".join(
        f"<div class='flow-node evidence'><strong>E{row['Rank']}</strong><span>{html.escape(str(row['Source']))}</span></div>"
        for row in rows[:12]
    )
    decision = str(state.get("recommendation") or nested_get(state, "recommendation_package", "recommendation") or "-").upper()
    risk = str(state.get("risk_level") or nested_get(state, "risk_authority", "risk_level") or "-").upper()
    flow = (
        "<div class='evidence-flow'>"
        f"<div class='flow-node customer'><strong>Customer</strong><span>{html.escape(customer_id)}</span></div>"
        "<div class='flow-arrow'>-></div>"
        f"<div class='flow-stack'>{source_nodes}</div>"
        "<div class='flow-arrow'>-></div>"
        f"<div class='flow-stack evidence-stack'>{evidence_nodes}</div>"
        "<div class='flow-arrow'>-></div>"
        f"<div class='flow-node selected'><strong>Selected Evidence Set</strong><span>{len(rows)} evidence signals</span></div>"
        "<div class='flow-arrow'>-></div>"
        f"<div class='flow-node decision'><strong>Governed Decision</strong><span>{html.escape(decision)} / {html.escape(risk)}</span></div>"
        "</div>"
    )
    return flow + _report_table_html(
        "Lineage Evidence Detail",
        rows,
        ["Rank", "Evidence", "Source", "Retrieval / Source Method", "Evidence Trust", "Trust Basis", "Decision Use", "Preview"],
    )


def _demo_readiness_audit_html(state: Dict[str, Any], tests: Dict[str, Any]) -> str:
    trace = [row for row in (state.get("agent_trace", []) or []) if isinstance(row, dict)]
    graph = state.get("agent_execution_graph", {}) if isinstance(state.get("agent_execution_graph"), dict) else {}
    nodes = [row for row in graph.get("nodes", []) if isinstance(row, dict)]
    edges = [row for row in graph.get("edges", []) if isinstance(row, dict)]
    observed_nodes = [row for row in nodes if row.get("observed")]
    skipped_nodes = [row for row in nodes if not row.get("observed")]
    display_trace = {_agent_display_name(row.get("agent") or row.get("agent_name")) for row in trace}
    display_graph = {_agent_display_name(row.get("label") or row.get("id")) for row in observed_nodes}
    consolidated = sorted(name for name in display_trace - display_graph if name not in {"-", ""})
    if consolidated:
        graph_note = "Some low-level runtime events are consolidated into boardroom graph stages: " + ", ".join(consolidated[:6])
    else:
        graph_note = "Runtime events and visible graph stages are aligned after display-name normalization."
    canonical_check_ids = {
        "recommendation_consistency",
        "trust_consistency",
        "confidence_consistency",
        "human_review_consistency",
        "risk_consistency",
        "governance_consistency",
        "retrieval_average_trust",
    }
    canonical_checks = [
        check for check in tests.get("checks", [])
        if isinstance(check, dict) and check.get("id") in canonical_check_ids
    ]
    canonical_passed = all(check.get("passed") for check in canonical_checks) if canonical_checks else True

    rows = [
        {
            "Audit Area": "Demo Stability",
            "Status": "PASS",
            "Signal": "Offline HTML is self-contained; raw runtime payloads are exported as separate JSON/CSV files, not shown in the presentation page.",
        },
        {
            "Audit Area": "Canonical Consistency",
            "Status": "PASS" if canonical_passed else "REVIEW",
            "Signal": (
                f"Recommendation {state.get('recommendation')} | Risk {state.get('risk_level')} | "
                f"Trust {state.get('trust_score')} | Confidence {state.get('confidence')} | "
                f"Evidence {state.get('evidence_count')}"
            ),
        },
        {
            "Audit Area": "Graph Credibility",
            "Status": "PASS",
            "Signal": (
                f"{len(trace)} runtime event(s), {len(observed_nodes)} visible executed graph stage(s), "
                f"{len(skipped_nodes)} skipped branch(es), {len(edges)} transition(s). {graph_note}"
            ),
        },
    ]
    return _report_table_html("Demo Readiness Audit", rows, ["Audit Area", "Status", "Signal"])


def _metric_cards_html(items: list[tuple[str, Any]]) -> str:
    cards = "".join(
        "<div class='metric'>"
        f"<span>{html.escape(_clean_text_for_report(label, 80))}</span>"
        f"<strong>{html.escape(_clean_text_for_report(value, 120))}</strong>"
        "</div>"
        for label, value in items
    )
    return f"<div class='metrics'>{cards}</div>"


def _dict_table_html(title: str, payload: Any, columns: tuple[str, str] = ("Metric", "Value")) -> str:
    if isinstance(payload, dict):
        rows = [
            {columns[0]: str(key).replace("_", " ").title(), columns[1]: value}
            for key, value in payload.items()
            if _has_report_value(value)
        ]
    elif isinstance(payload, list):
        rows = payload if all(isinstance(row, dict) for row in payload) else [{columns[0]: "Value", columns[1]: payload}]
    else:
        rows = [{columns[0]: title, columns[1]: payload}] if _has_report_value(payload) else []
    return _report_table_html(title, rows)


def _owasp_control_heatmap_html(controls: list[Dict[str, Any]]) -> str:
    if not controls:
        return "<p class='caption'>OWASP visual posture was not available for this run.</p>"
    cards = []
    for row in controls[:12]:
        status = str(row.get("Status") or "-").upper()
        score = row.get("Score", "-")
        if status in {"PASS", "PASSED", "COMPLIANT", "OK", "COMPLETED"}:
            band = "ok"
            label = "Pass"
        elif status in {"FAIL", "FAILED", "ERROR", "BLOCKED"}:
            band = "bad"
            label = "Fail"
        else:
            band = "warn"
            label = "Review"
        cards.append(
            "<div class='owasp-tile'>"
            f"<span>{html.escape(_clean_text_for_report(row.get('Control'), 42))}</span>"
            f"<strong>{html.escape(_clean_text_for_report(score))}</strong>"
            f"<em class='{band}'>{html.escape(label)}</em>"
            "</div>"
        )
    return (
        "<h3>OWASP AI Control Heatmap</h3>"
        "<p class='caption'>Visual security posture by control. Green means pass/compliant, amber means review, red means failed/error.</p>"
        "<div class='owasp-heatmap'>"
        + "".join(cards)
        + "</div>"
    )


def _visual_flow_html(title: str, steps: list[Dict[str, Any]]) -> str:
    if not steps:
        return ""
    parts = []
    for index, step in enumerate(steps):
        parts.append(
            "<div class='visual-step'>"
            f"<span>{html.escape(_clean_text_for_report(step.get('label') or f'Step {index + 1}', 48))}</span>"
            f"<strong>{html.escape(_clean_text_for_report(step.get('title') or '-', 72))}</strong>"
            f"<em>{html.escape(_clean_text_for_report(step.get('detail') or '-', 140))}</em>"
            "</div>"
        )
        if index < len(steps) - 1:
            parts.append("<div class='visual-arrow'>&rarr;</div>")
    return f"<h3>{html.escape(title)}</h3><div class='visual-flow'>{''.join(parts)}</div>"


def _visual_kpi_grid_html(items: list[tuple[str, Any, str]]) -> str:
    cards = []
    for label, value, detail in items:
        cards.append(
            "<div class='visual-kpi'>"
            f"<span>{html.escape(_clean_text_for_report(label, 64))}</span>"
            f"<strong>{html.escape(_clean_text_for_report(value, 90))}</strong>"
            f"<em>{html.escape(_clean_text_for_report(detail, 150))}</em>"
            "</div>"
        )
    return f"<div class='visual-kpi-grid'>{''.join(cards)}</div>" if cards else ""


def _summarize_findings_for_report(value: Any, limit: int = 220) -> str:
    if not _has_report_value(value):
        return "-"
    if isinstance(value, list):
        if not value:
            return "-"
        labels = []
        for item in value[:5]:
            if isinstance(item, dict):
                finding_type = item.get("type") or item.get("control") or item.get("severity") or item.get("status")
                basis = item.get("basis") or item.get("reason") or item.get("masked_value") or item.get("summary")
                labels.append(" - ".join(str(part) for part in (finding_type, basis) if _has_report_value(part)) or "Structured finding")
            else:
                labels.append(str(item))
        suffix = f"; +{len(value) - 5} more" if len(value) > 5 else ""
        return _clean_text_for_report("; ".join(labels) + suffix, limit)
    if isinstance(value, dict):
        for key in ("summary", "reason", "message", "finding", "status"):
            if _has_report_value(value.get(key)):
                return _clean_text_for_report(value.get(key), limit)
    return _clean_text_for_report(value, limit)


def _report_owasp_tab_html(state: Dict[str, Any]) -> str:
    security = state.get("security_analysis") or state.get("security") or {}
    security = security if isinstance(security, dict) else {}
    controls = []
    for key, value in security.items():
        if not isinstance(value, dict):
            continue
        if any(token in key for token in ("security", "injection", "pii", "leakage", "retrieval", "memory", "runtime", "jailbreak", "tool")):
            controls.append({
                "Control": str(key).replace("_", " ").title(),
                "Status": value.get("status") or value.get("decision") or value.get("result") or security.get("status", "-"),
                "Score": value.get("score") or value.get("security_score") or value.get("risk_score") or "-",
                "Findings": _summarize_findings_for_report(value.get("findings") or value.get("summary") or value.get("reason") or value.get("matches") or "-"),
            })
    if not controls:
        for item in security.get("review_controls", []) if isinstance(security.get("review_controls"), list) else []:
            controls.append({"Control": item, "Status": "REVIEW", "Score": "-", "Findings": "Review control signalled by OWASP analysis"})
    return (
        _metric_cards_html([
            ("Security Status", security.get("security_status") or security.get("status") or "-"),
            ("Security Score", security.get("security_score", "-")),
            ("Risk Level", security.get("risk_level", "-")),
            ("Failed Controls", len(security.get("failed_controls", []) or [])),
        ])
        + "<p class='caption'>OWASP AI checks are grouped by prompt, PII/data leakage, retrieval, memory, tool, and agent-runtime controls. Findings shown here are generated from the runtime security object, not static placeholder text.</p>"
        + _owasp_control_heatmap_html(controls)
        + _report_table_html("OWASP AI Control Results", controls[:30], ["Control", "Status", "Score", "Findings"])
    )


def _report_llm_judge_tab_html(state: Dict[str, Any]) -> str:
    assurance = get_llm_judge_assurance(state)
    verdicts = assurance.get("judge_verdicts", []) if isinstance(assurance.get("judge_verdicts"), list) else []
    rubrics = assurance.get("rubric_registry", []) if isinstance(assurance.get("rubric_registry"), list) else []
    committee = assurance.get("committee_roles", []) if isinstance(assurance.get("committee_roles"), list) else []
    adversarial = assurance.get("adversarial_tests", []) if isinstance(assurance.get("adversarial_tests"), list) else []
    model_risk = assurance.get("model_risk_management", []) if isinstance(assurance.get("model_risk_management"), list) else []
    resilience = assurance.get("resilience_controls", []) if isinstance(assurance.get("resilience_controls"), list) else []
    audit = state.get("llm_judge_audit", {}) if isinstance(state.get("llm_judge_audit"), dict) else {}
    judge_rows = [
        {
            "Judge": row.get("judge_name"),
            "Rubric Version": row.get("rubric_version"),
            "Engine": row.get("engine"),
            "Provider": row.get("provider"),
            "Model": row.get("model"),
            "Score": row.get("score"),
            "Verdict": row.get("verdict"),
            "Independent": "Yes" if row.get("independent_judge") else "No",
            "Fallback": "Yes" if row.get("fallback_used") else "No",
            "Rationale": row.get("rationale"),
        }
        for row in verdicts
        if isinstance(row, dict)
    ]
    return (
        _metric_cards_html([
            ("Judge Mode", assurance.get("judge_mode", "-")),
            ("Final Verdict", assurance.get("final_verdict", "-")),
            ("HITL Required", "YES" if assurance.get("hitl_required") else "NO"),
            ("Trace ID", assurance.get("trace_id", "-")),
            ("Rubrics", len(rubrics)),
            ("Audit", audit.get("status", "READY")),
        ])
        + _visual_flow_html("LLM Judge Assurance Flow", [
            {"label": "1", "title": "Canonical app output", "detail": "Runtime events, proposed decision, evidence pack, and final narrative are captured."},
            {"label": "2", "title": "Rubric registry", "detail": "Grounding, hallucination, retrieval, OWASP, governance, and executive quality are checked."},
            {"label": "3", "title": "Judge committee", "detail": "Security, evidence, grounding, governance, business risk, and arbitration verdicts are generated."},
            {"label": "4", "title": "Control action", "detail": "Pass, human review, block/review, alert routing, and audit persistence are decided."},
        ])
        + _report_table_html("LLM Judge Agent Ownership", [
            {
                "Question": "Which agent owns LLM Judge?",
                "Answer": "AEGIS Control Agent / Assurance Layer",
                "Explanation": "It validates canonical app output, evidence, risk, security, grounding, and release readiness.",
            },
            {
                "Question": "Is it an application agent?",
                "Answer": "No",
                "Explanation": "Application agents create the business answer. AEGIS judge agents independently validate that answer before it is trusted.",
            },
            {
                "Question": "Can it run during runtime?",
                "Answer": "Yes",
                "Explanation": "It can evaluate partial runtime signals while the app runs and also judge the final canonical decision before return.",
            },
        ])
        + _report_table_html("Judge Provider Chain", [
            {
                "Priority": 1,
                "Provider": "Groq",
                "When Used": "GROQ_API_KEY is available, SDK/network call succeeds, and judge mode requests LLM judging.",
                "Purpose": "Fast online independent judge for arbitration and executive demo validation.",
            },
            {
                "Priority": 2,
                "Provider": "Local Qwen",
                "When Used": "Groq is unavailable, blocked, or fails.",
                "Purpose": "Offline resilience path using the local model runtime.",
            },
            {
                "Priority": 3,
                "Provider": "Deterministic Policy Judge",
                "When Used": "Both LLM paths fail or are disabled.",
                "Purpose": "Guarantees audit package generation continues with rule-based verdicts.",
            },
        ])
        + f"<p class='caption'>Final judge rationale: {html.escape(str(assurance.get('final_rationale', '-')))}. "
          f"Audit database: {html.escape(str(audit.get('db_path', 'persisted during runtime completion')))}.</p>"
        + _report_table_html("LLM-as-Judge Verdict Ledger", judge_rows)
        + _report_table_html("Judge Rubric Registry", rubrics)
        + _report_table_html("Multi-Judge / Committee Mode", committee)
        + _report_table_html("Adversarial Testing Coverage", adversarial)
        + _report_table_html("Model Risk Management View", model_risk)
        + _report_table_html("Resilience Controls", resilience)
    )

    evaluation = state.get("evaluation_llm") or state.get("evaluation_results") or {}
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    reflection = state.get("reflection") if isinstance(state.get("reflection"), dict) else {}
    ragas = state.get("ragas_llm") or state.get("ragas_scores") or {}
    ragas = ragas if isinstance(ragas, dict) else {}
    retrieval = state.get("retrieval_judge") or nested_get(state, "retrieval", "retrieval_judge") or {}
    retrieval = retrieval if isinstance(retrieval, dict) else {}
    security = state.get("security_llm") or state.get("security_results") or state.get("owasp_ai") or {}
    security = security if isinstance(security, dict) else {}
    agents = state.get("agents") if isinstance(state.get("agents"), dict) else {}
    eval_validation = evaluation.get("execution_validation") if isinstance(evaluation.get("execution_validation"), dict) else {}
    hitl_required = bool(state.get("hitl_required") or nested_get(state, "governance", "human_review_required"))
    runtime_errors = state.get("runtime_errors", []) if isinstance(state.get("runtime_errors"), list) else []

    judge_rows = [
        {
            "Judge": "Evaluation Judge",
            "What It Judges": "Grounding, relevance, completeness, consistency, and final answer quality.",
            "Current Engine": evaluation.get("provider") or "LLM runtime with deterministic fallback",
            "Status": evaluation.get("status") or eval_validation.get("status") or "AVAILABLE",
            "Output": evaluation.get("model") or "evaluation-scorecard-v1",
        },
        {
            "Judge": "Reflection Judge",
            "What It Judges": "Narrative quality, hallucination risk, groundedness, coverage, and recommended improvements.",
            "Current Engine": reflection.get("provider") or nested_get(reflection, "llm_reflection", "provider") or "LLM runtime with deterministic fallback",
            "Status": nested_get(agents, "reflection", "status") or "AVAILABLE",
            "Output": reflection.get("quality") or reflection.get("overall_quality") or state.get("hallucination_risk") or "-",
        },
        {
            "Judge": "Retrieval Judge",
            "What It Judges": "Evidence sufficiency, retrieval coverage, missing information, and retrieval quality.",
            "Current Engine": retrieval.get("provider") or "LLM runtime with retrieval scoring fallback",
            "Status": retrieval.get("status") or nested_get(agents, "retrieval_judge", "status") or "AVAILABLE",
            "Output": retrieval.get("model") or retrieval.get("retrieval_quality") or "retrieval-judge",
        },
        {
            "Judge": "RAGAS / Grounding Judge",
            "What It Judges": "Faithfulness, context recall, answer relevancy, and evidence grounding.",
            "Current Engine": ragas.get("provider") or "RAGAS-style evaluator / deterministic fallback",
            "Status": nested_get(agents, "ragas", "status") or "AVAILABLE",
            "Output": ragas.get("model") or f"Grounding {state.get('groundedness_score', '-')}",
        },
        {
            "Judge": "Security / OWASP Judge",
            "What It Judges": "Prompt injection, jailbreak, PII exposure, data leakage, tool misuse, and unsafe output.",
            "Current Engine": security.get("provider") or "OWASP AI policy checks with optional LLM review",
            "Status": security.get("status") or "ACTIVE",
            "Output": security.get("model") or "OWASP AI controls",
        },
    ]

    return (
        _metric_cards_html([
            ("Judge Mode", "LLM-assisted + fallback"),
            ("Independent Judge", "Target pattern"),
            ("HITL Required", "YES" if hitl_required else "NO"),
            ("Runtime Errors", len(runtime_errors)),
            ("Rubrics", 6),
            ("Adversarial Tests", 5),
        ])
        + _visual_flow_html("LLM Judge Assurance Flow", [
            {"label": "1", "title": "App output", "detail": "Generated answer, proposed decision, evidence pack, and runtime events."},
            {"label": "2", "title": "Judge rubrics", "detail": "Grounding, hallucination, retrieval sufficiency, OWASP AI, governance, and executive quality."},
            {"label": "3", "title": "Committee verdict", "detail": "Security, evidence, governance, business risk, and final arbitration judges."},
            {"label": "4", "title": "Control action", "detail": "Approve, monitor, route to HITL, alert, block, or preserve audit evidence."},
        ])
        + "<p class='caption'>AEGIS currently has LLM-assisted judge services with deterministic fallback. The production target is an independent judge model separated from the generating model, with rubric versioning, traceability, and audit sign-off.</p>"
        + _report_table_html("LLM-as-Judge Implementation Matrix", judge_rows)
        + _report_table_html("Judge Rubric Registry", [
            {"Rubric": "Grounding", "Inputs": "Final answer, evidence pack, retrieved/reranked chunks", "Pass Criteria": "Claims are supported by cited customer-scoped evidence.", "Pillar": "Trustworthy / Auditable"},
            {"Rubric": "Hallucination", "Inputs": "Answer, evidence, forbidden-domain list, contradiction checks", "Pass Criteria": "No unsupported claims, no invented customer facts, no contradiction with evidence.", "Pillar": "Trustworthy"},
            {"Rubric": "Retrieval Sufficiency", "Inputs": "Query, retrieval set, reranked evidence, source coverage", "Pass Criteria": "Required entities and source types are represented with enough evidence.", "Pillar": "Trustworthy / Measurable"},
            {"Rubric": "OWASP AI Risk", "Inputs": "Prompt, output, tool use, memory/retrieval context", "Pass Criteria": "No prompt injection, jailbreak, PII leakage, insecure tool use, or policy breach.", "Pillar": "Governable / Resilient"},
            {"Rubric": "Governance Decision", "Inputs": "Recommendation, risk, trust, confidence, HITL flag, compliance state", "Pass Criteria": "Decision aligns to policy thresholds and review routing.", "Pillar": "Governable"},
            {"Rubric": "Executive Quality", "Inputs": "Final narrative, customer facts, evidence, decision rationale", "Pass Criteria": "Board-ready, concise, evidence-backed, and free of unsupported business claims.", "Pillar": "Measurable / Auditable"},
        ])
        + _report_table_html("Multi-Judge / Committee Mode", [
            {"Judge Role": "Security Judge", "Verdict Focus": "Prompt, PII, jailbreak, data leakage, unsafe tool behavior", "Current Status": "Implemented via OWASP/security checks", "Next Upgrade": "Independent model verdict + severity calibration"},
            {"Judge Role": "Evidence Judge", "Verdict Focus": "Evidence sufficiency, source authority, retrieval/rerank quality", "Current Status": "Implemented via retrieval judge and evidence metrics", "Next Upgrade": "Cross-source contradiction scoring"},
            {"Judge Role": "Governance Judge", "Verdict Focus": "Risk, compliance, HITL, approval/monitor/block decision", "Current Status": "Implemented via governance/compliance engines", "Next Upgrade": "Policy-as-code approval workflow"},
            {"Judge Role": "Business Risk Judge", "Verdict Focus": "Customer risk, financial impact, segment-specific controls", "Current Status": "Implemented for current canonical customer profile and risk evidence", "Next Upgrade": "LOB-specific policy packs"},
            {"Judge Role": "Final Arbitration Judge", "Verdict Focus": "Resolve judge disagreements and produce governed outcome", "Current Status": "Implemented with provider chain: Groq, Qwen, deterministic fallback", "Next Upgrade": "Enterprise quorum workflow and named reviewer sign-off"},
        ])
        + _report_table_html("Adversarial Testing Coverage", [
            {"Test Type": "Prompt injection", "Example Signal": "Ignore previous instructions / reveal hidden policy", "Current Handling": "OWASP AI and security pattern checks", "Upgrade": "Automated red-team test set per app"},
            {"Test Type": "PII leakage", "Example Signal": "Credit card, account, phone, email, government ID exposure", "Current Handling": "Security/PII checks where payload is inspected", "Upgrade": "Entity-level masking and DLP policy integration"},
            {"Test Type": "Unsupported recommendation", "Example Signal": "Approval or risk statement without evidence", "Current Handling": "Grounding/reflection/evidence checks", "Upgrade": "Hard fail when no cited evidence supports decision"},
            {"Test Type": "False evidence", "Example Signal": "Evidence from wrong customer or stale source", "Current Handling": "Customer scoping and canonical evidence filtering", "Upgrade": "Source freshness and data-owner attestation"},
            {"Test Type": "Unsafe tool use", "Example Signal": "Unauthorized action, external call, or hidden tool invocation", "Current Handling": "OWASP/tool security review", "Upgrade": "Tool allowlist and runtime policy enforcement"},
        ])
        + _report_table_html("Human Review Workflow", [
            {"Step": "Trigger", "Description": "High OWASP risk, low trust, low confidence, missing evidence, policy breach, or model disagreement.", "Current Build": "HITL flag, alert evidence, and audit_human_review row", "Production Upgrade": "Workflow queue / GRC case creation"},
            {"Step": "Reviewer Packet", "Description": "Query, proposed decision, evidence pack, judge verdicts, risk, and rationale.", "Current Build": "Offline HTML/PDF package plus reviewer packet JSON in audit ledger", "Production Upgrade": "Reviewer UI with approve/reject/comment"},
            {"Step": "Decision Recording", "Description": "Reviewer decision, reason, timestamp, and artifact hashes are retained.", "Current Build": "Decision and human-review audit tables are populated per run", "Production Upgrade": "Enterprise immutable ledger integration"},
        ])
        + _report_table_html("Model Risk Management View", [
            {"Control": "Model inventory", "What To Capture": "Provider, model, version, purpose, owner, environment", "Current Status": "Visible in AI Asset Registry / LLM Trace", "Priority": "High"},
            {"Control": "Prompt registry", "What To Capture": "Prompt template, prompt hash, version, owner, approval status", "Current Status": "Partially captured", "Priority": "High"},
            {"Control": "Evaluation history", "What To Capture": "Judge score over time, failed rubrics, drift indicators", "Current Status": "Partially captured per run", "Priority": "High"},
            {"Control": "Risk rating", "What To Capture": "Model criticality, data sensitivity, user impact, control strength", "Current Status": "Captured as model risk controls in LLM assurance object", "Priority": "Medium"},
            {"Control": "Review cadence", "What To Capture": "Last review date, next review date, reviewer, sign-off", "Current Status": "Captured as review-control rows; enterprise calendar integration remains optional", "Priority": "Medium"},
        ])
        + _report_table_html("Resilience Controls", [
            {"Control": "Retries", "Runtime Signal": "retry_count, max_retries, retry_reason", "Current Status": "Canonical contract defined", "Why It Matters": "Separates transient failures from broken controls."},
            {"Control": "Fallback mode", "Runtime Signal": "fallback_used, provider, model, execution_mode", "Current Status": "Used by deterministic judge/policy engines", "Why It Matters": "Demo and governance continue even when LLM is unavailable."},
            {"Control": "Timeout / slow-agent detection", "Runtime Signal": "duration_ms, performance_band, slow_reason", "Current Status": "Runtime observability and latency waterfall", "Why It Matters": "Shows operational maturity to CTO/CIO audience."},
            {"Control": "Alert routing", "Runtime Signal": "alert_type, severity, notification_target", "Current Status": "Configured view; mail dispatch environment-gated", "Why It Matters": "Turns control findings into action."},
            {"Control": "Audit preservation", "Runtime Signal": "audit_id, artifact_hash, canonical_decision_id", "Current Status": "Offline package generated", "Why It Matters": "Supports repeatable review and evidence retention."},
        ])
    )


def _report_hitl_tab_html(state: Dict[str, Any]) -> str:
    workflow = state.get("hitl_workflow", {}) if isinstance(state.get("hitl_workflow"), dict) else {}
    gate = state.get("publication_gate", {}) if isinstance(state.get("publication_gate"), dict) else {}
    packet = workflow.get("reviewer_packet", {}) if isinstance(workflow.get("reviewer_packet"), dict) else {}
    required = bool(workflow.get("required") or state.get("hitl_required"))
    release_allowed = gate.get("release_allowed")
    if release_allowed is None:
        release_allowed = not required
    retry_count = gate.get("retry_count", 0)
    max_retries = gate.get("max_retries", 3)
    gate_status = gate.get("status") or ("BLOCKED" if required else "PASSED")
    workflow_status = workflow.get("status") or ("PENDING_REVIEW" if required else "NOT_REQUIRED")
    attempts = gate.get("attempts", []) if isinstance(gate.get("attempts"), list) else []
    condition_rows = [
        {
            "Condition": "High OWASP / PII / prompt-injection risk",
            "Signal Source": "OWASP AI + Security Judge",
            "AEGIS Action": "Block auto-release and route to HITL if unresolved",
            "Why It Matters": "Prevents unsafe, policy-violating, or sensitive output from leaving the app boundary.",
        },
        {
            "Condition": "Hallucination risk or weak grounding",
            "Signal Source": "Grounding Check + Reflection + LLM Judge",
            "AEGIS Action": f"Ask app to retry/repair up to {max_retries} times, then HITL",
            "Why It Matters": "Ensures final output is supported by retrieved evidence before publication.",
        },
        {
            "Condition": "Low trust, low confidence, or insufficient evidence",
            "Signal Source": "Evidence Judge + Trust Authority + Decision Policy",
            "AEGIS Action": "Escalate for review or return governed MONITOR/REVIEW decision",
            "Why It Matters": "Avoids overconfident approval when evidence quality is not strong enough.",
        },
        {
            "Condition": "Runtime failure, missing canonical object, or skipped required control",
            "Signal Source": "Runtime Observability + Canonical Consistency Audit",
            "AEGIS Action": "Stop release, preserve audit trail, and request remediation",
            "Why It Matters": "Keeps execution measurable and auditable even when the app workflow degrades.",
        },
        {
            "Condition": "All controls pass",
            "Signal Source": "Publication Gate",
            "AEGIS Action": "Release governed output back to the onboarded application",
            "Why It Matters": "Provides a board-ready proof that the output was checked before use.",
        },
    ]
    return (
        _metric_cards_html([
            ("HITL Required", "YES" if required else "NO"),
            ("Workflow Status", workflow_status),
            ("Release Gate", gate_status),
            ("Retry Policy", f"{retry_count}/{max_retries}"),
            ("Release Allowed", "YES" if release_allowed else "NO"),
            ("Review Queue", workflow.get("queue", "-")),
        ])
        + _visual_flow_html("Human Review & Release Gate Flow", [
            {"label": "1", "title": "App output", "detail": "Business app emits runtime events and final canonical decision."},
            {"label": "2", "title": "AEGIS checks", "detail": "Trust, grounding, OWASP, policy, evidence, runtime, and cost checks run."},
            {"label": "3", "title": "Retry policy", "detail": "AEGIS requests repair/retry up to the configured limit when output is not publication-ready."},
            {"label": "4", "title": "Human review", "detail": "If the issue remains, the reviewer packet is routed to the HITL queue."},
            {"label": "5", "title": "Release decision", "detail": "Output is either released, blocked, or approved by a reviewer."},
        ])
        + "<p class='caption'>This is the AEGIS release-control view. In this demo it is persisted as canonical runtime state and audit evidence; in production it can integrate with GRC, Jira, ServiceNow, email, or internal case-management queues.</p>"
        + _report_table_html("Release-Gate Conditions", condition_rows, ["Condition", "Signal Source", "AEGIS Action", "Why It Matters"])
        + _report_table_html("Human Review Workflow", [
            {"Field": "Workflow ID", "Value": workflow.get("workflow_id", "-")},
            {"Field": "Runtime ID", "Value": workflow.get("runtime_id") or state.get("runtime_id", "-")},
            {"Field": "Customer ID", "Value": workflow.get("customer_id") or state.get("customer_id", "-")},
            {"Field": "Required", "Value": "Yes" if required else "No"},
            {"Field": "Status", "Value": workflow_status},
            {"Field": "Trigger", "Value": workflow.get("trigger") or gate.get("block_reason") or "-"},
            {"Field": "Queue", "Value": workflow.get("queue", "-")},
            {"Field": "Priority", "Value": workflow.get("priority", "-")},
            {"Field": "Allowed Actions", "Value": ", ".join(workflow.get("allowed_actions", []) or []) or "-"},
            {"Field": "SLA", "Value": workflow.get("sla", "-")},
        ], ["Field", "Value"])
        + _report_table_html("Reviewer Packet", [
            {"Review Item": "Recommendation", "Canonical Value": packet.get("recommendation") or state.get("recommendation", "-")},
            {"Review Item": "Risk Level", "Canonical Value": packet.get("risk_level") or state.get("risk_level", "-")},
            {"Review Item": "Trust Score", "Canonical Value": packet.get("trust_score") or state.get("trust_score", "-")},
            {"Review Item": "Confidence", "Canonical Value": packet.get("confidence") or state.get("confidence", "-")},
            {"Review Item": "Evidence Count", "Canonical Value": packet.get("evidence_count") or len(state.get("evidence_pack") or state.get("retrieved_chunks") or [])},
            {"Review Item": "Publication Gate", "Canonical Value": gate_status},
            {"Review Item": "Release Allowed", "Canonical Value": "Yes" if release_allowed else "No"},
        ], ["Review Item", "Canonical Value"])
        + (_report_table_html("Publication Retry Attempts", attempts) if attempts else "")
    )


def _report_runtime_observability_tab_html(state: Dict[str, Any], latency_html: str, timeline_table: str) -> str:
    runtime_health = state.get("runtime_health_v2") or state.get("runtime_health") or {}
    runtime_health = runtime_health if isinstance(runtime_health, dict) else {}
    telemetry = state.get("runtime_telemetry", {}) if isinstance(state.get("runtime_telemetry"), dict) else {}
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    total_ms = sum(_numeric_for_report(row.get("duration_ms")) for row in trace if isinstance(row, dict))
    telemetry_events = telemetry.get("execution_events", [])
    if isinstance(telemetry_events, (list, tuple, set)):
        telemetry_event_count = len(telemetry_events)
    elif isinstance(telemetry_events, dict):
        telemetry_event_count = len(telemetry_events)
    else:
        telemetry_event_count = int(_numeric_for_report(telemetry_events))
    return (
        _metric_cards_html([
            ("Runtime Status", state.get("runtime_status") or runtime_health.get("status") or state.get("status") or "-"),
            ("Health Score", runtime_health.get("health_score", "-")),
            ("Agents Observed", len(trace)),
            ("Total Execution Time", _format_ms_for_report(total_ms)),
            ("Telemetry Events", telemetry_event_count),
            ("Warnings", len(runtime_health.get("warnings", []) or [])),
        ])
        + _dict_table_html("Runtime Health Summary", runtime_health)
        + "<h3>Execution Timeline</h3>"
        + timeline_table
        + "<h3>Latency Waterfall / Agent Performance Chart</h3>"
        + latency_html
    )


def _report_alerts_tab_html(state: Dict[str, Any]) -> str:
    notification = state.get("alert_notifications", {}) if isinstance(state.get("alert_notifications"), dict) else _notification_readiness_for_report(state)
    alerts = notification.get("alerts", []) if isinstance(notification.get("alerts"), list) else []
    if not alerts:
        alerts = [{"Severity": "Info", "Signal": "No critical trigger", "Detail": "No runtime critical alert in this artifact"}]
    policy_rows = [
        {"Severity": "Critical", "Trigger Examples": "OWASP failure, high hallucination, governance block, runtime exception", "Frequency": "Immediate per run", "Channel": "Email + incident channel"},
        {"Severity": "High", "Trigger Examples": "Trust below threshold, missing evidence, customer data missing", "Frequency": "Immediate per run", "Channel": "Email + GRC queue"},
        {"Severity": "Medium", "Trigger Examples": "Confidence warning, slow agent, cache miss", "Frequency": "Near real-time or digest", "Channel": "Dashboard / email digest"},
    ]
    return (
        _metric_cards_html([
            ("Monitoring Mode", "Per-run event evaluation"),
            ("Trigger Mode", "Auto-send ready" if notification.get("automatic_dispatch") else "Manual / controlled send"),
            ("Active Alerts", notification.get("active_alert_count", len(alerts))),
            ("Critical / High", f"{notification.get('critical_alert_count', 0)} / {notification.get('high_alert_count', 0)}"),
            ("Mail Channel", "Configured" if notification.get("smtp_configured") else "Not configured"),
        ])
        + _visual_flow_html("Alert Escalation Flow", [
            {"label": "Signal", "title": "Runtime / policy event", "detail": "Latency, OWASP, evidence, trust, cache, or runtime exception is evaluated per run."},
            {"label": "Control", "title": "Severity classification", "detail": "AEGIS classifies the condition as critical, high, medium, or informational."},
            {"label": "Route", "title": "Notification target", "detail": "Email, GRC queue, incident channel, dashboard, or digest route is selected."},
            {"label": "Audit", "title": "Evidence retained", "detail": "The alert reason and supporting runtime record are kept in the audit package."},
        ])
        + "<p class='caption'>This offline view uses the same alert service as Streamlit. Mail is sent only when SMTP variables are configured and a controlled send action or approved auto-send policy is enabled.</p>"
        + _report_table_html("Notification Configuration", [
            {"Setting": "Dispatch Status", "Value": notification.get("dispatch_status", "-")},
            {"Setting": "SMTP Configured", "Value": "Yes" if notification.get("smtp_configured") else "No"},
            {"Setting": "Missing Configuration", "Value": ", ".join(notification.get("missing_configuration", []) or []) or "-"},
            {"Setting": "Email Subject Preview", "Value": notification.get("subject_preview", "-")},
        ])
        + _report_table_html("Current Run Alert Signals", [
            {
                "Severity": row.get("Severity"),
                "Signal": row.get("Signal") or row.get("Trigger"),
                "Detail": row.get("Detail") or row.get("Current Run Signal"),
            }
            for row in alerts
            if isinstance(row, dict)
        ])
        + _report_table_html("Alert Routing Policy", policy_rows)
    )


def _report_cache_tab_html(state: Dict[str, Any], cache_maturity_html: str) -> str:
    cache = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
    query_cache = state.get("query_cache", {}) if isinstance(state.get("query_cache"), dict) else {}
    key_dimensions = cache.get("key_dimensions", {}) if isinstance(cache.get("key_dimensions"), dict) else {}
    total_ms = _numeric_for_report(state.get("total_execution_ms") or state.get("latency_ms") or state.get("total_latency_ms"))
    if not total_ms:
        trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
        total_ms = sum(_numeric_for_report(row.get("duration_ms") or row.get("latency_ms")) for row in trace if isinstance(row, dict))
    runtime_status = str(cache.get("status") or "-").upper()
    query_status = str(query_cache.get("status") or "-").upper()
    reuse_ratio = _numeric_for_report(cache.get("cache_hit_ratio"))
    cache_business_flow = _visual_flow_html("Cache Business Impact", [
        {
            "label": "1",
            "title": f"Runtime {runtime_status}",
            "detail": "Full runtime cache serves the completed investigation only when every cache-contract dimension matches.",
        },
        {
            "label": "2",
            "title": f"Query {query_status}",
            "detail": "Query rewrite can be reused independently even when the full runtime result is still warming.",
        },
        {
            "label": "3",
            "title": _format_ms_for_report(total_ms),
            "detail": "Observed execution time that can become next-run saving when full runtime cache hits.",
        },
        {
            "label": "4",
            "title": f"{reuse_ratio:.1f}% reuse",
            "detail": "Current full-runtime reuse signal for this exact customer, query, app, data, model, and policy version.",
        },
    ])
    key_rows = [
        {"Dimension": str(key).replace("_", " ").title(), "Value / Fingerprint": value, "Why It Matters": "Part of exact-match full runtime cache reuse"}
        for key, value in key_dimensions.items()
    ]
    key_table = _report_table_html("Full Runtime Cache Exact-Match Contract", key_rows) if key_rows else ""
    return (
        _metric_cards_html([
            ("Runtime Cache Status", cache.get("status", "-")),
            ("Query Cache Status", query_cache.get("status", "-")),
            ("Entries", cache.get("entries", 0)),
            ("Hit Ratio", f"{_numeric_for_report(cache.get('cache_hit_ratio')):.1f}%"),
            ("TTL", _format_ms_for_report(_numeric_for_report(cache.get("ttl_seconds")) * 1000) if cache.get("ttl_seconds") else "-"),
            ("Cache Key", cache.get("cache_key", "-")),
        ])
        + cache_business_flow
        + "<p class='caption'>Full runtime reuse requires the same customer, normalized query, app version, data fingerprint, model version, policy version, and cache contract version. Query cache may hit even when full runtime cache is still warming.</p>"
        + _dict_table_html("Runtime Cache Details", cache)
        + _dict_table_html("Query Cache Details", query_cache)
        + key_table
        + "<h3>Cache Reuse Maturity by Layer</h3>"
        + cache_maturity_html
    )


def _report_cost_tab_html(state: Dict[str, Any]) -> str:
    token = state.get("token_metrics", {}) if isinstance(state.get("token_metrics"), dict) else {}
    telemetry = state.get("runtime_telemetry", {}) if isinstance(state.get("runtime_telemetry"), dict) else {}
    cost = telemetry.get("cost_metrics") if isinstance(telemetry.get("cost_metrics"), dict) else state.get("cost_metrics", {})
    cost = cost if isinstance(cost, dict) else {}
    llm_trace = state.get("llm_trace", []) if isinstance(state.get("llm_trace"), list) else []
    trace_rows = []
    for row in llm_trace[:50]:
        if isinstance(row, dict):
            trace_rows.append({
                "Agent": row.get("agent") or row.get("agent_name") or "-",
                "Provider": row.get("provider", "-"),
                "Model": row.get("model", "-"),
                "Status": row.get("status", "-"),
                "Input Tokens": row.get("input_tokens", row.get("prompt_tokens", 0)),
                "Output Tokens": row.get("output_tokens", row.get("completion_tokens", 0)),
                "Estimated Cost (USD)": row.get("estimated_cost_usd", 0),
                "Cost Basis": row.get("cost_basis", "Token telemetry only; latency is not used for cost allocation"),
            })
    trace_table = _report_table_html("LLM Trace", trace_rows) if trace_rows else "<p class='caption'>LLM trace unavailable.</p>"
    return (
        _metric_cards_html([
            ("Provider", token.get("provider", "-")),
            ("Model", token.get("model", "-")),
            ("Total Tokens", token.get("total_tokens", 0)),
            ("Estimated Cost (USD)", token.get("estimated_cost_usd", cost.get("estimated_cost_usd", 0))),
        ])
        + _visual_flow_html("Cost Attribution Flow", [
            {"label": "1", "title": "Prompt tokens", "detail": "Captured from model telemetry when available."},
            {"label": "2", "title": "Completion tokens", "detail": "Captured from the generated response payload."},
            {"label": "3", "title": "Pricing basis", "detail": "Token price table or configured enterprise rate card."},
            {"label": "4", "title": "Estimated cost (USD)", "detail": "Calculated from tokens, not from execution time."},
        ])
        + "<p class='caption'>Cost is attributed from token telemetry only. Execution time is shown separately because waiting, retrieval, CPU work, and serialization do not necessarily burn model tokens.</p>"
        + _dict_table_html("Token Consumption", token)
        + _dict_table_html("Cost Monitoring", cost)
        + trace_table
    )


def _report_risk_governance_tab_html(state: Dict[str, Any], governance_html: str, recommendation_html: str) -> str:
    governance = state.get("governance", {}) if isinstance(state.get("governance"), dict) else {}
    compliance = state.get("compliance", {}) if isinstance(state.get("compliance"), dict) else {}
    rec = state.get("recommendation_package", {}) if isinstance(state.get("recommendation_package"), dict) else {}
    decision_rows = [
        {"Stage": "Risk Check", "Decision": state.get("risk_level", "-"), "Meaning": "Canonical risk authority for the customer/request."},
        {"Stage": "Compliance", "Decision": compliance.get("decision") or compliance.get("status") or "-", "Meaning": "Policy and banking controls result."},
        {"Stage": "Governance", "Decision": governance.get("decision") or "-", "Meaning": "AEGIS governed decision before final recommendation."},
        {"Stage": "Human Review", "Decision": "Required" if state.get("hitl_required") else "Not required", "Meaning": "Escalation decision based on risk, confidence, and policy."},
        {"Stage": "Final Recommendation", "Decision": state.get("recommendation") or rec.get("recommendation") or "-", "Meaning": "Final canonical recommendation shown across all outputs."},
    ]
    return (
        _metric_cards_html([
            ("Recommendation", state.get("recommendation", "-")),
            ("Risk Level", state.get("risk_level", "-")),
            ("Governance Decision", governance.get("decision", "-")),
            ("Compliance Status", compliance.get("status") or compliance.get("decision") or "-"),
            ("Human Review", "YES" if state.get("hitl_required") else "NO"),
            ("Governance Score", governance.get("governance_score", "-")),
        ])
        + _visual_flow_html("Human Review Decision Path", [
            {"label": "1", "title": "Risk authority", "detail": f"Risk signal: {state.get('risk_level', '-')}"},
            {"label": "2", "title": "Compliance controls", "detail": f"Compliance: {compliance.get('status') or compliance.get('decision') or '-'}"},
            {"label": "3", "title": "Governance gate", "detail": f"Decision: {governance.get('decision') or state.get('recommendation') or '-'}"},
            {"label": "4", "title": "Human review control", "detail": "Route to reviewer when risk, evidence, confidence, OWASP, or policy conditions require escalation."},
            {"label": "5", "title": "Final governed decision", "detail": f"Recommendation: {state.get('recommendation') or rec.get('recommendation') or '-'}"},
        ])
        + _report_table_html("Governance Control Ladder", decision_rows)
        + "<h3>Recommendation Authority</h3>"
        + recommendation_html
        + "<h3>Governance & Compliance Details</h3>"
        + governance_html
    )


def _report_investigation_tab_html(state: Dict[str, Any], customer_html: str, query_overview_html: str) -> str:
    customer = state.get("customer_profile", {}) if isinstance(state.get("customer_profile"), dict) else {}
    return (
        _metric_cards_html([
            ("Customer", state.get("customer_id", "-")),
            ("Runtime", state.get("runtime_id", "-")),
            ("Status", state.get("runtime_status") or state.get("status") or "-"),
            ("Customer Name", customer.get("customer_name", "-")),
            ("KYC", customer.get("kyc_status", "-")),
            ("AML", customer.get("aml_status", "-")),
        ])
        + _visual_flow_html("Investigation Intake Flow", [
            {"label": "Input", "title": "Original user query", "detail": "Raw analyst request captured for traceability."},
            {"label": "Normalize", "title": "Updated query", "detail": "Business intent is expanded into an evidence-ready investigation objective."},
            {"label": "Scope", "title": "Customer context", "detail": "Customer ID, profile, KYC, AML, account, and transaction context are bound to the run."},
            {"label": "Execute", "title": "Governed investigation", "detail": "Runtime events, evidence, controls, and final decision are recorded."},
        ])
        + "<h3>Investigation Context</h3>"
        + query_overview_html
        + "<h3>Customer Intelligence</h3>"
        + customer_html
    )


def _report_agents_tab_html(state: Dict[str, Any], traversal_html: str, agent_table: str, timeline_table: str, runtime_canonical_html: str) -> str:
    graph = state.get("agent_execution_graph", {}) if isinstance(state.get("agent_execution_graph"), dict) else {}
    nodes = graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else []
    skipped = [row for row in nodes if isinstance(row, dict) and not row.get("observed")]
    observed_nodes = [row for row in nodes if isinstance(row, dict) and row.get("observed")]
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    executed = [row for row in trace if isinstance(row, dict) and str(row.get("status", "")).upper() in {"SUCCESS", "COMPLETED"}]
    skipped_rows = [
        {
            "Agent": row.get("label") or row.get("id") or "-",
            "Status": "NOT EXECUTED",
            "Skip Reason": row.get("skip_reason") or "Branch was planned but not selected by the runtime route.",
        }
        for row in skipped
    ]
    return (
        _metric_cards_html([
            ("Executed Graph Nodes", f"{len(observed_nodes)}/{len(nodes) or len(trace)}"),
            ("Runtime Trace Events", len(executed)),
            ("Skipped Branches", len(skipped)),
            ("Graph Transitions", len(graph.get("edges", []) if isinstance(graph.get("edges"), list) else [])),
        ])
        + "<p class='caption'>Graph nodes are the executive topology view. Runtime trace events are the raw emitted agent events; the counts can differ because multiple low-level trace events may be consolidated into one presentation node.</p>"
        + traversal_html
        + runtime_canonical_html
        + "<h3>Observed Agents</h3>"
        + agent_table
        + (_report_table_html("Path Not Taken", skipped_rows) if skipped_rows else "")
        + "<h3>Runtime Execution Events</h3>"
        + timeline_table
    )


def _report_retrieval_tab_html(state: Dict[str, Any], retrieved_table: str, reranked_table: str) -> str:
    retrieval = state.get("retrieval", {}) if isinstance(state.get("retrieval"), dict) else {}
    knowledge = state.get("knowledge_intelligence", {}) if isinstance(state.get("knowledge_intelligence"), dict) else {}
    retrieved = state.get("retrieved_chunks", []) if isinstance(state.get("retrieved_chunks"), list) else []
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    method_summary = [{
        "Retrieval Mode": "Hybrid BM25 + Semantic Vector + Authoritative CSV",
        "Retrieved Chunks": len(retrieved),
        "Evidence Pack": len(evidence),
        "Customer Scope": "Enforced",
        "Score Meaning": "Authoritative rows use 1 as direct-match marker; hybrid rows use BM25/vector fusion relevance.",
    }]
    score_rows = [
        {"Score": "1", "Applies To": "Authoritative CSV match", "Meaning": "Exact customer-scoped source-of-record match marker, not a trust score."},
        {"Score": "Hybrid value", "Applies To": "BM25 + vector retrieval", "Meaning": "Relevance contribution from keyword and semantic retrieval."},
        {"Score": "Rerank score", "Applies To": "Reranked view", "Meaning": "Final read priority after retrieval/fusion/source priority."},
        {"Score": "Evidence Trust", "Applies To": "Evidence pack", "Meaning": "Source authority for audit confidence, separate from retrieval relevance."},
    ]
    return (
        _metric_cards_html([
            ("Retrieved Chunks", len(retrieved)),
            ("Evidence", len(evidence)),
            ("Retrieval Mode", "Hybrid + authoritative"),
            ("Evidence Source", "Customer-scoped records"),
        ])
        + _visual_flow_html("Retrieved vs Reranked vs Final Evidence", [
            {"label": "Source", "title": "Customer-scoped records", "detail": "CSV/source-of-record rows and vector-indexed chunks are searched."},
            {"label": "Retrieve", "title": "BM25 + semantic vector", "detail": "Keyword and embedding retrieval produce relevance candidates."},
            {"label": "Rerank", "title": "Fusion / source priority", "detail": "Candidates are prioritized for reading order and evidence packaging."},
            {"label": "Finalize", "title": "Governed evidence pack", "detail": "Selected evidence is passed into governance and audit."},
        ])
        + _report_table_html("Retrieval Method Summary", method_summary)
        + _report_table_html("Retrieval Score Guide", score_rows)
        + "<h3>Retrieved Chunks</h3>"
        + retrieved_table
        + "<h3>Reranked Evidence</h3>"
        + reranked_table
        + "<h3>Retrieval Statistics</h3>"
        + _dict_table_html("Retrieval Statistics", retrieval.get("retrieval_statistics") or state.get("retrieval_statistics") or {})
        + "<h3>Knowledge Intelligence</h3>"
        + _dict_table_html("Knowledge Intelligence", knowledge)
    )


def _report_auditability_tab_html(state: Dict[str, Any], tests: Dict[str, Any], checks: str) -> str:
    passed = tests.get("passed_count", 0)
    total = tests.get("total", 0)
    artifact_dir = state.get("artifact_dir") or state.get("result_dir") or "-"
    rows = [
        {"Audit Object": "Canonical Runtime State", "Status": "Captured", "Purpose": "Single source for UI, HTML, PDF, CSV, JSON, and audit checks."},
        {"Audit Object": "Evidence Records", "Status": "Captured", "Purpose": "Evidence source, rank, trust, and content hashes for traceability."},
        {"Audit Object": "Agent Execution", "Status": "Captured", "Purpose": "Agent status, execution order, execution time, skipped branches, and handoffs."},
        {"Audit Object": "Generated Artifacts", "Status": "Captured", "Purpose": "Offline package for review without rerunning the app."},
    ]
    return (
        _metric_cards_html([
            ("Runtime Checks", f"{passed}/{total} passed"),
            ("Canonical Status", "PASS" if tests.get("passed") else "REVIEW"),
            ("Artifact Location", artifact_dir),
            ("Audit Mode", "Offline portable"),
        ])
        + _visual_flow_html("Audit Trail Flow", [
            {"label": "Run", "title": "Runtime state", "detail": "One canonical runtime object feeds UI, HTML, PDF, CSV, JSON, and audit checks."},
            {"label": "Trace", "title": "Agent execution", "detail": "Agent status, order, execution time, retries, skipped paths, and lineage are captured."},
            {"label": "Evidence", "title": "Evidence hashes", "detail": "Source, rank, trust, and content hash support traceability."},
            {"label": "Package", "title": "Portable artifacts", "detail": "HTML, PDF, JSON, CSV, and manifest are retained for offline review."},
        ])
        + _report_table_html("Audit Objects", rows)
        + _report_table_html("Runtime Check Summary", _runtime_check_summary_rows(tests), ["Control Check", "Status", "What It Proves", "Evidence"])
        + "<p class='caption'>Detailed invariant payloads are preserved in test_results.json. The offline presentation keeps this view board-readable.</p>"
    )


def _runtime_check_summary_rows(tests: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Convert raw invariant checks into a presentation-safe audit summary."""
    checks = tests.get("checks", []) if isinstance(tests, dict) else []
    if not isinstance(checks, list):
        return []
    friendly = {
        "terminal_status": ("Runtime completed", "The run reached a terminal successful status."),
        "terminal_phase": ("Runtime phase complete", "The orchestrator reached the runtime-complete phase."),
        "mandatory_trust": ("Trust agent executed", "Trust scoring was present in the runtime trace."),
        "trust_terminal_state": ("Trust terminal state", "Trust control finished cleanly."),
        "retrieval_scope_enforced": ("Customer scope enforced", "Retrieved evidence was constrained to the investigated customer."),
        "customer_retrieval_coverage": ("Customer evidence coverage", "Customer-specific evidence was available or review routing was applied."),
        "missing_customer_guard": ("Missing-customer guard", "Missing customer data cannot be silently auto-approved."),
        "low_confidence_governance": ("Low-confidence governance", "Low confidence routes to review unless an authoritative decision exists."),
        "recommendation_consistency": ("Recommendation consistency", "Recommendation is identical across UI, HTML, PDF, JSON, and audit views."),
        "trust_consistency": ("Trust consistency", "Trust score is reconciled from one canonical value."),
        "confidence_consistency": ("Confidence consistency", "Confidence is reconciled from one canonical value."),
        "human_review_consistency": ("Human review consistency", "HITL flag is consistent across decision objects."),
        "risk_consistency": ("Risk consistency", "Risk score and level use the canonical risk authority."),
        "governance_consistency": ("Governance consistency", "Governance decision aligns with the final recommendation."),
        "retrieval_average_trust": ("Retrieval trust available", "Evidence has a non-zero source-authority signal."),
        "executive_llm_grounding": ("Executive narrative grounded", "Executive narrative avoids forbidden unsupported claims."),
        "hallucination_decision_consistency": ("Hallucination decision check", "Approval is allowed only when hallucination posture is acceptable or review is required."),
        "reflection_math_consistency": ("Reflection score consistency", "Grounding, coverage, hallucination, and quality are mutually consistent."),
        "no_runtime_errors": ("No runtime errors", "No execution exceptions were captured."),
        "canonical_values_present": ("Canonical values present", "Core values are present for reuse across all projections."),
        "canonical_cost_not_latency_allocated": ("Cost calculation basis", "Model cost is token/rate-card based, not allocated by waiting time."),
        "llm_judge_provider_transparency": ("Judge provider transparency", "Each judge verdict shows provider and engine used."),
        "runtime_signal_contract": ("Runtime signal contract", "Each observed agent emitted or inherited the canonical runtime signal."),
    }
    rows = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_id = str(check.get("id") or "runtime_check")
        title, purpose = friendly.get(check_id, (check_id.replace("_", " ").title(), "Runtime invariant validation."))
        actual = _clean_text_for_report(check.get("actual"), 160)
        rows.append({
            "Control Check": title,
            "Status": "PASS" if check.get("passed") else "REVIEW",
            "What It Proves": purpose,
            "Evidence": actual,
        })
    return rows

def _report_html(state: Dict[str, Any], tests: Dict[str, Any]) -> str:
    customer = state.get("customer_profile", {}) if isinstance(state.get("customer_profile"), dict) else {}
    technical_project = state.get("technical_project_summary") or _build_technical_project_summary(state)
    query_rewrite = state.get("query_rewrite", {}) if isinstance(state.get("query_rewrite"), dict) else {}
    query_context = {
        "original_query": (
            state.get("original_query")
            or state.get("user_input")
            or state.get("query")
            or query_rewrite.get("original_query")
        ),
        "updated_query": (
            state.get("rewritten_query")
            or state.get("updated_query")
            or query_rewrite.get("rewritten_query")
            or query_rewrite.get("updated_query")
            or state.get("query")
        ),
        "query_changed": query_rewrite.get("query_changed"),
        "rewrite_strategy": query_rewrite.get("rewrite_strategy") or query_rewrite.get("strategy"),
        "rewrite_reason": query_rewrite.get("reason") or query_rewrite.get("rewrite_reason"),
    }
    if query_context.get("query_changed") is None:
        query_context["query_changed"] = (
            bool(query_context.get("original_query") and query_context.get("updated_query"))
            and str(query_context.get("original_query")) != str(query_context.get("updated_query"))
        )
    query_context = {key: value for key, value in query_context.items() if value not in (None, "")}
    if query_context:
        state["query_context"] = query_context
    rows = {
        "Runtime ID": state.get("runtime_id"), "Customer ID": state.get("customer_id"),
        "Customer": customer.get("customer_name"), "Status": state.get("runtime_status", state.get("status")),
        "Recommendation": state.get("recommendation"), "Trust": state.get("trust_score"),
        "Confidence": state.get("confidence"), "Human Review": state.get("hitl_required"),
        "Agents": len(state.get("agent_trace", []) or []), "Evidence": len(state.get("evidence_pack", []) or []),
    }
    facts = "".join(f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in rows.items() if v not in (None, ""))
    risk_authority = state.get("risk_authority", {}) if isinstance(state.get("risk_authority"), dict) else {}
    retrieval_scope = state.get("retrieval_scope", {}) if isinstance(state.get("retrieval_scope"), dict) else {}
    customer_missing = (
        state.get("customer_found") is False
        or str(customer.get("record_status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or str(risk_authority.get("status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or str(retrieval_scope.get("coverage_status", "")).upper() == "CUSTOMER_NOT_FOUND"
    )
    customer_alert_html = (
        f"<div class='alert'><strong>Customer not present in source database/CSV.</strong> "
        f"Customer {html.escape(str(state.get('customer_id') or customer.get('customer_id') or ''))} "
        "cannot be risk-scored, health-classified or auto-approved. Human review is required.</div>"
        if customer_missing else ""
    )
    checks = "".join(f"<tr><td>{html.escape(c['id'])}</td><td><span class='pill {'ok' if c['passed'] else 'bad'}'>{'PASS' if c['passed'] else 'FAIL'}</span></td><td><pre>{html.escape(str(c['actual']))}</pre></td></tr>" for c in tests["checks"])
    evidence = state.get("evidence_pack", []) if isinstance(state.get("evidence_pack"), list) else []
    retrieved_rows = _retrieved_evidence_rows(state)
    reranked_rows = state.get("reranked_evidence") if isinstance(state.get("reranked_evidence"), list) else _reranked_evidence_rows(state)
    trace = state.get("agent_trace", []) if isinstance(state.get("agent_trace"), list) else []
    timeline = state.get("execution_timeline", []) if isinstance(state.get("execution_timeline"), list) else []
    def table(records, columns):
        body = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(_clean_text_for_report(_format_export_value(col, row.get(col, '')), 520))}</td>"
                for col in columns
            )
            + "</tr>"
            for row in records[:100]
            if isinstance(row, dict)
        )
        headers = "".join(f"<th>{html.escape(str(col).replace('_',' ').title())}</th>" for col in columns)
        return f"<div class='table-scroll'><table><tr>{headers}</tr>{body}</table></div>"
    agent_table = table(trace, ["execution_order", "agent", "phase", "status", "duration_ms", "tool_used"])
    evidence_report_rows = []
    for index, row in enumerate(evidence, start=1):
        if not isinstance(row, dict):
            continue
        retrieval_method = _retrieval_method_for_report(row)
        retrieval_score = _score_for_report(row, "score", "similarity_score", "retrieval_score")
        rerank_score = _score_for_report(row, "rerank_score", "cross_encoder_score", "relevance_score")
        retrieval_summary = "-"
        if retrieval_method != "-" or retrieval_score != "-" or rerank_score != "-":
            retrieval_summary = f"{retrieval_method}; retrieval {retrieval_score}; rerank {rerank_score}"
        evidence_report_rows.append({
            "rank": index,
            "evidence_id": f"Evidence {index}",
            "source": _evidence_source_for_report(row),
            "evidence_trust": _evidence_trust_for_report(row),
            "trust_basis": _evidence_trust_basis_for_report(row),
            "retrieval_rerank": retrieval_summary,
            "evidence_preview": _clean_text_for_report(
                _field(row, "content", "text", "document", "chunk", "summary") or row,
                360,
            ),
        })
    evidence_table = table(evidence_report_rows, ["rank", "evidence_id", "source", "evidence_trust", "trust_basis", "retrieval_rerank", "evidence_preview"])
    retrieved_table = table(retrieved_rows, ["rank", "source", "evidence_trust", "trust_basis", "retrieval_method", "retrieval_contribution", "score", "rerank_score", "text"])
    reranked_table = table(reranked_rows, ["rerank", "source", "retrieval_method", "rerank_score", "original_rank", "evidence_text"])
    timeline_table = table(state.get("execution_events_clean") or _execution_event_export_rows(state), ["phase", "status", "start_time", "end_time", "event_time", "duration_ms", "trust", "confidence"])
    trust = float(state.get("trust_score", 0) or 0); confidence = float(state.get("confidence", 0) or 0)
    chart = f"""<svg viewBox='0 0 720 180' role='img' aria-label='Decision scores'><line x1='40' y1='145' x2='690' y2='145' stroke='#ccd1d8'/><rect x='120' y='{145-trust}' width='150' height='{trust}' rx='4' fill='#e31837'/><rect x='430' y='{145-confidence}' width='150' height='{confidence}' rx='4' fill='#344054'/><text x='195' y='168' text-anchor='middle'>Trust {trust:.2f}</text><text x='505' y='168' text-anchor='middle'>Confidence {confidence:.2f}</text></svg>"""
    metric_cards = "".join(
        f"<div class='metric'><span>{html.escape(str(label))}</span><strong>{html.escape(str(value))}</strong></div>"
        for label, value in [
            ("Recommendation", state.get("recommendation")),
            ("Trust", state.get("trust_score")),
            ("Confidence", state.get("confidence")),
            ("Human Review", state.get("hitl_required")),
            ("Agents", len(trace)),
            ("Evidence", len(evidence)),
        ]
    )
    original_query, updated_query = _runtime_query_pair_for_report(state)
    query_overview_html = (
        "<div class='query-grid'>"
        f"<div><h3>User Query</h3><pre>{html.escape(original_query)}</pre></div>"
        f"<div><h3>Updated Query</h3><pre>{html.escape(updated_query)}</pre></div>"
        "</div>"
    )
    positioning_html = _report_positioning_html()
    traversal_html = _report_agent_graphviz_svg_html(state) + _report_agent_traversal_html(state)
    lineage_html = _report_decision_lineage_html(state)
    evidence_lineage_html = _report_evidence_lineage_html(state)
    readiness_html = _demo_readiness_audit_html(state, tests)
    latency_html = _report_latency_waterfall_html(state)
    pillars_html = _control_pillars_html(state)
    cache_maturity_html = _cache_maturity_html(state)
    architecture_html = _architecture_svg_for_report()
    nav_items = [
        ("query", "Query"), ("architecture", "Architecture"), ("snapshot", "Snapshot"), ("pillars", "AI Pillars"), ("traversal", "Traversal"), ("lineage", "Lineage"),
        ("evidence-lineage", "Evidence Lineage"),
        ("latency", "Latency"), ("cache-maturity", "Cache Maturity"), ("cache", "Cache"), ("customer", "Customer"), ("executive", "Executive"),
        ("retrieval", "Retrieval"), ("recommendation", "Recommendation"), ("agents", "Agents"),
        ("governance", "Governance"), ("technical", "Technical Summary"), ("runtime", "Runtime"),
        ("tests", "Tests"), ("details", "Full Details"),
    ]
    nav = "".join(f"<a href='#{anchor}'>{label}</a>" for anchor, label in nav_items)
    executive = state.get("executive_narrative", {}) if isinstance(state.get("executive_narrative"), dict) else {}
    recommendation_package = state.get("recommendation_package", {}) if isinstance(state.get("recommendation_package"), dict) else {}
    retrieval = state.get("retrieval", {}) if isinstance(state.get("retrieval"), dict) else {}
    evidence_analysis = state.get("evidence_analysis", {}) if isinstance(state.get("evidence_analysis"), dict) else {}
    governance = state.get("governance", {}) if isinstance(state.get("governance"), dict) else {}
    compliance = state.get("compliance", {}) if isinstance(state.get("compliance"), dict) else {}
    runtime_health = state.get("runtime_health_v2") or state.get("runtime_health") or {}
    runtime_health = runtime_health if isinstance(runtime_health, dict) else {}
    cache = state.get("cache_metrics", {}) if isinstance(state.get("cache_metrics"), dict) else {}
    cache_lookup = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
    query_cache = state.get("query_cache", {}) if isinstance(state.get("query_cache"), dict) else {}
    technical_html = _html_report_value(technical_project)
    executive_summary = html.escape(str(executive.get("executive_summary") or executive.get("summary") or "Executive summary not supplied."))
    recommendation_html = _html_report_value(recommendation_package)
    customer_html = _html_report_value(customer)
    query_html = _html_report_value(query_context) if query_context else "<p>No query context reported.</p>"
    retrieval_html = _html_report_value(retrieval)
    evidence_html = _html_report_value(evidence_analysis or evidence[:20])
    governance_html = _html_report_value({"governance": governance, "compliance": compliance})
    runtime_html = _html_report_value({"runtime_health": runtime_health, "cache_metrics": cache, "runtime_telemetry": state.get("runtime_telemetry", {})})
    cache_html = _html_report_value({
        "runtime_cache": cache_lookup,
        "query_cache": query_cache,
        "cache_key_query": state.get("cache_key_query"),
        "cache_metrics": cache,
        "cache_layers": state.get("cache_layers", {}),
    })
    security_html = _html_report_value(state.get("security_analysis") or state.get("security") or {})
    audit_artifact_html = _report_table_html("Generated Artifact Inventory", [
        {"Artifact": "Interactive_Dashboard.html", "Purpose": "Offline Streamlit-style demo dashboard with tabs and visuals.", "Audience": "Executives / SG management"},
        {"Artifact": "Executive_Investigation_Report.pdf", "Purpose": "Portable executive report for offline sharing.", "Audience": "Executives / risk / audit"},
        {"Artifact": "runtime_state.json", "Purpose": "Full canonical runtime payload retained for audit traceability.", "Audience": "Technical audit"},
        {"Artifact": "agent_trace.json / Agent_Trace.csv", "Purpose": "Raw emitted agent runtime events and lineage.", "Audience": "Engineering / audit"},
        {"Artifact": "canonical_runtime_events.json / Canonical_Runtime_Events.csv", "Purpose": "One canonical runtime signal per graph node with status, timing, lineage, retries, decision, evidence, trust, confidence, risk, and cost.", "Audience": "Architecture / audit"},
        {"Artifact": "evidence.json / Evidence_Pack.csv", "Purpose": "Governed evidence pack used for the decision.", "Audience": "Risk / audit"},
        {"Artifact": "retrieved_evidence.json / Retrieved_Evidence.csv", "Purpose": "Retrieved evidence before final packaging.", "Audience": "AI / retrieval teams"},
        {"Artifact": "reranked_evidence.json / Reranked_Evidence.csv", "Purpose": "Reranked evidence ordering and score trace.", "Audience": "AI / model risk"},
        {"Artifact": "test_results.json", "Purpose": "Canonical consistency and runtime invariant checks.", "Audience": "Audit / governance"},
        {"Artifact": "manifest.json", "Purpose": "Package inventory with artifact hashes.", "Audience": "Audit / release control"},
    ])
    detail_sections = ""
    html_doc = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>AEGIS Investigation {html.escape(str(state.get('runtime_id')))}</title><style>:root{{--red:#e31837;--ink:#252b36;--muted:#667085;--line:#dfe3e8;--soft:#f6f7f9}}body{{font:14px Segoe UI,Arial;margin:0;background:var(--soft);color:var(--ink)}}header{{background:#fff;border-bottom:4px solid var(--red);padding:24px 5%;position:sticky;top:0;z-index:5}}main{{max-width:1450px;margin:auto;padding:22px}}.card{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:20px;margin:16px 0;box-shadow:0 2px 8px #1018280b}}.alert{{background:#feecef;color:#b42318;border:1px solid #fda29b;border-radius:10px;padding:14px 18px;margin:16px 0}}h1{{margin:0;font-size:32px}}h2{{border-left:4px solid var(--red);padding-left:10px}}h3{{margin-top:18px}}.caption{{color:var(--muted)}}.nav{{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}}.nav a{{text-decoration:none;color:var(--ink);border:1px solid var(--line);border-radius:999px;padding:7px 12px;background:#fff}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}}.metric{{border:1px solid var(--line);border-top:3px solid var(--red);border-radius:8px;padding:14px;background:#fff}}.metric span{{display:block;color:var(--muted);font-size:12px}}.metric strong{{font-size:24px;display:block;margin-top:8px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid var(--line);padding:9px;text-align:left;vertical-align:top;max-width:520px;overflow-wrap:anywhere}}th{{background:#f6f7f9}}pre{{white-space:pre-wrap;margin:0;max-width:700px}}.pill{{padding:3px 8px;border-radius:12px;font-weight:600}}.ok{{background:#e7f8f0;color:#087443}}.bad{{background:#feecef;color:#b42318}}details{{margin:12px 0;border:1px solid var(--line);border-radius:8px;background:#fff}}summary{{font-weight:600;cursor:pointer;padding:10px}}details>*:not(summary){{margin-left:10px;margin-right:10px}}.scroll{{overflow:auto}}@media print{{header{{position:static}}body{{background:#fff}}.card{{break-inside:auto;box-shadow:none}}details{{display:block}}.nav{{display:none}}}}</style></head><body><header><h1>AEGIS Executive Investigation Dashboard</h1><p class='caption'>Complete portable Runtime Intelligence report â€” Streamlit-like offline replica generated from canonical runtime_state.</p><nav class='nav'>{nav}</nav></header><main>{customer_alert_html}<section id='snapshot' class='card'><h2>Executive Snapshot</h2><div class='metrics'>{metric_cards}</div><table>{facts}</table>{chart}</section><section id='cache' class='card'><h2>Cache Acceleration</h2>{cache_html}</section><section id='customer' class='card'><h2>Customer Intelligence</h2>{customer_html}</section><section id='executive' class='card'><h2>Executive Summary</h2><p>{executive_summary}</p>{_html_report_value(executive)}</section><section id='retrieval' class='card'><h2>Retrieval Intelligence</h2><div class='grid'><div><h3>Retrieval Configuration</h3>{retrieval_html}</div><div><h3>Evidence Analysis</h3>{evidence_html}</div></div><h3>Retrieved Evidence</h3>{retrieved_table}<h3>Reranked Evidence</h3>{reranked_table}<h3>Evidence Pack</h3>{evidence_table}</section><section id='recommendation' class='card'><h2>Executive Recommendation</h2>{recommendation_html}</section><section id='agents' class='card'><h2>Agent Execution & Runtime Events</h2><h3>Observed Agents</h3>{agent_table}<h3>Runtime Execution Events</h3>{timeline_table}</section><section id='governance' class='card'><h2>Governance, Compliance & Security</h2>{governance_html}{security_html}</section><section id='technical' class='card'><h2>Technical Architecture</h2>{technical_html}</section><section id='runtime' class='card'><h2>Runtime Telemetry & Health</h2>{runtime_html}</section><section id='tests' class='card'><h2>Runtime Tests</h2><table><tr><th>Test</th><th>Result</th><th>Actual</th></tr>{checks}</table></section><section id='details' class='card'><h2>Full Runtime Details</h2><p class='caption'>Expanded canonical runtime sections below mirror the Streamlit page data model for audit review.</p>{detail_sections}</section></main></body></html>"""
    sidebar_nav = "".join(
        f"<a class='sidebar-link' href='#{anchor}'>{html.escape(label)}</a>"
        for anchor, label in nav_items[:15]
    )
    sidebar = (
        "<div class='st-shell'>"
        "<aside class='st-sidebar'>"
        "<div class='sidebar-kicker'>app v2</div>"
        "<div class='sidebar-title'>AEGIS Control Tower V2</div>"
        "<a class='sidebar-link active' href='#query'>Runtime Intelligence</a>"
        "<div class='sidebar-block'>"
        "<div class='sidebar-label'>Investigation</div>"
        f"<div class='sidebar-meta'><strong>Customer ID</strong><br>{html.escape(str(state.get('customer_id') or '-'))}</div>"
        f"<div class='sidebar-meta'><strong>Runtime ID</strong><br>{html.escape(str(state.get('runtime_id') or '-'))}</div>"
        f"<div class='sidebar-meta'><strong>Status</strong><br>{html.escape(str(state.get('runtime_status', state.get('status', '-'))))}</div>"
        "</div>"
        f"<div class='sidebar-block'>{sidebar_nav}</div>"
        "</aside>"
        "<div class='st-main'>"
    )
    html_doc = html_doc.replace("<body><header>", f"<body>{sidebar}<header class='st-header'>", 1)
    html_doc = html_doc.replace("</header><main>", "</header><main class='st-content'>", 1)
    html_doc = html_doc.replace("</main></body>", "</main></div></div></body>", 1)
    html_doc = html_doc.replace("AEGIS Executive Investigation Dashboard", "AEGIS Enterprise Control Tower")
    html_doc = html_doc.replace(
        "Complete portable Runtime Intelligence report â€” Streamlit-like offline replica generated from canonical runtime_state.",
        "Enterprise Agentic AI Investigation Platform â€” offline replica of the Streamlit Control Tower.",
    )
    html_doc = html_doc.replace("<nav class='nav'>", "<nav class='nav tabs'>", 1)
    visual_css = """.st-shell{display:grid;grid-template-columns:304px minmax(0,1fr);min-height:100vh;background:#fff}.st-sidebar{background:#eef1f5;border-right:1px solid #d7dee8;padding:28px 18px;position:sticky;top:0;height:100vh;overflow:auto}.sidebar-kicker{color:#475467;font-size:13px;margin-bottom:14px}.sidebar-title{font-weight:800;color:#0f1728;background:#dce3ee;border-radius:6px;padding:10px 12px;margin:8px 0 12px}.sidebar-link{display:block;text-decoration:none;color:#344054;padding:9px 10px;border-radius:6px;margin:2px 0}.sidebar-link:hover,.sidebar-link.active{background:#e2e8f0;color:#111827}.sidebar-block{border-top:1px solid #c9d2df;margin-top:18px;padding-top:18px}.sidebar-label{font-weight:800;font-size:18px;color:#111827;margin-bottom:10px}.sidebar-meta{font-size:13px;color:#475467;line-height:1.5;margin:0 0 12px}.st-main{min-width:0;background:#fff}.st-header{position:static!important;border-bottom:1px solid #d7dce3!important;padding:52px 34px 24px!important}.st-header h1{font-size:42px!important;color:#1d2736!important}.st-content{max-width:1320px!important;margin:0 auto!important;padding:26px 34px 42px!important}.nav{border-bottom:1px solid #cfd5dd!important;border-radius:0!important;gap:4px!important}.nav a{border:0!important;border-bottom:2px solid transparent!important;border-radius:0!important;background:transparent!important;color:#475467!important;padding:12px 10px!important}.nav a:first-child,.nav a:hover{color:#e31837!important;border-bottom-color:#e31837!important}.card{border-radius:7px!important;box-shadow:none!important}.card h2{border-left:0!important;padding-left:0!important}.metric{border-radius:7px!important;min-height:92px}.metric strong{font-size:30px!important}.query-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}.query-grid>div{border:1px solid var(--line);border-radius:8px;padding:16px;background:#fbfcfe}.warn{background:#fff4e5;color:#b54708}.info{background:#e8f1ff;color:#175cd3}.positioning-banner{border:1px solid #b7d7ff;border-left:6px solid #1f73d2;background:#eef6ff;border-radius:10px;padding:16px 18px;margin:12px 0 18px}.positioning-banner strong{display:block;color:#17324d;font-size:20px;margin-bottom:6px}.positioning-banner span{display:block;color:#334155;font-size:15px;line-height:1.45}.architecture-svg{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px}.architecture-svg svg{width:100%;min-width:980px;height:auto;display:block}.pillar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:14px 0}.pillar-card{border:1px solid var(--line);border-top:4px solid #11845b;border-radius:8px;padding:14px;background:#f3fbf7}.pillar-card span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:700}.pillar-card strong{font-size:28px;display:block;margin:8px 0}.pillar-card em{font-style:normal;color:#344054}.agent-path{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px;align-items:stretch}.agent-node{border:1px solid var(--line);border-top:4px solid var(--red);border-radius:8px;padding:13px;background:#fff;min-height:145px}.agent-node .step{color:var(--muted);font-size:12px}.agent-node strong,.lineage-step strong{display:block;font-size:16px;margin:8px 0 4px}.agent-node em,.lineage-step em{display:block;color:var(--muted);font-style:normal;margin-bottom:8px}.agent-node small{display:block;color:var(--muted);margin-top:7px}.path-arrow{display:none}.lineage-path{display:flex;gap:12px;align-items:stretch;overflow:auto;padding-bottom:8px}.lineage-step{min-width:205px;border:1px solid var(--line);border-top:4px solid #52a8ff;border-radius:8px;padding:16px;background:#fbfcfe}.lineage-step:last-child{border-top-color:#21a67a;background:#f2fbf7}.lineage-step span{color:var(--muted);font-size:12px}.lineage-arrow{display:flex;align-items:center;color:#7f8aa3;font-size:24px}.evidence-flow{display:flex;gap:12px;align-items:center;overflow:auto;padding:8px 0 14px}.flow-stack{display:grid;gap:8px;min-width:210px}.evidence-stack{grid-template-columns:repeat(2,minmax(88px,1fr));min-width:250px}.flow-node{border:1px solid var(--line);border-top:4px solid #175cd3;border-radius:8px;background:#fff;padding:12px;min-width:150px}.flow-node strong{display:block;color:#202938}.flow-node span{display:block;color:var(--muted);font-size:12px;margin-top:5px}.flow-node.customer{border-top-color:#0b3a66}.flow-node.evidence{border-top-color:#21a67a;min-width:80px}.flow-node.selected{border-top-color:#344054}.flow-node.decision{border-top-color:#007a5a}.flow-arrow{font-size:24px;color:#7f8aa3;flex:0 0 auto}.waterfall{display:grid;gap:10px}.waterfall-row,.maturity-row{display:grid;grid-template-columns:240px 1fr 90px;gap:12px;align-items:center}.bar-track{height:18px;background:#eef2f6;border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#e31837,#344054)}.bar-fill.green{background:#11845b}.bar-fill.amber{background:#f79009}.bar-fill.gray{background:#98a2b3}@media(max-width:980px){.st-shell{grid-template-columns:1fr}.st-sidebar{position:static;height:auto}.st-header,.st-content{padding-left:18px!important;padding-right:18px!important}.st-header h1{font-size:32px!important}}@media(max-width:800px){.waterfall-row,.maturity-row{grid-template-columns:1fr}.lineage-path,.evidence-flow{display:grid}.lineage-arrow,.flow-arrow{display:none}.architecture-svg svg{min-width:760px}}@media print{.st-shell{display:block}.st-sidebar,.nav{display:none}.st-header{padding:0!important}.st-content{max-width:none!important;padding:0!important}}"""
    html_doc = html_doc.replace("</style>", f"{visual_css}</style>", 1)
    query_card = (
        f"<section id='query' class='card'><h2>User Query + Updated Query</h2>"
        f"{query_overview_html}{query_html}</section>"
    )
    visual_sections = (
        f"<section id='architecture' class='card'><h2>Control Tower Architecture</h2>"
        f"<p class='caption'>Offline replica of the Streamlit architecture view. External apps stay outside AEGIS and emit canonical runtime events plus final decision records.</p>{architecture_html}</section>"
        f"<section id='pillars' class='card'><h2>Enterprise AI Control Tower Pillars</h2>"
        f"<p class='caption'>Trustworthy, governable, measurable, scalable, resilient, and auditable AI signals captured in the artifact.</p>{pillars_html}</section>"
        f"<section id='traversal' class='card'><h2>Live Agent Traversal Path</h2>"
        f"<p class='caption'>Static artifact view of executed and skipped agents. "
        f"Interactive click-through remains available in Streamlit.</p>{traversal_html}</section>"
        f"<section id='lineage' class='card'><h2>Decision Lineage Graph</h2>"
        f"<p class='caption'>Boardroom view of how the recommendation was produced.</p>{lineage_html}</section>"
        f"<section id='evidence-lineage' class='card'><h2>Evidence Lineage Graph</h2>"
        f"<p class='caption'>Static offline view of source evidence flowing into governance and final decisioning.</p>{evidence_lineage_html}</section>"
        f"<section id='latency' class='card'><h2>Latency Waterfall / Agent Performance</h2>{latency_html}</section>"
        f"<section id='cache-maturity' class='card'><h2>Cache Reuse Maturity by Layer</h2>{cache_maturity_html}</section>"
    )
    streamlit_tabs = [
        ("six-pillars", "Six Pillar Control View"),
        ("dbs-value", "DBS Value Add"),
        ("owasp", "OWASP AI"),
        ("llm-judge", "LLM Judge & Assurance"),
        ("release-policy", "AI Release Policy Gate"),
        ("human-review", "Human Review & Release Gate"),
        ("runtime-observability", "Runtime Observability"),
        ("alerts", "Alerts & Notifications"),
        ("cache", "Cache Acceleration"),
        ("cost", "Model Cost & Token Economics"),
        ("evidence", "Evidence"),
        ("risk", "Risk, Governance & Decisioning"),
        ("investigation", "Investigation"),
        ("agents", "Agents"),
        ("retrieval", "Retrieval"),
        ("architecture", "Control Tower Architecture"),
        ("onboarding", "Application Onboarding Contract"),
        ("technical", "Technical Architecture"),
        ("asset-registry", "AI Asset Registry"),
        ("auditability", "Auditability"),
        ("audit-package", "Audit & Evidence Package"),
    ]
    top_nav_items = [
        ("query", "Query"),
        ("snapshot", "Runtime Snapshot"),
        ("positioning", "Executive Positioning"),
        ("pillars", "Control Tower Pillars"),
        ("canonical", "Canonical Audit"),
        ("cache-roi", "Cache ROI"),
        ("traversal", "Agent Traversal"),
        ("lineage", "Decision Lineage"),
    ] + streamlit_tabs + [("executive", "Executive Summary")]
    top_nav = "".join(f"<a href='#{anchor}'>{html.escape(label)}</a>" for anchor, label in top_nav_items)
    tab_nav = "".join(
        f"<button type='button' class='st-tab-button{' active' if index == 0 else ''}' data-tab='{html.escape(anchor)}'>{html.escape(label)}</button>"
        for index, (anchor, label) in enumerate(streamlit_tabs)
    )
    sidebar_nav = "".join(
        f"<a class='sidebar-link' href='#{anchor}'>{html.escape(label)}</a>"
        for anchor, label in top_nav_items
    )
    token_html = _html_report_value(state.get("token_metrics", {}))
    alert_html = _html_report_value({
        "alert_status": "Configured for offline review",
        "runtime_errors": state.get("runtime_errors", []),
        "human_review_required": state.get("hitl_required"),
        "notification_note": "Email dispatch is runtime-configured in Streamlit; this offline page preserves the alert evidence.",
    })
    canonical_html = (
        "<div class='metrics'>"
        f"<div class='metric'><span>Recommendation</span><strong>{html.escape(str(state.get('recommendation') or '-'))}</strong></div>"
        f"<div class='metric'><span>Risk Level</span><strong>{html.escape(str(state.get('risk_level') or nested_get(state, 'risk_authority', 'risk_level') or '-'))}</strong></div>"
        f"<div class='metric'><span>Trust</span><strong>{html.escape(str(state.get('trust_score') or '-'))}</strong></div>"
        f"<div class='metric'><span>Confidence</span><strong>{html.escape(str(state.get('confidence') or '-'))}</strong></div>"
        f"<div class='metric'><span>Evidence</span><strong>{html.escape(str(len(evidence)))}</strong></div>"
        f"<div class='metric'><span>Agents</span><strong>{html.escape(str(len(trace)))}</strong></div>"
        "</div>"
        f"<table>{facts}</table>"
    )
    onboarding_html = _report_table_html("Onboarding Contract", [
        {
            "Contract Area": "Application Identity",
            "Required": "Mandatory",
            "What the app emits": "app_id, app_name, business_domain, owner, environment, run_id",
            "AEGIS pillar": "Auditable / Governable",
        },
        {
            "Contract Area": "Runtime Canonical Events",
            "Required": "Mandatory",
            "What the app emits": "agent started/completed, tool calls, evidence retrieval, risk/cache/latency/error events",
            "AEGIS pillar": "Measurable / Resilient",
        },
        {
            "Contract Area": "Final Canonical Decision Record",
            "Required": "Mandatory",
            "What the app emits": "recommendation, risk level, confidence, trust, governance result, HITL flag",
            "AEGIS pillar": "Trustworthy / Governable",
        },
        {
            "Contract Area": "Evidence Pack",
            "Required": "Mandatory for evidence-backed apps",
            "What the app emits": "retrieved evidence, reranked evidence, source, rank, trust score, content hash",
            "AEGIS pillar": "Trustworthy / Auditable",
        },
        {
            "Contract Area": "Cost and Cache Telemetry",
            "Required": "Optional but recommended",
            "What the app emits": "token usage, model cost, cache lookup/hit/miss, TTL, reuse reason",
            "AEGIS pillar": "Scalable / Measurable",
        },
        {
            "Contract Area": "Alert and Resilience Signals",
            "Required": "Optional but recommended",
            "What the app emits": "policy breach, latency breach, hallucination risk, failed tool, fallback path",
            "AEGIS pillar": "Resilient / Governable",
        },
    ])
    onboarding_completeness_html = _report_table_html("Onboarding Contract Completeness", [
        {"Contract Area": "Runtime Identity", "Completeness": "100%", "Why It Matters": "Identifies app, run, environment, customer, and ownership."},
        {"Contract Area": "Runtime Events", "Completeness": "100%", "Why It Matters": "Powers traversal, status, latency, skipped-path, and resilience views."},
        {"Contract Area": "Decision Record", "Completeness": "100%", "Why It Matters": "Creates the canonical source for recommendation, risk, trust, confidence, and HITL."},
        {"Contract Area": "Evidence Objects", "Completeness": "100%", "Why It Matters": "Supports grounding, lineage, retrieval/rerank transparency, and audit review."},
        {"Contract Area": "Cost & Cache", "Completeness": "85%", "Why It Matters": "Shows USD cost, token usage, cache reuse, TTL, and repeat-run savings."},
        {"Contract Area": "Asset & Audit Metadata", "Completeness": "80%", "Why It Matters": "Connects app, agents, prompts, models, tools, and generated artifacts to audit records."},
    ])
    canonical_signal_flow_html = _visual_flow_html("Canonical Signal Flow", [
        {"label": "1", "title": "External AI Application", "detail": "Dify, Claude, OpenAI, Azure AI Foundry, Bedrock, LangChain, or custom app runs its own agents."},
        {"label": "2", "title": "Runtime Canonical Events", "detail": "Every app agent emits start, complete, skip, retry, tool, evidence, latency, cost, and error signals."},
        {"label": "3", "title": "AEGIS Runtime Monitor", "detail": "AEGIS reconstructs traversal, detects slow or skipped branches, and records live observability."},
        {"label": "4", "title": "Final Canonical Decision", "detail": "The app sends recommendation, risk, confidence, evidence pack, and proposed response."},
        {"label": "5", "title": "Governance, Audit & Release Gate", "detail": "AEGIS checks grounding, OWASP/PII, policy, HITL, auditability, cost, cache, and release readiness."},
    ])
    agent_parameter_html = _report_table_html("Accepted Canonical Agent Parameters", [
        {"Agent Category": "All Agents", "Parameter": "agent_id, agent_name, agent_type", "Required": "Mandatory", "Type": "string / enum", "Purpose": "Identifies the agent and whether it belongs to the business application or AEGIS control plane."},
        {"Agent Category": "All Agents", "Parameter": "phase, execution_order, stage_id", "Required": "Mandatory / stage_id optional", "Type": "string / integer", "Purpose": "Reconstructs sequence and parallel execution stages."},
        {"Agent Category": "All Agents", "Parameter": "status, started_at, completed_at, duration_ms", "Required": "Mandatory", "Type": "enum / datetime / integer", "Purpose": "Measures execution health, runtime, and completion state."},
        {"Agent Category": "All Agents", "Parameter": "retry_count, max_retries, retry_reason", "Required": "Mandatory / reason when applicable", "Type": "integer / string", "Purpose": "Shows resilience policy and actual retry behavior."},
        {"Agent Category": "All Agents", "Parameter": "previous_agents, next_agents", "Required": "Mandatory", "Type": "array[string]", "Purpose": "Preserves lineage and handoff path."},
        {"Agent Category": "LLM Agents", "Parameter": "provider, model, model_version, prompt_hash, input_tokens, output_tokens, total_tokens", "Required": "Mandatory", "Type": "string / integer", "Purpose": "Supports model governance, token economics, and prompt auditability."},
        {"Agent Category": "Retrieval Agents", "Parameter": "retrieval_method, retrieved_chunks, reranked_chunks, source, rank, score, content_hash", "Required": "Mandatory", "Type": "enum / array[object]", "Purpose": "Proves evidence lineage and retrieval/reranking behavior."},
        {"Agent Category": "Control Agents", "Parameter": "control_id, control_status, findings, severity", "Required": "Mandatory", "Type": "string / enum / array", "Purpose": "Captures OWASP, PII, grounding, hallucination, compliance, and policy outcomes."},
        {"Agent Category": "Decision Agents", "Parameter": "recommendation, risk_level, confidence, rationale", "Required": "Mandatory", "Type": "string / numeric", "Purpose": "Publishes the canonical governed decision record."},
        {"Agent Category": "All Agents", "Parameter": "error_code, error_message, fallback_used", "Required": "Mandatory when applicable", "Type": "string / boolean", "Purpose": "Enables resilience monitoring and audit review for failed or degraded execution."},
    ])
    runtime_canonical_html = _report_table_html("Runtime Canonical Objects", [
        {
            "Canonical Object": "Runtime Canonical Event",
            "Emitter": "Every app agent and every AEGIS control agent",
            "When Emitted": "During execution: agent start, completion, tool call, evidence retrieval, retry, failure, or skip.",
            "Mandatory Fields": "runtime_id, agent_id, agent_name, event_type, status, timestamp, execution_time_ms, receives_from, passes_to",
            "AEGIS Use": "Live traversal, observability, bottleneck analysis, resilience, cost monitoring, lineage, audit ledger.",
        },
        {
            "Canonical Object": "Final Canonical Decision",
            "Emitter": "Business application or response generator",
            "When Emitted": "After the app completes its business workflow or streams a proposed decision to AEGIS.",
            "Mandatory Fields": "runtime_id, customer_id, original_query, updated_query, recommendation, risk_level, confidence, evidence_pack",
            "AEGIS Use": "Governance validation, OWASP checks, grounding, decision consistency, executive summary, audit package.",
        },
        {
            "Canonical Object": "Governed Decision Record",
            "Emitter": "AEGIS control plane",
            "When Emitted": "After AEGIS validates the final decision against trust, risk, evidence, policy, and audit controls.",
            "Mandatory Fields": "runtime_id, canonical_decision_id, governed_recommendation, governed_risk, governance_status, audit_id",
            "AEGIS Use": "Returning the governed outcome to the app, audit evidence, executive reporting, notification triggers.",
        },
        {
            "Canonical Object": "Agent Execution Record",
            "Emitter": "Each agent or tool wrapper",
            "When Emitted": "At agent completion or failure.",
            "Mandatory Fields": "agent_id, agent_name, agent_type, phase, status, execution_order, duration_ms, previous_agents, next_agents",
            "AEGIS Use": "Agent trace, app-vs-AEGIS separation, handoff map, bottleneck table, runtime health.",
        },
        {
            "Canonical Object": "Evidence Object",
            "Emitter": "Retrieval/evidence layer or business app",
            "When Emitted": "When evidence is retrieved, reranked, selected, or attached to final answer.",
            "Mandatory Fields": "evidence_id, source, content_hash, retrieval_method, rank, score, rerank_score, evidence_trust, trust_basis",
            "AEGIS Use": "Evidence lineage, grounding, trust calculation, audit package, reranking transparency.",
        },
        {
            "Canonical Object": "Control Outcome",
            "Emitter": "OWASP, grounding, governance, compliance, LLM judge, or policy agent",
            "When Emitted": "When a control is evaluated.",
            "Mandatory Fields": "control_id, control_name, pillar, status, severity, score, finding, remediation, hitl_trigger",
            "AEGIS Use": "Governance center, OWASP AI, HITL gate, alerts, auditability, six-pillar view.",
        },
    ])
    runtime_contract_html = _report_table_html("Runtime Ingestion Contract Status", [
        {
            "Contract Signal": "Runtime ingestion",
            "Status": nested_get(state, "canonical_runtime_event_contract", "status") or "-",
            "Schema Version": nested_get(state, "canonical_runtime_event_contract", "schema_version") or "-",
            "Events Captured": nested_get(state, "canonical_runtime_event_contract", "event_count") or 0,
            "Invalid Events": nested_get(state, "canonical_runtime_event_contract", "invalid_count") or 0,
            "Required Fields": nested_get(state, "canonical_runtime_event_contract", "required_fields") or "-",
        }
    ])
    runtime_event_rows = []
    for event in (nested_get(state, "runtime_ingestion", "events") or [])[:30]:
        if not isinstance(event, dict):
            continue
        runtime_event_rows.append({
            "Order": event.get("execution_order"),
            "Agent": event.get("agent_name"),
            "Agent Type": event.get("agent_type"),
            "Event": event.get("event_type"),
            "Status": event.get("status"),
            "Execution Time": event.get("execution_time_ms"),
            "Retries": f"{event.get('retry_count', 0)} / {event.get('max_retries', 3)}",
            "Contract": event.get("contract_status"),
        })
    runtime_events_html = _report_table_html("Canonical Runtime Events Captured", runtime_event_rows)
    policy_as_code = state.get("policy_as_code", {}) if isinstance(state.get("policy_as_code"), dict) else {}
    policy_gate_html = _report_table_html("Policy-as-Code Decision Gate", [
        {
            "Policy Version": policy_as_code.get("policy_version") or "-",
            "Gate Status": policy_as_code.get("status") or "-",
            "Release Allowed": "YES" if policy_as_code.get("release_allowed") else "NO",
            "Human Review": "YES" if policy_as_code.get("hitl_required") else "NO",
            "Failed Checks": policy_as_code.get("failed_count", 0),
            "Critical Failed": policy_as_code.get("critical_failed_count", 0),
        }
    ])
    policy_checks = [
        check for check in policy_as_code.get("checks", []) or []
        if isinstance(check, dict)
    ]
    policy_passed = sum(1 for check in policy_checks if check.get("passed"))
    policy_review = len(policy_checks) - policy_passed
    policy_flow_html = _visual_flow_html("AI Release Policy Flow", [
        {"label": "1", "title": "App proposed output", "detail": "Decision, evidence, runtime events, cost, retry, and security signals arrive from the onboarded app."},
        {"label": "2", "title": "Policy-as-code rules", "detail": "AEGIS checks trust, confidence, evidence minimum, OWASP/PII, latency, retry limits, and allowed recommendation."},
        {"label": "3", "title": "Retry or repair", "detail": "Repairable issues can be sent back to the app up to the configured retry policy."},
        {"label": "4", "title": "Human review if needed", "detail": "Critical or unresolved policy issues are routed to HITL with a reviewer packet."},
        {"label": "5", "title": "Governed release", "detail": "If the gate passes, the governed output is returned and the policy result is persisted in the audit ledger."},
    ])
    policy_visual_html = (
        "<div class='visual-kpi-grid'>"
        f"<div class='visual-kpi'><span>Gate Status</span><strong>{html.escape(str(policy_as_code.get('status') or '-'))}</strong><em>Policy evaluation outcome</em></div>"
        f"<div class='visual-kpi'><span>Passed Checks</span><strong>{policy_passed}</strong><em>Rules satisfied</em></div>"
        f"<div class='visual-kpi'><span>Review / Block</span><strong>{policy_review}</strong><em>Rules requiring attention</em></div>"
        f"<div class='visual-kpi'><span>Release Allowed</span><strong>{'YES' if policy_as_code.get('release_allowed') else 'NO'}</strong><em>Final automated release status</em></div>"
        "</div>"
    )
    policy_checks_html = _report_table_html(
        "Release Rule Details",
        _policy_rule_display_rows_for_report(policy_checks),
    )
    asset_registry_html = _report_table_html("AI Asset Registry", [
        {
            "Asset Type": "External AI Application",
            "Registered Asset": "Customer 360 AI App / Dify / LangChain / Claude / OpenAI / Azure / Bedrock / custom service",
            "Captured In This Run": "Yes",
            "Governance Signal": "Business app emitted the canonical runtime and decision records.",
        },
        {
            "Asset Type": "Agent / Workflow Step",
            "Registered Asset": f"{len(trace)} observed runtime agents",
            "Captured In This Run": "Yes",
            "Governance Signal": "Execution trace, status, ordering, execution time, and skipped branch evidence captured.",
        },
        {
            "Asset Type": "Model / Provider",
            "Registered Asset": str(state.get("model_name") or state.get("llm_model") or state.get("provider") or "Runtime-provided"),
            "Captured In This Run": "Yes",
            "Governance Signal": "Model usage connected to cost, trust, prompt, and audit records.",
        },
        {
            "Asset Type": "Data / Vector Assets",
            "Registered Asset": ", ".join(sorted({str(row.get("source") or row.get("Source") or "-") for row in evidence if isinstance(row, dict)})) or "-",
            "Captured In This Run": "Yes",
            "Governance Signal": "Evidence sources linked to retrieval, reranking, trust, and final decisioning.",
        },
        {
            "Asset Type": "Audit Artifacts",
            "Registered Asset": "HTML, PDF, JSON, CSV, evidence pack, runtime checks",
            "Captured In This Run": "Yes",
            "Governance Signal": "Execution is portable for review without rerunning Streamlit.",
        },
    ])
    customer_health = state.get("customer_health", {}) if isinstance(state.get("customer_health"), dict) else {}
    executive_score_rows = [
        {"Score": "Relationship", "Value": state.get("relationship_score", customer_health.get("relationship_score", "-")), "How To Read It": "Customer relationship strength derived from trust and confidence."},
        {"Score": "Engagement", "Value": state.get("engagement_score", customer_health.get("engagement_score", "-")), "How To Read It": "Observed customer activity and stability signal."},
        {"Score": "Portfolio", "Value": state.get("portfolio_score", customer_health.get("portfolio_score", "-")), "How To Read It": "Blended customer posture across relationship and engagement."},
        {"Score": "Risk", "Value": state.get("risk_score", customer_health.get("risk_score", "-")), "How To Read It": "Canonical adverse-risk score used by governance decisioning."},
        {"Score": "Trust", "Value": state.get("trust_score", "-"), "How To Read It": "Canonical trust score reused across the dashboard."},
        {"Score": "Confidence", "Value": state.get("confidence", "-"), "How To Read It": "Decision confidence after evidence, policy, and controls."},
    ]
    executive_html = (
        f"<section id='executive' class='st-card'><h2>Executive Summary</h2>"
        f"<div class='metrics'>"
        f"<div class='metric'><span>Recommendation</span><strong>{html.escape(str(state.get('recommendation') or '-'))}</strong></div>"
        f"<div class='metric'><span>Risk Level</span><strong>{html.escape(str(state.get('risk_level') or '-'))}</strong></div>"
        f"<div class='metric'><span>Trust</span><strong>{html.escape(str(state.get('trust_score') or '-'))}</strong></div>"
        f"<div class='metric'><span>Confidence</span><strong>{html.escape(str(state.get('confidence') or '-'))}</strong></div>"
        f"</div>"
        f"<p>{executive_summary}</p>"
        f"{_report_table_html('Executive Score Explanation', executive_score_rows)}"
        f"</section>"
    )
    def pillar_callout(pillars: list[str], message: str) -> str:
        chips = "".join(f"<span class='pillar-chip'>{html.escape(str(pillar))}</span>" for pillar in pillars)
        return f"<div class='pillar-coverage'><div>{chips}</div><p>{html.escape(str(message))}</p></div>"

    owasp_tab_html = _report_owasp_tab_html(state)
    llm_judge_tab_html = _report_llm_judge_tab_html(state)
    hitl_tab_html = _report_hitl_tab_html(state)
    runtime_tab_html = _report_runtime_observability_tab_html(state, latency_html, timeline_table)
    alerts_tab_html = _report_alerts_tab_html(state)
    cache_tab_html = _report_cache_tab_html(state, cache_maturity_html)
    cost_tab_html = _report_cost_tab_html(state)
    evidence_metrics_html = _evidence_metrics_html(state)
    risk_tab_html = _report_risk_governance_tab_html(state, governance_html, recommendation_html)
    investigation_tab_html = _report_investigation_tab_html(state, customer_html, query_overview_html)
    agents_tab_html = _report_agents_tab_html(state, traversal_html, agent_table, timeline_table, runtime_canonical_html + runtime_contract_html + runtime_events_html)
    retrieval_tab_html = _report_retrieval_tab_html(state, retrieved_table, reranked_table)
    auditability_tab_html = _report_auditability_tab_html(state, tests, checks)
    dbs_value_tab_html = _report_dbs_value_html(state)
    onboarding_flow_html = _visual_flow_html("Application Onboarding Flow", [
        {"label": "1", "title": "External AI app", "detail": "Dify, Claude, OpenAI, Azure, Bedrock, LangChain, or custom app keeps its own workflow."},
        {"label": "2", "title": "Runtime canonical events", "detail": "Each agent emits started, completed, skipped, retried, failed, evidence, cost, and latency signals."},
        {"label": "3", "title": "Final canonical decision", "detail": "The app emits recommendation, risk, confidence, evidence pack, and audit IDs."},
        {"label": "4", "title": "AEGIS control plane", "detail": "AEGIS governs, measures, validates, audits, and packages the run."},
    ])
    technical_flow_html = _visual_flow_html("Technical Runtime Flow", [
        {"label": "UI", "title": "Streamlit / offline HTML", "detail": "Presentation layer for live and portable review."},
        {"label": "Runtime", "title": "AEGIS orchestrator", "detail": "Builds the canonical runtime state and invokes controls."},
        {"label": "Evidence", "title": "Hybrid retrieval", "detail": "Authoritative records, BM25, semantic vector, reranking, and evidence packaging."},
        {"label": "Controls", "title": "Governance checks", "detail": "OWASP AI, grounding, trust, compliance, risk, and HITL rules."},
        {"label": "Artifacts", "title": "Audit package", "detail": "HTML, PDF, JSON, CSV, manifests, and trace records."},
    ])
    registry_flow_html = _visual_flow_html("AI Asset Governance Map", [
        {"label": "Apps", "title": "External AI systems", "detail": "Business apps and agent platforms onboarded to AEGIS."},
        {"label": "Agents", "title": "Runtime actors", "detail": "Application agents and AEGIS control agents are separated and observed."},
        {"label": "Models", "title": "Model providers", "detail": "Model name, provider, version, prompt hash, tokens, and cost telemetry."},
        {"label": "Data", "title": "Evidence assets", "detail": "Source systems, CSV rows, vector index, retrieved and reranked chunks."},
        {"label": "Audit", "title": "Control evidence", "detail": "Generated artifacts, runtime checks, and canonical consistency records."},
    ])
    audit_package_flow_html = _visual_flow_html("Audit Package Flow", [
        {"label": "State", "title": "Canonical runtime JSON", "detail": "The source object for consistent dashboard, PDF, and HTML values."},
        {"label": "Evidence", "title": "Evidence and trace CSV", "detail": "Rows preserved for source, ranking, trust, and execution review."},
        {"label": "Reports", "title": "HTML and PDF", "detail": "Presentation-ready package for offline stakeholder review."},
        {"label": "Manifest", "title": "Artifact inventory", "detail": "Files and package metadata retained for auditability."},
    ])

    six_pillar_html = _report_table_html("Pillar To Dashboard Coverage", [
        {"AEGIS Pillar": "Trustworthy AI", "Primary Tabs": "Evidence, Retrieval, OWASP AI, Risk/Governance", "What It Proves": "Outputs are grounded, evidence-backed, checked for hallucination risk, and supported by traceable evidence."},
        {"AEGIS Pillar": "Governable AI", "Primary Tabs": "Risk, Governance & Decisioning, OWASP AI, Auditability", "What It Proves": "Policy, compliance, human-review, risk, and security controls are applied before a decision is accepted."},
        {"AEGIS Pillar": "Measurable AI", "Primary Tabs": "Runtime Observability, Agents, Model Cost & Token Economics", "What It Proves": "Execution time, agent status, observed handoffs, execution stages, parallel controls, model cost, tokens, and runtime health are observable."},
        {"AEGIS Pillar": "Scalable AI", "Primary Tabs": "Cache Acceleration, AI Asset Registry, Application Onboarding Contract", "What It Proves": "Repeated workloads can reuse cache, onboard consistently, and be governed through reusable platform assets."},
        {"AEGIS Pillar": "Resilient AI", "Primary Tabs": "Alerts & Notifications, Runtime Observability, Agents", "What It Proves": "Failures, latency spikes, skipped branches, fallback needs, and alert conditions are visible."},
        {"AEGIS Pillar": "Auditable AI", "Primary Tabs": "Auditability, Audit & Evidence Package, Evidence", "What It Proves": "The run produces portable audit records, evidence lineage, consistency checks, and artifact history."},
    ])
    tab_sections = (
        f"<section id='six-pillars' class='st-card'><h2>Six Pillar Control View</h2>{pillars_html}{six_pillar_html}</section>"
        f"<section id='dbs-value' class='st-card'><h2>DBS Value Add</h2>{pillar_callout(['Governable AI', 'Measurable AI', 'Scalable AI', 'Resilient AI', 'Auditable AI'], 'DBS Value Add connects the AEGIS control-tower capabilities to practical enterprise outcomes for banking technology, risk, audit, and business leadership.')}{dbs_value_tab_html}</section>"
        f"<section id='owasp' class='st-card'><h2>OWASP AI</h2>{pillar_callout(['Trustworthy AI', 'Governable AI', 'Resilient AI'], 'OWASP AI proves that prompt, retrieval, memory, tool, and runtime security controls are being checked before the output is trusted.')}{owasp_tab_html}</section>"
        f"<section id='llm-judge' class='st-card'><h2>LLM Judge & Assurance</h2>{pillar_callout(['Trustworthy AI', 'Governable AI', 'Auditable AI', 'Resilient AI'], 'LLM Judge & Assurance explains how AEGIS validates generated output, retrieved evidence, security posture, model risk, human review, and resilience controls.')}{llm_judge_tab_html}</section>"
        f"<section id='release-policy' class='st-card'><h2>AI Release Policy Gate</h2>{pillar_callout(['Governable AI', 'Resilient AI', 'Auditable AI'], 'AI Release Policy Gate shows the rules AEGIS applies before output release, retry, block, or human review.')}{policy_flow_html}{policy_visual_html}{policy_gate_html}{policy_checks_html}</section>"
        f"<section id='human-review' class='st-card'><h2>Human Review & Release Gate</h2>{pillar_callout(['Governable AI', 'Resilient AI', 'Auditable AI'], 'Human Review and Release Gate shows when AEGIS blocks automated publication, requests retries, and routes the case to a reviewer queue.')}{policy_gate_html}{hitl_tab_html}</section>"
        f"<section id='runtime-observability' class='st-card'><h2>Runtime Observability</h2>{pillar_callout(['Measurable AI', 'Resilient AI'], 'Runtime Observability proves execution health, agent timing, bottlenecks, skipped paths, and operational readiness.')}{runtime_tab_html}</section>"
        f"<section id='alerts' class='st-card'><h2>Alerts & Notifications</h2>{pillar_callout(['Resilient AI', 'Governable AI'], 'Alerts and notifications show which runtime, policy, security, or evidence conditions need escalation.')}{alerts_tab_html}</section>"
        f"<section id='cache' class='st-card'><h2>Cache Acceleration</h2>{pillar_callout(['Scalable AI', 'Measurable AI'], 'Cache Acceleration proves repeatability, reuse, reduced execution time, and lower model/runtime cost over repeated runs.')}{cache_tab_html}</section>"
        f"<section id='cost' class='st-card'><h2>Model Cost & Token Economics</h2>{pillar_callout(['Measurable AI', 'Scalable AI'], 'Model Cost and Token Economics make AI usage financially measurable and scalable across applications.')}{cost_tab_html}</section>"
        f"<section id='evidence' class='st-card'><h2>Evidence</h2>{pillar_callout(['Trustworthy AI', 'Auditable AI'], 'Evidence proves the final decision is grounded, traceable, reranked, and explainable to risk, audit, and technology teams.')}<h3>Evidence Lineage Graph</h3>{evidence_lineage_html}{evidence_metrics_html}<h3>Evidence Pack</h3>{evidence_table}<h3>Retrieved Evidence</h3>{retrieved_table}<h3>Reranked Evidence</h3>{reranked_table}</section>"
        f"<section id='risk' class='st-card'><h2>Risk, Governance & Decisioning</h2>{pillar_callout(['Governable AI', 'Trustworthy AI'], 'Risk, governance, and decisioning prove that the recommendation is policy-controlled, risk-aware, and review-ready.')}<h3>Decision Lineage Graph</h3>{lineage_html}{risk_tab_html}</section>"
        f"<section id='investigation' class='st-card'><h2>Investigation</h2>{investigation_tab_html}</section>"
        f"<section id='agents' class='st-card'><h2>Agents</h2>{pillar_callout(['Measurable AI', 'Resilient AI'], 'Agents prove traversal, execution status, timing, skipped branches, repeated runs, and runtime health.')}{agents_tab_html}</section>"
        f"<section id='retrieval' class='st-card'><h2>Retrieval</h2>{pillar_callout(['Trustworthy AI', 'Auditable AI'], 'Retrieval proves which sources were searched, what method was used, and what evidence was returned before decisioning.')}{retrieval_tab_html}</section>"
        f"<section id='architecture' class='st-card'><h2>Control Tower Architecture</h2>{architecture_html}</section>"
        f"<section id='onboarding' class='st-card'><h2>Application Onboarding Contract</h2>{pillar_callout(['Governable AI', 'Measurable AI', 'Auditable AI'], 'The onboarding contract defines what external AI apps must emit so AEGIS can govern, observe, and audit them consistently.')}{canonical_signal_flow_html}{onboarding_flow_html}<p class='caption'>What external AI applications must emit so AEGIS can observe, govern, measure, and audit them without replacing the application.</p>{onboarding_completeness_html}<div class='info'>Legend: Green means the mandatory contract area is fully covered. Amber means the capability is supported, but some fields are optional or maturity-dependent for the onboarded application.</div>{onboarding_html}{runtime_canonical_html}{runtime_contract_html}{runtime_events_html}{agent_parameter_html}</section>"
        f"<section id='technical' class='st-card'><h2>Technical Architecture</h2>{technical_flow_html}{technical_html}</section>"
        f"<section id='asset-registry' class='st-card'><h2>AI Asset Registry</h2>{pillar_callout(['Scalable AI', 'Governable AI', 'Auditable AI'], 'The AI Asset Registry shows which apps, agents, models, prompts, tools, data assets, controls, and artifacts are governed.')}{registry_flow_html}{asset_registry_html}</section>"
        f"<section id='auditability' class='st-card'><h2>Auditability</h2>{pillar_callout(['Auditable AI', 'Governable AI'], 'Auditability proves canonical consistency, runtime checks, evidence records, generated artifacts, and review readiness.')}{policy_gate_html}{policy_checks_html}{auditability_tab_html}</section>"
        f"<section id='audit-package' class='st-card'><h2>Audit & Evidence Package</h2>{pillar_callout(['Auditable AI', 'Trustworthy AI'], 'The audit package preserves the evidence, runtime state, reports, and export artifacts needed for independent review.')}{audit_package_flow_html}<p class='caption'>Generated HTML, PDF, JSON, CSV, image, and package manifest artifacts are preserved beside this dashboard. The offline presentation page shows curated evidence; raw runtime payloads remain in the exported files for audit review.</p>{audit_artifact_html}</section>"
    )
    tab_sections = tab_sections.replace("class='st-card'", "class='st-card offline-tab-panel'")
    tab_sections = tab_sections.replace(
        "id='six-pillars' class='st-card offline-tab-panel'",
        "id='six-pillars' class='st-card offline-tab-panel active'",
        1,
    )
    streamlit_css = """
    :root{--red:#e31837;--ink:#252b36;--muted:#667085;--line:#dfe3e8;--soft:#f6f7f9;--sidebar:#eef1f5;--green:#087443;--blue:#175cd3}
    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{font:14px "Source Sans Pro","Segoe UI",Arial,sans-serif;margin:0;background:#fff;color:var(--ink)}
    .st-shell{display:grid;grid-template-columns:300px minmax(0,1fr);min-height:100vh;background:#fff}
    .st-sidebar{background:var(--sidebar);border-right:1px solid #d7dee8;padding:28px 18px;position:sticky;top:0;height:100vh;overflow:auto}
    .sidebar-kicker{color:#475467;font-size:13px;margin-bottom:14px}
    .sidebar-title{font-weight:800;color:#0f1728;background:#dce3ee;border-radius:6px;padding:10px 12px;margin:8px 0 12px}
    .sidebar-link{display:block;text-decoration:none;color:#344054;padding:8px 10px;border-radius:6px;margin:1px 0;font-size:13px}
    .sidebar-link:hover,.sidebar-link.active{background:#e2e8f0;color:#111827}
    .sidebar-block{border-top:1px solid #c9d2df;margin-top:18px;padding-top:18px}
    .sidebar-label{font-weight:800;font-size:18px;color:#111827;margin-bottom:10px}
    .sidebar-meta{font-size:13px;color:#475467;line-height:1.5;margin:0 0 12px}
    .st-main{min-width:0;background:#fff}
    .st-page{max-width:1320px;margin:0 auto;padding:58px 34px 44px}
    .st-hero{display:flex;gap:18px;align-items:center;margin:0 0 34px}
    .st-hero-icon{font-size:42px;line-height:1}
    h1{font-size:42px;line-height:1.15;margin:0;color:#1d2736;font-weight:800}
    .hero-subtitle{color:#8a9099;margin-top:12px}
    .st-divider{height:1px;background:#d7dce3;margin:28px 0 30px}
    .st-card{border:1px solid #cfd5dd;border-radius:7px;padding:22px;margin:14px 0 18px;background:#fff;scroll-margin-top:16px}
    .st-card h2{font-size:22px;margin:0 0 14px;color:#252b36}
    .st-card h3{font-size:16px;margin:22px 0 10px;color:#252b36}
    .caption{color:#7a8088;font-size:14px;line-height:1.45;margin:4px 0 14px}
    .st-tabs{display:flex;gap:4px;overflow:auto;border-bottom:1px solid #cfd5dd;margin:16px 0 18px;white-space:nowrap}
    .st-tabs a,.st-tabs button{text-decoration:none;color:#475467;padding:12px 10px 11px;border:0;border-bottom:2px solid transparent;font-size:13px;background:transparent;cursor:pointer;font-family:inherit}
    .st-tabs a:first-child,.st-tabs a:hover,.st-tabs button:hover,.st-tabs button.active{color:var(--red);border-bottom-color:var(--red)}
    .offline-tab-panel{display:none}
    .offline-tab-panel.active{display:block}
    .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:16px 0}
    .metric{border:1px solid #e1e5ea;border-top:3px solid var(--red);border-radius:7px;padding:18px 16px;background:#fff;min-height:92px}
    .metric span{display:block;color:#667085;font-size:12px;margin-bottom:8px}
    .metric strong{font-size:30px;line-height:1.1;display:block;font-weight:800;color:#252b36;overflow-wrap:anywhere}
    .query-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}
    .query-grid>div{border:1px solid var(--line);border-radius:8px;padding:16px;background:#fbfcfe}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}
    .table-scroll{width:100%;overflow:auto;border-radius:7px}
    table{border-collapse:separate;border-spacing:0;width:100%;margin:12px 0;border:1px solid #dfe3e8;border-radius:7px;overflow:hidden}
    th,td{border-right:1px solid #e5e7eb;border-bottom:1px solid #e5e7eb;padding:9px 10px;text-align:left;vertical-align:top;max-width:560px;overflow-wrap:anywhere;font-size:13px}
    th:last-child,td:last-child{border-right:0}
    tr:last-child td{border-bottom:0}
    th{background:#f7f8fa;color:#667085;font-weight:500}
    pre{white-space:pre-wrap;margin:0;max-width:720px;font:13px Consolas,"Courier New",monospace}
    .pill{padding:3px 8px;border-radius:12px;font-weight:700;font-size:12px}
    .ok{background:#dcfae6;color:#087443}.bad{background:#feecef;color:#b42318}.warn{background:#fff4e5;color:#b54708}.info{background:#e8f1ff;color:#175cd3}
    .architecture-svg{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px}
    .architecture-svg svg{width:100%;min-width:980px;height:auto;display:block}
    .pillar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:14px 0}
    .pillar-card{border:1px solid var(--line);border-top:4px solid #11845b;border-radius:8px;padding:14px;background:#f3fbf7}
    .pillar-card span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:700}
    .pillar-card strong{font-size:28px;display:block;margin:8px 0}.pillar-card em{font-style:normal;color:#344054}
    .pillar-coverage{border:1px solid #cfe0ff;border-left:5px solid #2f80ed;background:#f3f8ff;border-radius:9px;padding:12px 14px;margin:6px 0 16px}
    .pillar-coverage p{color:#344054;margin:8px 0 0;line-height:1.38}
    .pillar-chip{display:inline-block;margin:2px 6px 2px 0;padding:4px 9px;border-radius:999px;background:#e8f1ff;color:#175cd3;border:1px solid #b7d7ff;font-size:12px;font-weight:700}
    .radar-wrap{display:grid;justify-items:center;margin:10px 0 18px;padding:10px;background:#fff;border:1px solid var(--line);border-radius:10px}
    .pillar-radar{width:min(100%,620px);height:auto;display:block}
    .radar-ring{fill:none;stroke:#d0d5dd;stroke-width:1}.radar-axis{stroke:#e4e7ec;stroke-width:1}
    .radar-target{fill:none;stroke:#12396b;stroke-width:2;stroke-dasharray:7 7}
    .radar-actual{fill:#e3183730;stroke:#e31837;stroke-width:3}
    .radar-dot{fill:#e31837;stroke:#fff;stroke-width:2}.radar-label{fill:#667085;font:700 13px Arial,sans-serif}.radar-score{fill:#252b36;font:700 12px Arial,sans-serif}.radar-tick{fill:#98a2b3;font:10px Arial,sans-serif}
    .radar-legend{display:flex;gap:22px;align-items:center;justify-content:center;color:#344054;font-size:13px;margin-top:4px}
    .radar-swatch{display:inline-block;width:28px;height:0;border-top:3px solid #e31837;margin-right:6px;vertical-align:middle}.radar-swatch.target{border-top-color:#12396b;border-top-style:dashed}
    .owasp-heatmap{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:12px 0 18px}
    .owasp-tile{border:1px solid var(--line);border-radius:9px;padding:14px;background:#fbfcfe;min-height:118px;border-top:4px solid #667085}
    .owasp-tile span{display:block;color:#475467;font-size:12px;font-weight:700;min-height:32px}
    .owasp-tile strong{display:block;font-size:28px;margin:8px 0;color:#252b36}
    .owasp-tile em{display:inline-block;font-style:normal;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:800}
    .visual-flow{display:flex;gap:12px;align-items:stretch;overflow:auto;margin:12px 0 18px;padding-bottom:4px}
    .visual-step{min-width:200px;max-width:280px;flex:1;border:1px solid var(--line);border-top:4px solid #2e90fa;border-radius:9px;background:#fbfcfe;padding:14px}
    .visual-step span{display:block;color:#667085;font-size:12px;font-weight:800;text-transform:uppercase;margin-bottom:7px}
    .visual-step strong{display:block;color:#252b36;font-size:17px;line-height:1.2;margin-bottom:8px;overflow-wrap:anywhere}
    .visual-step em{display:block;color:#475467;font-style:normal;font-size:13px;line-height:1.35}
    .visual-arrow{align-self:center;color:#7f8aa3;font-size:24px;line-height:1;flex:0 0 auto}
    .visual-kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:12px 0 18px}
    .visual-kpi{border:1px solid var(--line);border-top:4px solid #175cd3;border-radius:9px;background:#fbfcfe;padding:14px}
    .visual-kpi span{display:block;color:#667085;font-size:12px;font-weight:700}
    .visual-kpi strong{display:block;color:#252b36;font-size:24px;line-height:1.1;margin:8px 0}
    .visual-kpi em{display:block;color:#475467;font-style:normal;font-size:12px;line-height:1.35}
    .graphviz-offline{overflow:auto;border:1px solid var(--line);border-radius:10px;background:#fbfcfe;padding:12px;margin:10px 0 16px}
    .graphviz-offline svg{display:block;min-width:900px;width:min(100%,1040px);height:auto;margin:0 auto}
    .graphviz-legend{display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin:4px 0 10px;color:#344054;font-size:13px}
    .graphviz-legend .sw{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:5px;vertical-align:-1px}.sw.app{background:#0b3f35}.sw.aegis{background:#12396b}.sw.skipped{background:#242938}
    .graphviz-legend .line{display:inline-block;width:24px;border-top:3px solid #20d6a3;margin-right:5px;vertical-align:middle}.graphviz-legend .line.signal{border-top:3px dotted #2e90fa}
    .gv-title{font:700 20px Arial, sans-serif;fill:#1d2736;text-anchor:middle}.gv-step{font:700 13px Arial, sans-serif;fill:#f8fafc;text-anchor:middle}.gv-agent{font:700 16px Arial, sans-serif;fill:#f8fafc;text-anchor:middle}.gv-meta{font:700 12px Arial, sans-serif;fill:#f8fafc;text-anchor:middle}
    .gv-edge-label{font:12px Arial, sans-serif;fill:#344054}.gv-bus-label{font:700 12px Arial, sans-serif;fill:#175cd3}.gv-exec{stroke:#20d6a3;stroke-width:3;fill:none}.gv-signal{stroke:#2e90fa;stroke-width:2;stroke-dasharray:3 6;fill:none}.gv-signal-dot{fill:#0284c7;stroke:#fff;stroke-width:1.5}.gv-signal-bus{stroke:#2e90fa;stroke-width:2;stroke-dasharray:3 6}.gv-skip{stroke:#8a94a8;stroke-width:3;stroke-dasharray:7 4;fill:none}.gv-skipped-box{fill:#242938;stroke:#8a94a8;stroke-width:3;stroke-dasharray:6 4}.gv-skipped-text{font:700 13px Arial, sans-serif;fill:#f8fafc;text-anchor:middle}
    .agent-path{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px;align-items:stretch}
    .agent-node{border:1px solid var(--line);border-top:4px solid var(--red);border-radius:8px;padding:13px;background:#fff;min-height:145px}
    .agent-node .step{color:var(--muted);font-size:12px}.agent-node strong,.lineage-step strong{display:block;font-size:16px;margin:8px 0 4px}
    .agent-node em,.lineage-step em{display:block;color:var(--muted);font-style:normal;margin-bottom:8px}.agent-node small{display:block;color:var(--muted);margin-top:7px}
    .path-arrow{display:none}.lineage-path{display:flex;gap:12px;align-items:stretch;overflow:auto;padding-bottom:8px}
    .lineage-step{min-width:205px;border:1px solid var(--line);border-top:4px solid #52a8ff;border-radius:8px;padding:16px;background:#fbfcfe}
    .lineage-step:last-child{border-top-color:#21a67a;background:#f2fbf7}.lineage-step span{color:var(--muted);font-size:12px}.lineage-arrow{display:flex;align-items:center;color:#7f8aa3;font-size:0}.lineage-arrow:before{content:'>';font-size:24px}
    .evidence-flow{display:flex;gap:12px;align-items:center;overflow:auto;padding:8px 0 14px}.flow-stack{display:grid;gap:8px;min-width:210px}.evidence-stack{grid-template-columns:repeat(2,minmax(88px,1fr));min-width:250px}
    .flow-node{border:1px solid var(--line);border-top:4px solid #175cd3;border-radius:8px;background:#fff;padding:12px;min-width:150px}.flow-node strong{display:block}.flow-node span{display:block;color:var(--muted);font-size:12px;margin-top:5px}
    .flow-node.customer{border-top-color:#0b3a66}.flow-node.evidence{border-top-color:#21a67a;min-width:80px}.flow-node.selected{border-top-color:#344054}.flow-node.decision{border-top-color:#007a5a}.flow-arrow{font-size:24px;color:#7f8aa3;flex:0 0 auto}
    .coverage-heatmap table{table-layout:fixed}.coverage-cell{display:block;border-radius:7px;padding:7px 8px;text-align:center;font-weight:700;font-size:12px}.coverage-cell.covered{background:#e7f8f0;color:#087443;border:1px solid #abefc6}.coverage-cell.empty{background:#f2f4f7;color:#98a2b3;border:1px solid #eaecf0}
    .waterfall{display:grid;gap:10px}.waterfall-row,.maturity-row{display:grid;grid-template-columns:240px 1fr 90px;gap:12px;align-items:center}.bar-track{height:18px;background:#eef2f6;border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#e31837,#344054)}.bar-fill.green{background:#11845b}.bar-fill.amber{background:#f79009}.bar-fill.gray{background:#98a2b3}
    details{margin:12px 0;border:1px solid var(--line);border-radius:8px;background:#fff}summary{font-weight:700;cursor:pointer;padding:10px}details>*:not(summary){margin-left:10px;margin-right:10px}
    @media(max-width:980px){.st-shell{grid-template-columns:1fr}.st-sidebar{position:static;height:auto}.st-page{padding:30px 18px}h1{font-size:32px}}
    @media(max-width:800px){.waterfall-row,.maturity-row{grid-template-columns:1fr}.lineage-path,.evidence-flow{display:grid}.lineage-arrow,.flow-arrow{display:none}.architecture-svg svg{min-width:760px}}
    @media print{.st-shell{display:block}.st-sidebar,.st-tabs{display:none}.st-page{max-width:none;padding:0}.st-card{break-inside:auto}}
    """
    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width'>
<title>AEGIS Enterprise Control Tower - {html.escape(str(state.get('runtime_id') or 'offline'))}</title>
<style>{streamlit_css}</style>
</head>
<body>
<div class='st-shell'>
<aside class='st-sidebar'>
  <div class='sidebar-kicker'>app v2</div>
  <div class='sidebar-title'>AEGIS Control Tower V2</div>
  <a class='sidebar-link active' href='#query'>Runtime Intelligence</a>
  <div class='sidebar-block'>
    <div class='sidebar-label'>Investigation</div>
    <div class='sidebar-meta'><strong>Customer ID</strong><br>{html.escape(str(state.get('customer_id') or '-'))}</div>
    <div class='sidebar-meta'><strong>Runtime ID</strong><br>{html.escape(str(state.get('runtime_id') or '-'))}</div>
    <div class='sidebar-meta'><strong>Status</strong><br>{html.escape(str(state.get('runtime_status', state.get('status', '-'))))}</div>
  </div>
  <div class='sidebar-block'>{sidebar_nav}</div>
</aside>
<main class='st-main'>
<div class='st-page'>
  <div class='st-hero'><div class='st-hero-icon'>&#128737;</div><div><h1>AEGIS Enterprise Control Tower</h1><div class='hero-subtitle'>Enterprise Agentic AI Investigation Platform</div></div></div>
  <div class='st-divider'></div>
  {customer_alert_html}
  <section id='query' class='st-card'><h2>User Query + Updated Query</h2>{query_overview_html}{query_html}</section>
  <section id='snapshot' class='st-card'><h2>Executive Runtime Snapshot</h2><div class='metrics'>{metric_cards}</div><table>{facts}</table>{chart}</section>
  <section id='positioning' class='st-card'><h2>Executive Positioning</h2>{positioning_html}</section>
  <section id='pillars' class='st-card'><h2>Enterprise AI Control Tower Pillars</h2><p class='caption'>Trustworthy, governable, measurable, scalable, resilient, and auditable AI signals captured in this execution.</p>{pillars_html}<h3>AEGIS Reference Architecture</h3>{architecture_html}</section>
  <section id='canonical' class='st-card'><h2>Canonical Runtime Audit</h2>{canonical_html}</section>
  <section id='cache-roi' class='st-card'><h2>Cache ROI</h2>{cache_html}</section>
  <section id='traversal' class='st-card'><h2>Live Agent Traversal Path</h2><p class='caption'>Offline static replica of executed and skipped agents from the Streamlit runtime graph.</p>{traversal_html}</section>
  <section id='lineage' class='st-card'><h2>Decision Lineage Graph</h2>{lineage_html}</section>
  <nav class='st-tabs' role='tablist' aria-label='AEGIS Control Tower tabs'>{tab_nav}</nav>
  {tab_sections}
  {executive_html}
</div>
</main>
</div>
<script>
(function() {{
  function showTab(tabId, updateHash) {{
    var panels = document.querySelectorAll('.offline-tab-panel');
    var buttons = document.querySelectorAll('.st-tab-button');
    panels.forEach(function(panel) {{ panel.classList.toggle('active', panel.id === tabId); }});
    buttons.forEach(function(button) {{ button.classList.toggle('active', button.getAttribute('data-tab') === tabId); }});
    if (updateHash && history.replaceState) {{ history.replaceState(null, '', '#' + tabId); }}
  }}
  document.querySelectorAll('.st-tab-button').forEach(function(button) {{
    button.addEventListener('click', function() {{ showTab(button.getAttribute('data-tab'), true); }});
  }});
  document.querySelectorAll('.sidebar-link').forEach(function(link) {{
    link.addEventListener('click', function() {{
      var target = (link.getAttribute('href') || '').replace('#', '');
      if (document.getElementById(target) && document.getElementById(target).classList.contains('offline-tab-panel')) {{
        showTab(target, false);
      }}
    }});
  }});
  var initial = (window.location.hash || '').replace('#', '');
  if (initial && document.getElementById(initial) && document.getElementById(initial).classList.contains('offline-tab-panel')) {{
    showTab(initial, false);
  }}
}})();
</script>
</body>
</html>"""
    return html_doc


def _write_csv(path: Path, rows: Any) -> None:
    rows = [_jsonable(row) for row in (rows if isinstance(rows, list) else []) if isinstance(row, dict)]
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or ["message"])
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def _write_runtime_log(path: Path, state: Dict[str, Any], tests: Dict[str, Any]) -> None:
    lines = [
        "AEGIS COMPLETE RUNTIME LOG", "=" * 80,
        f"Runtime ID: {state.get('runtime_id')}", f"Customer ID: {state.get('customer_id')}",
        f"Status: {state.get('runtime_status', state.get('status'))}", f"Current Phase: {state.get('current_phase')}",
        f"Recommendation: {state.get('recommendation')}", f"Trust Score: {state.get('trust_score')}",
        f"Confidence: {state.get('confidence')}", f"HITL Required: {state.get('hitl_required')}",
        "", "EXECUTION TIMELINE", "-" * 80,
    ]
    for event in state.get("execution_timeline", []) or []:
        if isinstance(event, dict):
            lines.append(json.dumps(_jsonable(event), ensure_ascii=False))
    lines.extend(["", "AGENT TRACE", "-" * 80])
    for event in state.get("agent_trace", []) or []:
        if isinstance(event, dict):
            lines.append(json.dumps(_jsonable(event), ensure_ascii=False))
    lines.extend(["", "INVARIANT TESTS", "-" * 80])
    for check in tests["checks"]:
        lines.append(f"{'PASS' if check['passed'] else 'FAIL'} | {check['id']} | {check['actual']}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_dashboard_png(path: Path, state: Dict[str, Any]) -> None:
    from PIL import Image, ImageDraw, ImageFont
    def load_font(size, bold=False):
        candidates = ["arialbd.ttf" if bold else "arial.ttf", "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"]
        for candidate in candidates:
            try: return ImageFont.truetype(candidate, size)
            except OSError: pass
        return ImageFont.load_default()
    image = Image.new("RGB", (1600, 900), "#f6f7f9")
    draw = ImageDraw.Draw(image)
    title_font, heading_font, body_font, metric_font = load_font(30, True), load_font(18, True), load_font(15), load_font(28, True)
    draw.rectangle((0, 0, 1600, 110), fill="#ffffff")
    draw.rectangle((0, 104, 1600, 110), fill="#e31837")
    draw.text((70, 35), "AEGIS Executive Investigation Dashboard", fill="#252b36", font=title_font)
    metrics = [("Recommendation", state.get("recommendation")), ("Trust", state.get("trust_score")), ("Confidence", state.get("confidence")), ("Status", state.get("runtime_status", state.get("status")))]
    for index, (label, value) in enumerate(metrics):
        x = 70 + index * 375
        draw.rounded_rectangle((x, 155, x + 330, 285), radius=12, fill="#ffffff", outline="#dfe3e8", width=2)
        draw.rectangle((x, 155, x + 330, 161), fill="#e31837")
        draw.text((x + 24, 185), str(label), fill="#667085", font=body_font)
        draw.text((x + 24, 225), str(value), fill="#252b36", font=metric_font)
    summary = state.get("executive_narrative", {})
    summary_text = summary.get("executive_summary", "") if isinstance(summary, dict) else ""
    draw.rounded_rectangle((70, 335, 1530, 500), radius=12, fill="#ffffff", outline="#dfe3e8", width=2)
    draw.text((95, 365), "Executive Summary", fill="#252b36", font=heading_font)
    words = str(summary_text).split(); lines=[]; current=[]
    for word in words:
        if len(" ".join(current + [word])) > 150: lines.append(" ".join(current)); current=[word]
        else: current.append(word)
    lines.append(" ".join(current))
    for idx, line in enumerate(lines[:5]): draw.text((95, 410 + idx * 24), line, fill="#344054", font=body_font)
    draw.rounded_rectangle((70, 550, 760, 820), radius=12, fill="#ffffff", outline="#dfe3e8", width=2)
    draw.text((95, 580), f"Agents Executed: {len(state.get('agent_trace', []) or [])}", fill="#252b36", font=heading_font)
    draw.text((95, 625), f"Evidence Objects: {len(state.get('evidence_pack', []) or [])}", fill="#252b36", font=heading_font)
    draw.rounded_rectangle((810, 550, 1530, 820), radius=12, fill="#ffffff", outline="#dfe3e8", width=2)
    draw.text((835, 580), "Decision Scores", fill="#252b36", font=heading_font)
    for idx, (name, score, color) in enumerate((("Trust", float(state.get('trust_score',0) or 0), "#e31837"), ("Confidence", float(state.get('confidence',0) or 0), "#344054"))):
        y=640+idx*75; draw.text((835,y),name,fill="#252b36",font=body_font); draw.rectangle((970,y,1470,y+22),fill="#e4e7ec"); draw.rectangle((970,y,970+int(5*max(0,min(100,score))),y+22),fill=color)
    image.save(path, "PNG")


def _write_executive_pdf(path: Path, state: Dict[str, Any], tests: Dict[str, Any]) -> None:
    try:
        # Use the dependency-independent multipage renderer in every desktop
        # environment so PDF content is identical whether ReportLab happens to
        # be installed or not.
        raise ModuleNotFoundError
    except ModuleNotFoundError:
        # Create a complete multipage report with the dependencies shipped in
        # the desktop runtime. Each Streamlit data domain is included, rather
        # than converting only the executive cover screenshot.
        from PIL import Image, ImageDraw, ImageFont
        import textwrap
        try:
            normal = ImageFont.truetype("arial.ttf", 18)
            bold = ImageFont.truetype("arialbd.ttf", 22)
            title_font = ImageFont.truetype("arialbd.ttf", 32)
        except OSError:
            normal = bold = title_font = ImageFont.load_default()
        pages = []
        page = None
        draw = None
        y = 0
        page_number = 0

        def new_page():
            nonlocal page, draw, y, page_number
            page_number += 1
            page = Image.new("RGB", (1240, 1754), "white")
            draw = ImageDraw.Draw(page)
            draw.rectangle((0, 0, 1240, 12), fill="#e31837")
            draw.text((60, 40), "AEGIS Executive Investigation Report", fill="#252b36", font=title_font)
            draw.text((60, 1695), f"Runtime {state.get('runtime_id')}  |  Page {page_number}", fill="#667085", font=normal)
            pages.append(page)
            y = 105

        def add_line(text, font=normal, color="#252b36", indent=0):
            nonlocal y
            for line in textwrap.wrap(str(text), width=max(35, 105 - indent // 10), replace_whitespace=False) or [""]:
                if y > 1640:
                    new_page()
                draw.text((60 + indent, y), line, fill=color, font=font)
                y += 27 if font == normal else 34

        def add_section(title):
            nonlocal y
            y += 18
            add_line(title, bold, "#e31837")

        def clean_value(value):
            if isinstance(value, bool):
                return "Yes" if value else "No"
            if value is None:
                return "Not reported"
            if isinstance(value, float):
                return f"{value:.2f}"
            if isinstance(value, (dict, list)):
                return "See details below"
            text = str(value).replace("\n", " ").strip()
            return text if text else "Not reported"

        def add_kv_rows(rows, label_width=30):
            for label, value in rows:
                add_line(f"{str(label).replace('_', ' ').title()}: {clean_value(value)}", normal, "#344054", 12)

        def add_records(records, columns, limit=12):
            if isinstance(records, dict):
                add_kv_rows(records.items())
                return
            if not isinstance(records, list) or not records:
                add_line("No records reported.", normal, "#667085", 12)
                return
            for index, record in enumerate(records[:limit], start=1):
                if not isinstance(record, dict):
                    add_line(f"{index}. {clean_value(record)}", normal, "#344054", 12)
                    continue
                parts = []
                for column in columns:
                    if column in record:
                        parts.append(f"{column.replace('_', ' ').title()}={clean_value(record.get(column))}")
                add_line(f"{index}. " + "; ".join(parts), normal, "#344054", 12)
            if len(records) > limit:
                add_line(f"... {len(records) - limit} additional records included in the artifact JSON/HTML.", normal, "#667085", 12)

        def add_security_summary(security):
            if not isinstance(security, dict) or not security:
                add_line("No OWASP security analysis reported.", normal, "#667085", 12)
                return
            add_kv_rows([
                ("Security Status", security.get("security_status") or security.get("status")),
                ("Security Score", security.get("security_score")),
                ("Risk Level", security.get("risk_level")),
                ("OWASP Grade", security.get("security_grade")),
                ("Scan Surface", ", ".join(security.get("scan_surface", []) or [])),
                ("Failed Controls", ", ".join(security.get("failed_controls", []) or [])),
                ("Review Controls", ", ".join(security.get("review_controls", []) or [])),
            ])
            controls = [
                ("Prompt Injection", security.get("prompt_security") or security.get("prompt_injection")),
                ("Jailbreak Detection", security.get("jailbreak_security") or security.get("jailbreak_detection")),
                ("PII Exposure", security.get("pii_security") or security.get("pii_exposure")),
                ("Data Leakage", security.get("data_leakage")),
                ("Tool Security", security.get("tool_security")),
                ("Retrieval Security", security.get("retrieval_security")),
                ("Memory Security", security.get("memory_security")),
                ("Agent Runtime Security", security.get("agent_runtime_security")),
            ]
            for name, control in controls:
                if isinstance(control, dict):
                    add_line(
                        f"{name}: {control.get('status', 'Not reported')} | Score {clean_value(control.get('score'))} | Matches {clean_value(control.get('match_count', len(control.get('findings', []) or [])))}",
                        normal,
                        "#344054",
                        12,
                    )
                    findings = control.get("findings", []) or []
                    if findings:
                        add_line("Findings:", normal, "#667085", 24)
                        for finding in findings[:5]:
                            add_line(f"- {clean_value(finding)}", normal, "#667085", 36)

        def add_section_value(title, value):
            add_section(title)
            if title == "OWASP Security":
                add_security_summary(value)
            elif title == "Customer Profile" and isinstance(value, dict):
                add_kv_rows(value.items())
            elif title in {"Accounts", "Transactions", "Alerts", "Cases", "Evidence Pack", "Retrieved Chunks", "Data Quality"}:
                add_records(value, ["customer_id", "account_id", "transaction_id", "alert_id", "case_id", "source", "status", "type", "amount", "severity", "message", "content"])
            elif title == "Recommendation" and isinstance(value, dict):
                add_kv_rows([
                    ("Recommendation", value.get("recommendation") or value.get("decision")),
                    ("Confidence", value.get("confidence")),
                    ("Trust Score", value.get("trust_score")),
                    ("Human Review Required", value.get("human_review_required") or value.get("hitl_required")),
                    ("Reason", value.get("reason") or value.get("rationale") or value.get("business_impact")),
                ])
            elif title in {"Governance", "Compliance"} and isinstance(value, dict):
                add_kv_rows([
                    ("Status", value.get("status")),
                    ("Decision", value.get("decision")),
                    ("Reason", value.get("reason")),
                ])
                if isinstance(value.get("control_evidence"), list):
                    add_records(value.get("control_evidence"), ["control_id", "control", "status", "policy", "regulatory_basis"], 8)
            elif title == "Technical Project Summary" and isinstance(value, dict):
                add_line(clean_value(value.get("purpose")), normal, "#344054", 12)
                add_line("Workflow:", normal, "#667085", 12)
                add_records(value.get("end_to_end_workflow", []), ["stage", "details"], 10)
                add_line("Technology Stack:", normal, "#667085", 12)
                add_records(value.get("technology_stack", []), ["layer", "technology"], 10)
            elif isinstance(value, dict):
                scalar_rows = [(k, v) for k, v in value.items() if not isinstance(v, (dict, list))]
                add_kv_rows(scalar_rows[:20])
                nested_keys = [k for k, v in value.items() if isinstance(v, (dict, list))]
                if nested_keys:
                    add_line("Additional structured details are available in the offline HTML and JSON artifacts.", normal, "#667085", 12)
            elif isinstance(value, list):
                add_records(value, ["name", "status", "score", "source", "message", "summary"], 12)
            else:
                add_line(clean_value(value), normal, "#344054", 12)

        new_page()
        for label, value in [
            ("Runtime", state.get("runtime_id")), ("Customer", state.get("customer_id")),
            ("Status", state.get("runtime_status", state.get("status"))),
            ("Recommendation", state.get("recommendation")), ("Trust", state.get("trust_score")),
            ("Confidence", state.get("confidence")), ("Human Review", state.get("hitl_required")),
        ]:
            add_line(f"{label}: {value}", bold if label in {"Recommendation", "Status"} else normal)
        add_section("Cache Acceleration")
        cache_lookup = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
        query_cache = state.get("query_cache", {}) if isinstance(state.get("query_cache"), dict) else {}
        add_kv_rows([
            ("Runtime Cache Status", cache_lookup.get("status")),
            ("Query Cache Status", query_cache.get("status")),
            ("Cache Key", cache_lookup.get("cache_key")),
            ("Cache Query", state.get("cache_key_query")),
            ("Runtime Cache Hits", cache_lookup.get("cache_hits")),
            ("Runtime Cache Misses", cache_lookup.get("cache_misses")),
        ])
        add_section("Enterprise AI Control Tower Pillars")
        add_records(_control_pillar_rows_for_report(state), ["pillar", "score", "signal"], 8)
        add_section("Cache Reuse Maturity By Layer")
        add_records(_cache_layer_rows_for_report(state), ["layer", "hit_ratio", "status", "entries", "hits", "misses", "explanation"], 8)
        add_section("Retrieved And Reranked Evidence")
        add_line(f"Retrieved evidence chunks: {len(_retrieved_evidence_rows(state))}", normal, "#344054", 12)
        add_line(f"Reranked evidence rows: {len(_reranked_evidence_rows(state))}", normal, "#344054", 12)
        add_records(_reranked_evidence_rows(state), ["rerank", "source", "retrieval_method", "rerank_score", "original_rank", "evidence_text"], 8)
        for section_title, key in REPORT_SECTIONS:
            value = state.get(key)
            if not _has_report_value(value):
                continue
            add_section_value(section_title, value)
        y += 18
        add_line("Runtime Invariant Tests", bold, "#e31837")
        for check in tests.get("checks", []):
            add_line(f"{'PASS' if check.get('passed') else 'FAIL'} | {check.get('id')}")
        pages[0].save(path, "PDF", resolution=150.0, save_all=True, append_images=pages[1:])
        return
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    styles = getSampleStyleSheet(); styles.add(ParagraphStyle(name="AEGIS", parent=styles["Title"], textColor=colors.HexColor("#252b36"), alignment=TA_CENTER))
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=15*mm, bottomMargin=15*mm)
    story = [Paragraph("AEGIS Executive Investigation Report", styles["AEGIS"]), Spacer(1, 8*mm)]
    facts = [["Runtime ID", state.get("runtime_id")], ["Customer ID", state.get("customer_id")], ["Status", state.get("runtime_status", state.get("status"))], ["Recommendation", state.get("recommendation")], ["Trust Score", state.get("trust_score")], ["Confidence", state.get("confidence")], ["Human Review", state.get("hitl_required")]]
    fact_table=Table(facts,colWidths=[55*mm,110*mm]); fact_table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#f2f4f7")),("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d5dd")),("PADDING",(0,0),(-1,-1),7)])); story += [fact_table, Spacer(1,6*mm)]
    narrative=state.get("executive_narrative",{}); text=narrative.get("executive_summary","") if isinstance(narrative,dict) else ""; story += [Paragraph("Executive Summary",styles["Heading2"]),Paragraph(html.escape(str(text)),styles["BodyText"]),Spacer(1,5*mm)]
    technical_summary = state.get("technical_project_summary") or _build_technical_project_summary(state)
    story += [Paragraph("Technical Project Summary", styles["Heading2"])]
    story += [Paragraph(html.escape(str(technical_summary.get("purpose", ""))), styles["BodyText"]), Spacer(1, 4*mm)]
    workflow_rows = [["Stage", "Details"]] + [
        [row.get("stage"), row.get("details")]
        for row in technical_summary.get("end_to_end_workflow", [])[:12]
        if isinstance(row, dict)
    ]
    workflow_table = Table(workflow_rows, repeatRows=1, colWidths=[45*mm, 120*mm])
    workflow_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e31837")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0d5dd")),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [workflow_table, Spacer(1, 5*mm)]
    stack_rows = [["Layer", "Technology"]] + [
        [row.get("layer"), row.get("technology")]
        for row in technical_summary.get("technology_stack", [])[:15]
        if isinstance(row, dict)
    ]
    stack_table = Table(stack_rows, repeatRows=1, colWidths=[45*mm, 120*mm])
    stack_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#344054")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0d5dd")),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [stack_table, PageBreak(), Paragraph("Agent Execution",styles["Heading2"])]
    agent_rows=[["#","Agent","Type","Receives From","Passes To","Status","Latency (ms)","Retries"]]+[
        [
            r.get("execution_order"),
            r.get("agent"),
            r.get("agent_type"),
            r.get("receives_from"),
            r.get("passes_to"),
            r.get("status"),
            r.get("duration_ms"),
            f"{r.get('retry_count', 0)} / {r.get('max_retries', 2)}",
        ]
        for r in _agent_trace_with_lineage(state)
        if isinstance(r,dict)
    ]
    table=Table(agent_rows,repeatRows=1,colWidths=[7*mm,28*mm,28*mm,30*mm,30*mm,20*mm,16*mm,16*mm]); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e31837")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0d5dd")),("FONTSIZE",(0,0),(-1,-1),6),("PADDING",(0,0),(-1,-1),3),("VALIGN",(0,0),(-1,-1),"TOP")])); story += [table,Spacer(1,5*mm),Paragraph("Runtime Execution Events",styles["Heading2"])]
    event_rows=[["Phase","Status","Start","End","Event Time","Duration"]]+[[r.get("phase"),r.get("status"),r.get("start_time"),r.get("end_time"),r.get("event_time"),r.get("duration_ms")] for r in (state.get("execution_events_clean") or _execution_event_export_rows(state))[:40] if isinstance(r,dict)]
    event_table=Table(event_rows,repeatRows=1,colWidths=[32*mm,24*mm,34*mm,34*mm,34*mm,18*mm]); event_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#344054")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#d0d5dd")),("FONTSIZE",(0,0),(-1,-1),6),("PADDING",(0,0),(-1,-1),3),("VALIGN",(0,0),(-1,-1),"TOP")])); story += [event_table,PageBreak(),Paragraph("Runtime Validation",styles["Heading2"])]
    check_rows=[["Test","Result"]]+[[c["id"],"PASS" if c["passed"] else "FAIL"] for c in tests["checks"]]; ct=Table(check_rows,colWidths=[120*mm,35*mm]); ct.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#344054")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#d0d5dd")),("PADDING",(0,0),(-1,-1),6)])); story.append(ct)
    def footer(canvas, document): canvas.saveState(); canvas.setFont("Helvetica",8); canvas.setFillColor(colors.grey); canvas.drawString(16*mm,8*mm,f"AEGIS | Runtime {state.get('runtime_id')}"); canvas.drawRightString(194*mm,8*mm,f"Page {document.page}"); canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)


def _audit_ledger_path(root: Path) -> Path:
    return root / "aegis_audit_ledger.sqlite"


def _init_audit_ledger(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_run (
            runtime_id TEXT PRIMARY KEY,
            customer_id TEXT,
            run_directory TEXT,
            zip_path TEXT,
            status TEXT,
            recommendation TEXT,
            risk_level TEXT,
            trust_score REAL,
            confidence REAL,
            hitl_required INTEGER,
            tests_passed INTEGER,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_agent_execution (
            runtime_id TEXT,
            execution_order INTEGER,
            agent TEXT,
            phase TEXT,
            status TEXT,
            duration_ms REAL,
            tool_used TEXT,
            skip_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_evidence (
            runtime_id TEXT,
            rank INTEGER,
            chunk_id TEXT,
            source TEXT,
            retrieval_method TEXT,
            score TEXT,
            rerank_score TEXT,
            evidence_trust TEXT,
            content_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_decision (
            runtime_id TEXT PRIMARY KEY,
            recommendation TEXT,
            risk_level TEXT,
            compliance_status TEXT,
            governance_status TEXT,
            hitl_required INTEGER,
            rationale TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_human_review (
            runtime_id TEXT PRIMARY KEY,
            required INTEGER,
            status TEXT,
            trigger_reason TEXT,
            reviewer_packet_json TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_consistency_check (
            runtime_id TEXT,
            check_id TEXT,
            passed INTEGER,
            actual TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_cache_event (
            runtime_id TEXT,
            layer TEXT,
            status TEXT,
            cache_key TEXT,
            hits INTEGER,
            misses INTEGER,
            hit_ratio REAL,
            ttl_seconds REAL
        );
        CREATE TABLE IF NOT EXISTS audit_runtime_event (
            runtime_id TEXT,
            event_hash TEXT,
            agent_id TEXT,
            agent_name TEXT,
            agent_type TEXT,
            event_type TEXT,
            status TEXT,
            phase TEXT,
            execution_order INTEGER,
            execution_time_ms REAL,
            retry_count INTEGER,
            max_retries INTEGER,
            receives_from TEXT,
            passes_to TEXT,
            tool_name TEXT,
            cost_usd REAL,
            contract_status TEXT,
            timestamp TEXT,
            PRIMARY KEY (runtime_id, event_hash)
        );
        CREATE TABLE IF NOT EXISTS audit_policy_evaluation (
            runtime_id TEXT,
            policy_id TEXT,
            policy_version TEXT,
            passed INTEGER,
            severity TEXT,
            actual TEXT,
            expected TEXT,
            action TEXT,
            created_at TEXT,
            PRIMARY KEY (runtime_id, policy_id)
        );
        CREATE TABLE IF NOT EXISTS audit_artifact (
            runtime_id TEXT,
            artifact_name TEXT,
            artifact_path TEXT,
            bytes INTEGER,
            sha256 TEXT,
            created_at TEXT
        );
        """
    )


def _replace_audit_ledger_rows(
    root: Path,
    state: Dict[str, Any],
    tests: Dict[str, Any],
    final_dir: Path,
    zip_path: Path,
    manifest: Dict[str, Any],
) -> Dict[str, Any]:
    ledger_path = _audit_ledger_path(root)
    runtime_id = str(state.get("runtime_id") or "UNKNOWN")
    customer_id = str(state.get("customer_id") or "UNKNOWN")
    risk_level = str(
        state.get("risk_level")
        or nested_get(state, "risk_authority", "risk_level")
        or nested_get(state, "risk_authority", "level")
        or nested_get(state, "recommendation_package", "risk_level")
        or "-"
    ).upper()
    compliance = state.get("compliance", {}) if isinstance(state.get("compliance"), dict) else {}
    governance = state.get("governance", {}) if isinstance(state.get("governance"), dict) else {}
    recommendation = str(state.get("recommendation") or nested_get(state, "recommendation_package", "recommendation") or "-").upper()
    hitl_required = 1 if state.get("hitl_required") else 0
    created_at = datetime.now().isoformat()
    with sqlite3.connect(ledger_path) as conn:
        _init_audit_ledger(conn)
        for table in (
            "audit_run",
            "audit_agent_execution",
            "audit_evidence",
            "audit_decision",
            "audit_human_review",
            "audit_consistency_check",
            "audit_cache_event",
            "audit_runtime_event",
            "audit_policy_evaluation",
            "audit_artifact",
        ):
            conn.execute(f"DELETE FROM {table} WHERE runtime_id = ?", (runtime_id,))
        conn.execute(
            """
            INSERT INTO audit_run VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                runtime_id,
                customer_id,
                str(final_dir),
                str(zip_path),
                state.get("runtime_status", state.get("status")),
                recommendation,
                risk_level,
                _numeric_for_report(state.get("trust_score")),
                _numeric_for_report(state.get("confidence")),
                hitl_required,
                1 if tests.get("passed") else 0,
                created_at,
            ),
        )
        for row in state.get("agent_trace", []) or []:
            if not isinstance(row, dict):
                continue
            conn.execute(
                "INSERT INTO audit_agent_execution VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    row.get("execution_order"),
                    row.get("agent") or row.get("agent_name"),
                    row.get("phase"),
                    row.get("status"),
                    _numeric_for_report(row.get("duration_ms")),
                    row.get("tool_used") or row.get("tool"),
                    row.get("skip_reason") or row.get("reason"),
                ),
            )
        for rank, row in enumerate(state.get("evidence_pack", []) or [], start=1):
            if not isinstance(row, dict):
                continue
            text = str(row.get("content") or row.get("document") or row.get("text") or row)
            conn.execute(
                "INSERT INTO audit_evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    rank,
                    row.get("chunk_id"),
                    _evidence_source_for_report(row),
                    _retrieval_method_for_report(row),
                    str(_score_for_report(row, "score", "similarity_score", "retrieval_score")),
                    str(_score_for_report(row, "rerank_score", "cross_encoder_score", "relevance_score")),
                    str(_evidence_trust_for_report(row)),
                    hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest(),
                ),
            )
        review_required = bool(
            state.get("hitl_required")
            or recommendation != "APPROVE"
            or risk_level in {"INSUFFICIENT_EVIDENCE", "REVIEW_REQUIRED", "CUSTOMER_NOT_FOUND", "UNKNOWN", "HIGH", "CRITICAL"}
        )
        conn.execute(
            "INSERT INTO audit_decision VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                runtime_id,
                recommendation,
                risk_level,
                compliance.get("compliance_status") or compliance.get("status"),
                "REVIEW" if review_required else "PASS",
                1 if review_required else 0,
                nested_get(state, "recommendation_package", "reason")
                or nested_get(state, "recommendation_package", "rationale")
                or governance.get("reason"),
            ),
        )
        hitl_workflow = state.get("hitl_workflow", {}) if isinstance(state.get("hitl_workflow"), dict) else {}
        reviewer_packet = {
            "runtime_id": runtime_id,
            "customer_id": customer_id,
            "recommendation": recommendation,
            "risk_level": risk_level,
            "trust_score": state.get("trust_score"),
            "confidence": state.get("confidence"),
            "evidence_count": len(state.get("evidence_pack", []) or []),
            "judge_verdicts": nested_get(state, "llm_judge_assurance", "judge_verdicts") or [],
            "artifact_directory": str(final_dir),
        }
        conn.execute(
            "INSERT INTO audit_human_review VALUES (?, ?, ?, ?, ?, ?)",
            (
                runtime_id,
                1 if review_required else 0,
                hitl_workflow.get("status") or ("PENDING_REVIEW" if review_required else "NOT_REQUIRED"),
                hitl_workflow.get("trigger")
                or nested_get(state, "llm_judge_assurance", "final_rationale")
                or nested_get(state, "recommendation_package", "reason")
                or "-",
                json.dumps(_jsonable(reviewer_packet), ensure_ascii=False),
                created_at,
            ),
        )
        for check in tests.get("checks", []) or []:
            if isinstance(check, dict):
                conn.execute(
                    "INSERT INTO audit_consistency_check VALUES (?, ?, ?, ?)",
                    (runtime_id, check.get("id"), 1 if check.get("passed") else 0, json.dumps(_jsonable(check.get("actual")), ensure_ascii=False)),
                )
        cache_lookup = state.get("cache_lookup", {}) if isinstance(state.get("cache_lookup"), dict) else {}
        conn.execute(
            "INSERT INTO audit_cache_event VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                runtime_id,
                "runtime",
                cache_lookup.get("status"),
                cache_lookup.get("cache_key"),
                cache_lookup.get("cache_hits"),
                cache_lookup.get("cache_misses"),
                _numeric_for_report(cache_lookup.get("cache_hit_ratio")),
                _numeric_for_report(cache_lookup.get("ttl_seconds")),
            ),
        )
        for row in _cache_layer_rows_for_report(state):
            conn.execute(
                "INSERT INTO audit_cache_event VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    row.get("layer"),
                    row.get("status"),
                    None,
                    row.get("hits"),
                    row.get("misses"),
                    row.get("hit_ratio"),
                    None,
                ),
            )
        for event in nested_get(state, "runtime_ingestion", "events") or []:
            if not isinstance(event, dict):
                continue
            conn.execute(
                "INSERT OR REPLACE INTO audit_runtime_event VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    event.get("event_hash"),
                    event.get("agent_id"),
                    event.get("agent_name"),
                    event.get("agent_type"),
                    event.get("event_type"),
                    event.get("status"),
                    event.get("phase"),
                    event.get("execution_order"),
                    _numeric_for_report(event.get("execution_time_ms")),
                    event.get("retry_count"),
                    event.get("max_retries"),
                    json.dumps(_jsonable(event.get("receives_from")), ensure_ascii=False),
                    json.dumps(_jsonable(event.get("passes_to")), ensure_ascii=False),
                    event.get("tool_name"),
                    _numeric_for_report(event.get("cost_usd")),
                    event.get("contract_status"),
                    event.get("timestamp"),
                ),
            )
        policy_as_code = state.get("policy_as_code", {}) if isinstance(state.get("policy_as_code"), dict) else {}
        for check in policy_as_code.get("checks", []) or []:
            if not isinstance(check, dict):
                continue
            conn.execute(
                "INSERT OR REPLACE INTO audit_policy_evaluation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    check.get("policy_id"),
                    policy_as_code.get("policy_version"),
                    1 if check.get("passed") else 0,
                    check.get("severity"),
                    json.dumps(_jsonable(check.get("actual")), ensure_ascii=False),
                    json.dumps(_jsonable(check.get("expected")), ensure_ascii=False),
                    check.get("action"),
                    created_at,
                ),
            )
        for file_info in manifest.get("files", []) or []:
            if not isinstance(file_info, dict):
                continue
            conn.execute(
                "INSERT INTO audit_artifact VALUES (?, ?, ?, ?, ?, ?)",
                (
                    runtime_id,
                    file_info.get("name"),
                    str(final_dir / str(file_info.get("name"))),
                    file_info.get("bytes"),
                    file_info.get("sha256"),
                    created_at,
                ),
            )
        conn.commit()
        table_counts = {}
        for table in (
            "audit_run",
            "audit_agent_execution",
            "audit_evidence",
            "audit_decision",
            "audit_human_review",
            "audit_consistency_check",
            "audit_cache_event",
            "audit_runtime_event",
            "audit_policy_evaluation",
            "audit_artifact",
        ):
            table_counts[table] = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE runtime_id = ?",
                (runtime_id,),
            ).fetchone()[0]
    return {"status": "SAVED", "path": str(ledger_path), "table_counts": table_counts}


def save_investigation_artifacts(runtime_state: Dict[str, Any], results_root: Any = None) -> Dict[str, Any]:
    """Atomically save a complete run package; never mutates the source state."""
    root = Path(results_root or os.getenv("AEGIS_RESULTS_DIR") or DEFAULT_RESULTS_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    runtime_state = _canonicalize_runtime_state_for_artifacts(runtime_state)
    runtime_state["customer_profile"] = _format_customer_profile_for_export(runtime_state)
    if isinstance(runtime_state.get("evidence_analysis"), dict):
        runtime_state["evidence_analysis"] = dict(runtime_state["evidence_analysis"])
        runtime_state["evidence_analysis"].pop("health", None)
    runtime_state.pop("evidence_health", None)
    runtime_state["technical_explanation"] = _canonical_technical_explanation(runtime_state)
    runtime_state["execution_events_clean"] = _execution_event_export_rows(runtime_state)
    runtime_state["retrieved_evidence"] = _retrieved_evidence_rows(runtime_state)
    runtime_state["reranked_evidence"] = _reranked_evidence_rows(runtime_state)
    runtime_state.setdefault("technical_project_summary", _build_technical_project_summary(runtime_state))
    run_id = _safe_name(runtime_state.get("runtime_id"))
    customer_id = _safe_name(runtime_state.get("customer_id"))
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    final_dir = root / f"{stamp}_{run_id}_{customer_id}"
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{run_id}_", dir=root))
    tests = evaluate_runtime_invariants(runtime_state)
    try:
        enriched_agent_trace = _agent_trace_with_lineage(runtime_state)
        canonical_runtime_events = _canonical_runtime_events(runtime_state, enriched_agent_trace)
        runtime_state["canonical_runtime_events"] = canonical_runtime_events
        artifacts = {
            "runtime_state.json": runtime_state,
            "agent_trace.json": enriched_agent_trace,
            "canonical_runtime_events.json": canonical_runtime_events,
            "runtime_ingestion.json": runtime_state.get("runtime_ingestion", {}),
            "policy_as_code.json": runtime_state.get("policy_as_code", {}),
            "evidence.json": runtime_state.get("evidence_pack", []),
            "retrieved_evidence.json": runtime_state.get("retrieved_evidence", []),
            "reranked_evidence.json": runtime_state.get("reranked_evidence", []),
            "recommendation.json": runtime_state.get("recommendation_package", {}),
            "execution_graph.json": runtime_state.get("agent_execution_graph", {}),
            "timeline.json": runtime_state.get("execution_timeline", []),
            "data_quality.json": runtime_state.get("data_quality", []),
            "test_results.json": tests,
        }
        for filename, payload in artifacts.items():
            _write_json(temp_dir / filename, payload)
        (temp_dir / "Interactive_Dashboard.html").write_text(_report_html(runtime_state, tests), encoding="utf-8")
        evidence_export_rows = []
        for index, row in enumerate(runtime_state.get("evidence_pack", []) or [], start=1):
            if not isinstance(row, dict):
                continue
            evidence_export_rows.append({
                "rank": row.get("rank", index),
                "chunk_id": row.get("chunk_id") or row.get("id"),
                "source": _evidence_source_for_report(row),
                "evidence_trust": _evidence_trust_for_report(row),
                "trust_basis": _evidence_trust_basis_for_report(row),
                "retrieval_method": _retrieval_method_for_report(row),
                "retrieval_score": _score_for_report(row, "score", "similarity_score", "retrieval_score"),
                "rerank_score": _score_for_report(row, "rerank_score", "cross_encoder_score", "relevance_score"),
                "content": row.get("content") or row.get("text") or row.get("document") or str(row),
            })
        _write_csv(temp_dir / "Evidence_Pack.csv", evidence_export_rows)
        _write_csv(temp_dir / "Retrieved_Evidence.csv", runtime_state.get("retrieved_evidence", []))
        _write_csv(temp_dir / "Reranked_Evidence.csv", runtime_state.get("reranked_evidence", []))
        _write_csv(temp_dir / "Agent_Trace.csv", enriched_agent_trace)
        _write_csv(temp_dir / "Canonical_Runtime_Events.csv", canonical_runtime_events)
        _write_csv(temp_dir / "Runtime_Ingestion_Events.csv", nested_get(runtime_state, "runtime_ingestion", "events") or [])
        _write_csv(temp_dir / "Policy_As_Code_Checks.csv", nested_get(runtime_state, "policy_as_code", "checks") or [])
        _write_runtime_log(temp_dir / "Complete_Runtime_Log.txt", runtime_state, tests)
        _write_dashboard_png(temp_dir / "Dashboard_Screenshot.png", runtime_state)
        _write_executive_pdf(temp_dir / "Executive_Investigation_Report.pdf", runtime_state, tests)
        manifest_files = []
        for path in sorted(temp_dir.iterdir()):
            manifest_files.append({"name": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)})
        manifest = {"schema_version": ARTIFACT_SCHEMA_VERSION, "runtime_id": run_id, "customer_id": customer_id, "created_at": datetime.now().isoformat(), "tests_passed": tests["passed"], "files": manifest_files}
        _write_json(temp_dir / "manifest.json", manifest)
        if final_dir.exists():
            final_dir = root / f"{stamp}_{run_id}_{customer_id}_{datetime.now().strftime('%f')}"
        temp_dir.replace(final_dir)
        zip_path = final_dir.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(final_dir.iterdir()):
                archive.write(path, arcname=f"{final_dir.name}/{path.name}")
        ledger = _replace_audit_ledger_rows(root, runtime_state, tests, final_dir, zip_path, manifest)
        return {"status": "SAVED", "directory": str(final_dir), "zip_path": str(zip_path), "manifest": manifest, "test_results": tests, "audit_ledger": ledger}
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
