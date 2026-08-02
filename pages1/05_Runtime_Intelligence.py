import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
import html
import re
import sqlite3
import ast
import textwrap
from io import BytesIO
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services1.agent_graph_service import build_agent_execution_graph
from services1.email_notification_service import (
    build_alert_email,
    build_runtime_alerts,
    email_config_status,
    send_alert_email,
)
from services1.llm_judge_assurance_service import get_llm_judge_assurance
from services1.policy_as_code_service import evaluate_policy_as_code
from services1.query_security_service import validate_user_queries
from services1.ragas_service import evaluate_rag_quality
from services1.llm_judge_assurance_service import run_llm_judge_assurance
from services1.final_arbitration_service import run_final_arbitration
from services1.control_tower_operations_service import complete_operational_cycle, operation_rows
from services1.runtime_ingestion_service import events_from_agent_trace
from services1.control_tower_canonical_service import (
    attach_control_tower_measurements,
    canonical_object_audit_rows as service_canonical_object_audit_rows,
    canonical_consistency_audit_rows as service_canonical_consistency_audit_rows,
    canonical_display_payload as service_canonical_display_payload,
    canonical_quality_scores as service_canonical_quality_scores,
    canonical_compliance_status as service_canonical_compliance_status,
    governance_release_assessment as service_governance_release_assessment,
)


# Keep the original renderer so every table on this page can use one Arrow-safe
# conversion path, including direct ``st.dataframe`` calls outside render_table.
_streamlit_dataframe = st.dataframe
_streamlit_info = st.info


def _useful_info(message, *args, **kwargs):
    """Do not render empty-state noise on the audience-facing dashboard."""
    text = str(message or "").strip().casefold()
    empty_markers = (
        "not available", "unavailable", "no data available",
        "no execution events", "no agent execution", "no tools selected",
        "no active investigation", "run an aegis investigation to populate",
    )
    if not text or any(marker in text for marker in empty_markers):
        return None
    return _streamlit_info(message, *args, **kwargs)


st.info = _useful_info


def _numeric_score(value, default=0.0):
    if isinstance(value, dict):
        value = value.get("overall", value.get("score", value.get("value", default)))
    if value in (None, "", "-", "N/A", "n/a"):
        value = default
    if default in (None, "", "-", "N/A", "n/a"):
        default = 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _bounded_score(value, default=0.0):
    """Normalize display percentages to the valid 0..100 range."""
    return max(0.0, min(_numeric_score(value, default), 100.0))


def _safe_dict(value):
    """Return a dict for renderer access; tolerate strings/lists from runtime payloads."""
    return value if isinstance(value, dict) else {}


def _safe_get(value, key, default=None):
    """Dictionary-style get that cannot crash when value is a string/list/None."""
    return value.get(key, default) if isinstance(value, dict) else default


def _narrative_text(value, fallback="-"):
    """Render only useful narrative text; replace empty bullets/placeholders."""
    if isinstance(value, list):
        value = " ".join(str(item).strip() for item in value if str(item).strip())
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value or "").strip()
    empty_markers = {"", "-", "", "*", "[]", "{}", "none", "null", "n/a"}
    if text.casefold() in empty_markers:
        return fallback
    stripped = text.replace("\n", "").replace(" ", "").strip()
    if stripped in {"-", "", "*"}:
        return fallback
    return text


def _score_band(score, bands, default_label="UNKNOWN"):
    """Return a label/reason tuple for a numeric score and ordered upper-bound bands."""
    score_value = _numeric_score(score, 0)
    for upper_bound, label, reason in bands:
        if score_value <= upper_bound:
            return label, reason
    return default_label, "Score is outside the configured range."


def _safe_count(value):
    """Count list/dataframe-like runtime values without triggering pandas truth ambiguity."""
    if value is None:
        return 0
    try:
        return len(value)
    except TypeError:
        return 1 if value else 0


def _customer_number(value):
    text = str(value or "").upper()
    match = re.search(r"\b(?:CUST|CUS)0*(\d+)\b", text)
    return match.group(1) if match else ""


def _record_matches_customer_scope(record, customer_id):
    target = _customer_number(customer_id)
    if not target or record is None:
        return True
    if isinstance(record, dict):
        searchable = " ".join(str(value) for value in record.values())
    else:
        searchable = str(record)
    found_customer_numbers = re.findall(
        r"\b(?:CUST|CUS)0*(\d+)\b",
        searchable.upper(),
    )
    return not found_customer_numbers or target in found_customer_numbers


def _filter_customer_scoped_records(records, customer_id):
    if records is None:
        return records
    if hasattr(records, "to_dict"):
        try:
            filtered = records[
                records.apply(
                    lambda row: _record_matches_customer_scope(row.to_dict(), customer_id),
                    axis=1,
                )
            ]
            return filtered
        except Exception:
            return records
    if isinstance(records, list):
        return [
            record for record in records
            if _record_matches_customer_scope(record, customer_id)
        ]
    return records


def _format_missing_source_value(value):
    """Display source-missing customer fields as an explicit CSV-source message."""
    if value is None:
        return "Not present in source CSV"
    text = str(value).strip()
    if text.casefold() in {"", "unknown", "unkwn", "nan", "none", "null"}:
        return "Not present in source CSV"
    return value


def _customer_profile_display(profile, result=None):
    """Return a UI-only customer profile copy with clearer missing-source wording."""
    if not isinstance(profile, dict):
        return profile
    display = dict(profile)
    result = result if isinstance(result, dict) else {}
    evidence_rows = []
    for key in ("evidence_pack", "retrieved_chunks"):
        value = result.get(key)
        if isinstance(value, list):
            evidence_rows.extend(value)
    for item in evidence_rows:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "")).lower()
        content = item.get("content") or item.get("document") or item.get("text") or ""
        if source != "external source system" or not isinstance(content, str):
            continue
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        if not parsed:
            patterns = {
                "customer_name": r"Customer Name\s*:\s*([^\n\r]+?)(?:\s+Country\s*:|$)",
                "country": r"Country\s*:\s*([^\n\r]+?)(?:\s+Risk Segment\s*:|$)",
                "segment": r"Risk Segment\s*:\s*([^\n\r]+?)(?:\s+PEP Flag\s*:|$)",
            }
            for field, pattern in patterns.items():
                match = re.search(pattern, content, flags=re.IGNORECASE)
                if match:
                    parsed[field] = match.group(1).strip()
        if not isinstance(parsed, dict):
            continue
        for field in ("country", "segment", "relationship_since", "customer_name", "expected_recommendation"):
            current = str(display.get(field, "")).strip().casefold()
            replacement = parsed.get(field)
            if current in {"", "unknown", "not present in source csv"} and replacement not in (None, ""):
                display[field] = replacement
    source_descriptive_fields = {
        "country",
        "segment",
        "relationship_since",
        "balance_basis",
    }
    for field in source_descriptive_fields:
        if field in display:
            display[field] = _format_missing_source_value(display[field])
    return display


def _retrieval_method_label(chunk):
    """Human-readable retrieval method for evidence rows."""
    if not isinstance(chunk, dict):
        return "-"
    method = str(chunk.get("retrieval_method") or "").upper()
    metadata = chunk.get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    provenance = str(metadata.get("provenance") or "").upper()
    contributions = chunk.get("retrieval_contributions")
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


def _retrieval_contribution_label(chunk):
    """Compact description of how BM25/vector contributed to a retrieved row."""
    if not isinstance(chunk, dict):
        return "-"
    contributions = chunk.get("retrieval_contributions")
    if not isinstance(contributions, list) or not contributions:
        return "Direct customer-scoped CSV row" if _retrieval_method_label(chunk) == "Authoritative CSV match" else "-"
    parts = []
    for item in contributions:
        if not isinstance(item, dict):
            continue
        method = item.get("method", "-")
        rank = item.get("rank", "-")
        score = item.get("rrf_score", "-")
        parts.append(f"{method} rank {rank} / RRF {score}")
    return "; ".join(parts)


def _rerank_score_explanation():
    return (
        "Rerank Score is the final prioritization score after retrieval. "
        "For semantic/BM25 hits it is derived from fusion or cross-encoder relevance; "
        "authoritative customer-scoped CSV rows are promoted because they are exact source-of-record matches. "
        "Higher score means the row should be read earlier; it is not the same as Evidence Trust."
    )


def _render_retrieval_score_explanation():
    st.caption(_rerank_score_explanation())
    render_table(
        "How Retrieval Scores Are Generated",
        [
            {
                "Field": "Score",
                "Meaning": "Initial retrieval relevance or match strength.",
                "How Generated": "For HYBRID_RRF rows, this comes from lexical/BM25, semantic/vector, or fused retrieval contribution. For AUTHORITATIVE_CSV rows, the value is set to 1 because the row is an exact customer-scoped source match.",
                "Demo Explanation": "Score explains how strongly the row was retrieved before final ordering.",
            },
            {
                "Field": "Rerank Score",
                "Meaning": "Final read priority after reranking.",
                "How Generated": "AEGIS applies source authority, customer specificity, RRF-style fusion, and reranker/cross-encoder signals when available. Authoritative customer records are promoted to 100.",
                "Demo Explanation": "Higher means this evidence should be reviewed earlier; it is not a probability.",
            },
            {
                "Field": "AUTHORITATIVE_CSV",
                "Meaning": "Exact customer-scoped source-of-record row.",
                "How Generated": "The customer ID directly matched curated source data such as customers, accounts, transactions, or cards.",
                "Demo Explanation": "These rows are promoted because exact customer evidence is more important than generic similarity.",
            },
            {
                "Field": "HYBRID_RRF",
                "Meaning": "Hybrid retrieval using rank fusion.",
                "How Generated": "BM25/keyword and semantic/vector candidate lists are merged using Reciprocal Rank Fusion: each candidate gets contribution from its rank in each list.",
                "Demo Explanation": "RRF blends keyword precision and semantic recall in a deterministic, explainable way.",
            },
        ],
    )


def _customer_not_found(result):
    if not isinstance(result, dict):
        return False
    profile = result.get("customer_profile", {})
    if not isinstance(profile, dict):
        profile = {}
    risk_authority = result.get("risk_authority", {})
    if not isinstance(risk_authority, dict):
        risk_authority = {}
    retrieval_scope = result.get("retrieval_scope", {})
    if not isinstance(retrieval_scope, dict):
        retrieval_scope = {}
    return (
        result.get("customer_found") is False
        or str(profile.get("record_status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or str(profile.get("risk_rating", "")).upper() == "NOT_FOUND"
        or str(risk_authority.get("status", "")).upper() == "CUSTOMER_NOT_FOUND"
        or str(retrieval_scope.get("coverage_status", "")).upper() == "CUSTOMER_NOT_FOUND"
    )


def _is_unknown_value(value):
    if isinstance(value, (pd.DataFrame, pd.Series)):
        return value.empty
    if isinstance(value, (dict, list, tuple, set)):
        return len(value) == 0
    try:
        is_missing = pd.isna(value)
        if isinstance(is_missing, bool) and is_missing:
            return True
    except (TypeError, ValueError):
        pass
    text = str("" if value is None else value).strip().casefold()
    return text in {"", "-", "unknown", "unkwn", "none", "null", "n/a", "nan", "<na>"}


def _observed_llm_identity(result, token=None):
    """Resolve provider/model from token metrics, registry, trace, or agent telemetry."""
    token = token if isinstance(token, dict) else {}
    provider = token.get("provider")
    model = token.get("model") or token.get("model_name")

    def consider(detail):
        nonlocal provider, model
        if not isinstance(detail, dict):
            return
        telemetry = detail.get("telemetry", {}) if isinstance(detail.get("telemetry"), dict) else {}
        candidate_provider = (
            detail.get("provider")
            or detail.get("llm_provider")
            or telemetry.get("provider")
            or telemetry.get("llm_provider")
        )
        candidate_model = (
            detail.get("model")
            or detail.get("model_name")
            or detail.get("llm_model")
            or telemetry.get("model")
            or telemetry.get("model_name")
            or telemetry.get("llm_model")
        )
        if _is_unknown_value(provider) and not _is_unknown_value(candidate_provider):
            provider = candidate_provider
        if _is_unknown_value(model) and not _is_unknown_value(candidate_model):
            model = candidate_model

    registry = result.get("llm_registry", {}) if isinstance(result, dict) else {}
    if isinstance(registry, dict):
        for raw in registry.values():
            for detail in (raw if isinstance(raw, list) else [raw]):
                consider(detail)

    llm_trace = result.get("llm_trace", []) if isinstance(result, dict) else []
    if isinstance(llm_trace, list):
        for detail in llm_trace:
            consider(detail)
    elif isinstance(llm_trace, dict):
        consider(llm_trace)

    agents = result.get("agents", {}) if isinstance(result, dict) else {}
    if isinstance(agents, dict):
        for detail in agents.values():
            consider(detail)

    runtime_llm = result.get("runtime_llm", {}) if isinstance(result, dict) else {}
    consider(runtime_llm)

    if _is_unknown_value(provider):
        provider = "Not reported by active LLM runtime"
    if _is_unknown_value(model):
        model = "Not reported by active LLM runtime"
    return provider, model


def _complete_security_controls(security, fallback_rows):
    checks = security.get("checks", []) if isinstance(security, dict) else []
    if not isinstance(checks, list) or not checks:
        return fallback_rows
    rows = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        findings = check.get("findings", [])
        if isinstance(findings, list):
            formatted = []
            for item in findings[:8]:
                if isinstance(item, dict):
                    source = item.get("source")
                    pattern = item.get("pattern") or item.get("message") or item.get("finding")
                    formatted.append(f"{source}: {pattern}" if source else str(pattern or item))
                else:
                    formatted.append(str(item))
            findings = "; ".join(formatted)
        category = check.get("category", check.get("owasp_control", "Control"))
        findings = _clean_security_finding_text(category, check, findings)
        rows.append({
            "OWASP IDs": ", ".join(check.get("owasp_ids", [])),
            "OWASP Control": category,
            "Status": check.get("status"),
            "Score": check.get("score"),
            "Reason / Findings": findings or check.get("reason") or "No issue detected",
        })
    return rows or fallback_rows


def _clean_security_finding_text(label, control, findings):
    text = str(findings or "")
    if label == "PII Exposure":
        if "retrieved_chunks" in text or "none" in text.casefold():
            return (
                "Customer evidence contains PII-like fields. Review masking, "
                "redaction, minimization, and audit logging before external release."
            )
        if text:
            return (
                "PII review signal detected in customer evidence. Validate that "
                "sensitive values are masked or excluded from released output."
            )
    if label == "Agent Runtime Security":
        observability_notes = control.get("observability_notes") if isinstance(control, dict) else None
        if isinstance(observability_notes, list) and observability_notes:
            return "; ".join(str(note) for note in observability_notes[:4])
        if any(
            phrase in text
            for phrase in (
                "Missing agents:",
                "Low confidence agents:",
                "Missing runtime keys:",
            )
        ):
            return (
                "Core runtime path passed. Optional enrichment stages were not "
                "required as standalone agents for this execution."
            )
    if label == "Memory Security" and any(
        phrase in text
        for phrase in (
            "Working memory empty",
            "Semantic memory empty",
            "No episodic history",
            "Reflection memory",
        )
    ):
        return (
            "Persistent agent memory was not used in this run. The investigation "
            "cache may still be active; this is an observability note, not a security failure."
        )
    return findings


def _security_findings_rows(result):
    security = result.get("security_analysis") or result.get("security") or {}
    if not isinstance(security, dict):
        return []
    rows = []
    for label, key in [
        ("Prompt Injection", "prompt_security"),
        ("Jailbreak Detection", "jailbreak_security"),
        ("PII Exposure", "pii_security"),
        ("Data Leakage", "data_leakage"),
        ("Tool Security", "tool_security"),
        ("Retrieval Security", "retrieval_security"),
        ("Memory Security", "memory_security"),
        ("Agent Runtime Security", "agent_runtime_security"),
    ]:
        control = security.get(key) or security.get({
            "prompt_security": "prompt_injection",
            "jailbreak_security": "jailbreak_detection",
            "pii_security": "pii_exposure",
        }.get(key, key))
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "")).upper()
        if status not in {"FAIL", "REVIEW", "ERROR"} and not control.get("detected"):
            continue
        findings = control.get("findings") or control.get("sensitive_fields") or []
        if isinstance(findings, list):
            finding_text = []
            for item in findings[:6]:
                if isinstance(item, dict):
                    source = item.get("source")
                    pattern = item.get("pattern") or item.get("message") or item.get("finding")
                    finding_text.append(f"{source}: {pattern}" if source else str(pattern or item))
                else:
                    finding_text.append(str(item))
            findings = "; ".join(finding_text)
        findings = _clean_security_finding_text(label, control, findings)
        if (
            label == "Memory Security"
            and status == "REVIEW"
            and "observability note" in str(findings).casefold()
        ):
            continue
        rows.append({
            "OWASP Control": label,
            "Status": status or "-",
            "Score": control.get("score", "-"),
            "Matches": control.get("match_count", len(control.get("findings", []) or [])),
            "Findings": findings or control.get("reason") or "Review required",
        })
    return rows


def _canonical_agent_name(name):
    raw = str(name or "Unknown").strip()
    lowered = raw.casefold().replace("_", " ")
    aliases = {
        "Query Rewriter": "App Query Rewriter",
        "Query Rewriter Agent": "App Query Rewriter",
        "Planner": "App Planner",
        "Planner Agent": "App Planner",
        "Tool Router": "App Tool Router",
        "Tool Router Agent": "App Tool Router",
        "RAG": "App Evidence Retrieval",
        "Retriever Agent": "App Evidence Retrieval",
        "Evidence Retrieval Agent": "App Evidence Retrieval",
        "Evidence": "App Evidence Packager",
        "Evidence Service": "App Evidence Packager",
        "Answer": "App Response Generator",
        "Enterprise Answer Agent": "App Response Generator",
        "Recommendation": "App Canonical Decision Draft",
        "Recommendation Agent": "App Canonical Decision Draft",
        "Runtime Builder": "AEGIS Decision Outcome Packager",
        "Runtime Builder Agent": "AEGIS Decision Outcome Packager",
        "Governance": "AEGIS Governance",
        "Governance Agent": "AEGIS Governance",
        "Compliance": "AEGIS Compliance",
        "Compliance Agent": "AEGIS Compliance",
        "Reflection": "AEGIS Pre-Decision Quality Gate",
        "Reflection Agent": "AEGIS Pre-Decision Quality Gate",
        "RAGAS": "AEGIS RAGAS Evaluation",
        "RAGAS Evaluation Agent": "AEGIS RAGAS Evaluation",
        "Trust": "AEGIS Trust",
        "Trust Agent": "AEGIS Trust",
        "OWASP Security Agent": "AEGIS OWASP Security",
        "Hallucination Agent": "AEGIS Hallucination Check",
        "Grounding Agent": "AEGIS Grounding Check",
        "Cache Intelligence Agent": "AEGIS Cache Intelligence",
        "Risk Agent": "AEGIS Governance",
        "AML Agent": "AEGIS Compliance",
        "Customer Agent": "App Customer Context",
    }
    if raw in aliases:
        return aliases[raw]
    if "query rewriter" in lowered:
        return "App Query Rewriter"
    if "tool router" in lowered or "routing" in lowered:
        return "App Tool Router"
    if "planner" in lowered:
        return "App Planner"
    if "ragas" in lowered:
        return "AEGIS RAGAS Evaluation"
    if lowered == "rag" or "retriever" in lowered or "retrieval" in lowered:
        return "App Evidence Retrieval"
    if "evidence" in lowered and "retrieval" not in lowered:
        return "App Evidence Packager"
    if "answer" in lowered or "response generator" in lowered:
        return "App Response Generator"
    if "recommendation" in lowered:
        return "App Canonical Decision Draft"
    if "runtime builder" in lowered or "runtime packager" in lowered:
        return "AEGIS Decision Outcome Packager"
    if "owasp" in lowered or "security" in lowered:
        return "AEGIS OWASP Security"
    if "governance" in lowered or "risk agent" in lowered:
        return "AEGIS Governance"
    if "compliance" in lowered or "aml agent" in lowered:
        return "AEGIS Compliance"
    if "trust" in lowered:
        return "AEGIS Trust"
    if "reflection" in lowered:
        return "AEGIS Pre-Decision Quality Gate"
    if "hallucination" in lowered:
        return "AEGIS Hallucination Check"
    if "grounding" in lowered:
        return "AEGIS Grounding Check"
    if "cache intelligence" in lowered:
        return "AEGIS Cache Intelligence"
    if "customer agent" in lowered:
        return "App Customer Context"
    return raw


def _normalized_agent_trace(result):
    """Return one canonical row per agent execution for current and saved runs."""
    trace = result.get("agent_trace", []) if isinstance(result, dict) else []
    if not isinstance(trace, list):
        return []

    normalized_by_agent = {}
    for position, raw_row in enumerate(trace, start=1):
        if not isinstance(raw_row, dict):
            continue
        row = dict(raw_row)
        agent = _canonical_agent_name(row.get("agent") or row.get("agent_name") or row.get("name") or "-")
        phase = row.get("phase") or row.get("stage") or "-"
        status = str(row.get("status") or "UNKNOWN").upper()
        order = row.get("execution_order") or row.get("order") or position
        row["agent"] = agent
        row["agent_name"] = agent
        row["phase"] = phase
        row["status"] = status
        row["execution_order"] = order
        row["duration_ms"] = int(_numeric_score(row.get("duration_ms", row.get("latency_ms", 0))))
        row["trust_score"] = _numeric_score(row.get("trust_score", 0))
        row["confidence"] = _numeric_score(row.get("confidence", 0))
        retry_value = row.get("retry_count", row.get("retries", row.get("retry_attempts", row.get("attempts"))))
        max_retry_value = row.get("max_retries", row.get("retry_limit", row.get("configured_retries")))
        row["retry_count"] = int(_numeric_score(retry_value, 0))
        row["max_retries"] = int(_numeric_score(max_retry_value, 2))
        row["retry_signal"] = "Captured" if retry_value not in (None, "", "-") else "Default policy"
        row["execution_count"] = 1
        row["execution_orders"] = [order]
        key = agent.casefold()
        existing = normalized_by_agent.get(key)
        if existing is None:
            normalized_by_agent[key] = row
        else:
            richer, other = (row, existing) if row["duration_ms"] > existing.get("duration_ms", 0) else (existing, row)
            richer["execution_count"] = int(existing.get("execution_count", 1)) + int(row.get("execution_count", 1))
            richer["execution_orders"] = sorted(set((existing.get("execution_orders") or [existing.get("execution_order")]) + (row.get("execution_orders") or [row.get("execution_order")])))
            for field, value in other.items():
                if richer.get(field) in (None, "", "-", 0) and value not in (None, "", "-", 0):
                    richer[field] = value
            richer["execution_order"] = min(existing.get("execution_order", position), row.get("execution_order", position))
            normalized_by_agent[key] = richer
    normalized = sorted(normalized_by_agent.values(), key=lambda row: row.get("execution_order", 9999))
    for index, row in enumerate(normalized, start=1):
        row["execution_order"] = index
    return normalized


def _is_countable_agent_label(value):
    label = str(value or "").strip().casefold().replace("_", " ")
    return label not in {
        "runtime cache",
        "cache hit",
        "cache lookup",
        "artifact export",
    }


def _agent_lineage_key(value):
    return _canonical_agent_name(value).casefold()


def _agent_ownership(agent_name, phase=""):
    """Classify runtime agents by whether they belong to the app flow or AEGIS control plane."""
    text = f"{agent_name} {phase}".casefold()
    if any(token in text for token in (
        "governance", "compliance", "trust", "reflection", "evaluation",
        "ragas", "hallucination", "grounding", "owasp", "security",
        "cache intelligence", "runtime builder", "runtime packager", "audit",
    )):
        return "AEGIS Control Agent"
    if "risk agent" in text or "aml agent" in text:
        return "AEGIS Control Agent"
    return "Application Workflow Agent"


def _agent_lineage_maps(result, trace_rows=None):
    """Return previous/next agent maps from observed graph edges, falling back to trace order."""
    trace_rows = trace_rows or _normalized_agent_trace(result)
    incoming = {}
    outgoing = {}

    def add_edge(source, target):
        source_name = _canonical_agent_name(source)
        target_name = _canonical_agent_name(target)
        if not source_name or not target_name or source_name == "-" or target_name == "-":
            return
        source_key = _agent_lineage_key(source_name)
        target_key = _agent_lineage_key(target_name)
        outgoing.setdefault(source_key, [])
        incoming.setdefault(target_key, [])
        if target_name not in outgoing[source_key]:
            outgoing[source_key].append(target_name)
        if source_name not in incoming[target_key]:
            incoming[target_key].append(source_name)

    graph = result.get("agent_execution_graph") if isinstance(result, dict) else {}
    if not isinstance(graph, dict) or not graph.get("edges"):
        try:
            graph = build_agent_execution_graph(result)
        except Exception:
            graph = {}

    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    node_labels = {}
    for node in (nodes if isinstance(nodes, list) else []):
        if not isinstance(node, dict):
            continue
        label = _canonical_agent_name(node.get("label") or node.get("agent") or node.get("id"))
        node_labels[str(node.get("id") or label)] = label

    for edge in (edges if isinstance(edges, list) else []):
        if not isinstance(edge, dict) or edge.get("kind") != "observed":
            continue
        source = node_labels.get(str(edge.get("source")), edge.get("source"))
        target = node_labels.get(str(edge.get("target")), edge.get("target"))
        add_edge(source, target)

    if not incoming and not outgoing and trace_rows:
        ordered = sorted(trace_rows, key=lambda row: row.get("execution_order", 9999))
        for source, target in zip(ordered, ordered[1:]):
            add_edge(source.get("agent") or source.get("agent_name"), target.get("agent") or target.get("agent_name"))

    return incoming, outgoing


def _agent_trace_with_lineage(result):
    trace = _normalized_agent_trace(result)
    incoming, outgoing = _agent_lineage_maps(result, trace)
    enriched = []
    for row in trace:
        if not isinstance(row, dict):
            continue
        agent = _canonical_agent_name(row.get("agent") or row.get("agent_name") or "-")
        key = _agent_lineage_key(agent)
        enriched_row = dict(row)
        enriched_row["Agent Type"] = _agent_ownership(agent, row.get("phase", ""))
        enriched_row["Receives From"] = ", ".join(incoming.get(key, [])) or "START"
        enriched_row["Passes To"] = ", ".join(outgoing.get(key, [])) or "END"
        enriched.append(enriched_row)
    return enriched


def _agent_trace_display_rows(trace):
    """Agent-tab display rows with one row per canonical agent."""
    merged = {}
    order = []
    for index, row in enumerate(trace or [], start=1):
        if not isinstance(row, dict):
            continue
        agent = _canonical_agent_name(row.get("agent") or row.get("agent_name") or row.get("Agent") or f"Agent {index}")
        key = agent.casefold()
        duration_ms = int(_numeric_score(row.get("duration_ms", row.get("latency_ms", 0)), 0))
        event_time = (
            row.get("timestamp")
            if not _is_unknown_value(row.get("timestamp"))
            else row.get("end_time")
            if not _is_unknown_value(row.get("end_time"))
            else row.get("start_time")
        )
        display_row = {
            "Agent": agent,
            "Agent Type": row.get("Agent Type") or row.get("agent_type") or _agent_ownership(agent, row.get("phase", "")),
            "Status": _agent_display_status({"status": row.get("status"), "observed": True}),
            "Duration": _format_agent_latency(duration_ms) if duration_ms > 0 else "Not timed",
            "Event Time": "-" if _is_unknown_value(event_time) else event_time,
            "Retry": f"{int(_numeric_score(row.get('retry_count'), 0))} / {int(_numeric_score(row.get('max_retries'), 0))}",
            "Receives From": row.get("Receives From") or row.get("previous_agent") or "START",
            "Passes To": row.get("Passes To") or row.get("next_agents") or "END",
        }
        if key not in merged:
            merged[key] = {**display_row, "_duration_ms": duration_ms, "_order": int(_numeric_score(row.get("execution_order"), index))}
            order.append(key)
            continue

        existing = merged[key]
        existing["_duration_ms"] += duration_ms
        existing["Duration"] = _format_agent_latency(existing["_duration_ms"]) if existing["_duration_ms"] > 0 else "Not timed"
        if existing["Event Time"] == "-" and display_row["Event Time"] != "-":
            existing["Event Time"] = display_row["Event Time"]
        if existing["Receives From"] in {"-", "", "START"} and display_row["Receives From"] not in {"-", "", "START"}:
            existing["Receives From"] = display_row["Receives From"]
        if existing["Passes To"] in {"-", "", "END"} and display_row["Passes To"] not in {"-", "", "END"}:
            existing["Passes To"] = display_row["Passes To"]

    rows = [merged[key] for key in order]
    rows.sort(key=lambda item: item.get("_order", 9999))
    for row in rows:
        row.pop("_duration_ms", None)
        row.pop("_order", None)
    return rows


def _agent_runtime_contract_rows(trace):
    rows = []
    for index, row in enumerate(trace or [], start=1):
        if not isinstance(row, dict):
            continue
        agent = row.get("agent") or row.get("agent_name") or row.get("Agent") or row.get("name") or f"Agent {index}"
        status = row.get("status") or row.get("Status") or "-"
        duration_ms = row.get("duration_ms", row.get("latency_ms", row.get("Execution Time (ms)", 0)))
        required_fields = {
            "agent_id": row.get("agent_id") or row.get("id") or _agent_lineage_key(agent),
            "agent_name": agent,
            "agent_type": row.get("Agent Type") or row.get("agent_type") or "-",
            "status": status,
            "execution_time_ms": duration_ms,
            "receives_from": row.get("Receives From") or row.get("previous_agent") or "START",
            "passes_to": row.get("Passes To") or row.get("next_agents") or "END",
        }
        optional_fields = {
            "retry_count": row.get("retry_count", row.get("retries", 0)),
            "max_retries": row.get("max_retries", "-"),
            "evidence_ids": row.get("evidence_ids", row.get("evidence_id", "-")),
            "tokens": row.get("total_tokens", row.get("tokens", "-")),
            "cost_usd": row.get("estimated_cost_usd", row.get("cost_usd", "-")),
            "audit_id": row.get("audit_id", row.get("runtime_id", "-")),
        }
        missing_required = [
            key for key, value in required_fields.items()
            if value in (None, "", "-", [])
        ]
        rows.append({
            "Agent": _canonical_agent_name(agent),
            "Zone": required_fields["agent_type"],
            "Mandatory Runtime Signal": "COMPLETE" if not missing_required else "PARTIAL",
            "Runtime Field Notes": ", ".join(missing_required) if missing_required else "-",
            "Status": status,
            "Execution Time": _format_agent_latency(duration_ms),
            "Receives From": required_fields["receives_from"],
            "Passes To": required_fields["passes_to"],
            "Retry Policy": f"{optional_fields['retry_count']} / {optional_fields['max_retries']}",
            "Cost (USD)": optional_fields["cost_usd"],
            "Evidence IDs": optional_fields["evidence_ids"],
            "Audit ID": optional_fields["audit_id"],
        })
    return rows


def _canonical_agent_counts(result):
    """One UI-wide source of truth for agent totals and execution counts."""

    def _stage_for_agent(label, phase=""):
        text = f"{label} {phase}".casefold()
        if any(token in text for token in ("query", "planner", "router")):
            return "Input & Routing"
        if any(token in text for token in ("rag", "retrieval", "evidence", "answer")):
            return "Evidence & App Runtime"
        if any(token in text for token in ("governance", "compliance", "trust", "owasp", "security", "grounding", "hallucination")):
            return "Parallel Controls & Trust"
        if any(token in text for token in ("reflection", "ragas", "evaluation", "recommendation")):
            return "Quality, Decision & Review"
        if any(token in text for token in ("runtime", "audit", "builder", "cache")):
            return "Audit & Runtime Packaging"
        return str(phase or "Runtime")

    def _stage_summary(rows):
        stage_order = [
            "Input & Routing",
            "Evidence & App Runtime",
            "Parallel Controls & Trust",
            "Quality, Decision & Review",
            "Audit & Runtime Packaging",
        ]
        stages = {}
        for row in rows:
            label = row.get("label") or row.get("agent") or row.get("agent_name") or row.get("id")
            stage = _stage_for_agent(label, row.get("phase"))
            bucket = stages.setdefault(stage, {"stage": stage, "executed": 0, "planned": 0, "agents": []})
            bucket["planned"] += 1
            if row.get("observed", True):
                bucket["executed"] += 1
                bucket["agents"].append(_canonical_agent_name(label))
        ordered = sorted(
            [item for item in stages.values() if item["executed"] > 0],
            key=lambda item: (stage_order.index(item["stage"]) if item["stage"] in stage_order else 999, item["stage"])
        )
        parallel_stages = [item for item in ordered if item["executed"] > 1]
        parallel_checks = sum(item["executed"] for item in parallel_stages)
        return ordered, len(ordered), parallel_checks

    graph = result.get("agent_execution_graph") or {}
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    nodes = [
        {**node, "label": _canonical_agent_name(node.get("label") or node.get("id"))}
        for node in nodes
        if isinstance(node, dict)
        and _is_countable_agent_label(node.get("label") or node.get("id"))
    ]
    if not nodes:
        try:
            graph = build_agent_execution_graph(result)
            nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
            nodes = [
                {**node, "label": _canonical_agent_name(node.get("label") or node.get("id"))}
                for node in nodes
                if isinstance(node, dict)
                and _is_countable_agent_label(node.get("label") or node.get("id"))
            ]
        except Exception:
            nodes = []

    if nodes:
        edges = graph.get("edges", []) if isinstance(graph, dict) else []
        node_id_set = {str(node.get("id")) for node in nodes}
        observed_handoffs = sum(
            1 for edge in edges
            if isinstance(edge, dict)
            and edge.get("kind") == "observed"
            and str(edge.get("source")) in node_id_set
            and str(edge.get("target")) in node_id_set
        )
        total = len(nodes)
        executed = sum(1 for node in nodes if node.get("observed"))
        handoffs = observed_handoffs if observed_handoffs else max(executed - 1, 0)
        not_executed = total - executed
        completed = sum(
            1 for node in nodes
            if node.get("observed")
            and str(node.get("status", "")).upper() in {"COMPLETED", "SUCCESS", "SUCCEEDED"}
        )
        failed = sum(
            1 for node in nodes
            if node.get("observed")
            and str(node.get("status", "")).upper() in {"FAILED", "ERROR", "CRITICAL"}
        )
        running = sum(
            1 for node in nodes
            if node.get("observed")
            and str(node.get("status", "")).upper() in {"RUNNING", "IN_PROGRESS"}
        )
        latency_ms = sum(int(_numeric_score(node.get("duration_ms"), 0)) for node in nodes if node.get("observed"))
        stage_rows, stage_count, parallel_checks = _stage_summary(nodes)
        return {
            "total": total,
            "executed": executed,
            "not_executed": not_executed,
            "completed": completed,
            "failed": failed,
            "running": running,
            "transitions": handoffs,
            "observed_handoffs": handoffs,
            "execution_stages": stage_count,
            "parallel_control_checks": parallel_checks,
            "stage_breakdown": stage_rows,
            "latency_ms": latency_ms,
            "avg_latency_ms": latency_ms / executed if executed else 0,
            "source": "agent_execution_graph",
        }

    trace = [
        row for row in _normalized_agent_trace(result)
        if _is_countable_agent_label(row.get("agent") or row.get("agent_name"))
    ]
    completed = sum(1 for row in trace if str(row.get("status", "")).upper() in {"COMPLETED", "SUCCESS", "SUCCEEDED"})
    failed = sum(1 for row in trace if str(row.get("status", "")).upper() in {"FAILED", "ERROR", "CRITICAL"})
    running = sum(1 for row in trace if str(row.get("status", "")).upper() in {"RUNNING", "IN_PROGRESS"})
    latency_ms = sum(int(_numeric_score(row.get("duration_ms"), 0)) for row in trace)
    stage_rows, stage_count, parallel_checks = _stage_summary([{**row, "label": row.get("agent") or row.get("agent_name"), "observed": True} for row in trace])
    return {
        "total": len(trace),
        "executed": len(trace),
        "not_executed": 0,
        "completed": completed,
        "failed": failed,
        "running": running,
        "transitions": max(len(trace) - 1, 0),
        "observed_handoffs": max(len(trace) - 1, 0),
        "execution_stages": stage_count,
        "parallel_control_checks": parallel_checks,
        "stage_breakdown": stage_rows,
        "latency_ms": latency_ms,
        "avg_latency_ms": latency_ms / len(trace) if trace else 0,
        "source": "agent_trace",
    }


def _normalized_execution_timeline(result):
    timeline = result.get("execution_timeline", []) if isinstance(result, dict) else []
    if not isinstance(timeline, list):
        return []
    merged = {}
    order = []
    for raw in timeline:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        phase = str(row.get("phase") or "Unknown").replace("_", " ").strip().title()
        key = phase.casefold()
        timestamp = row.get("timestamp")
        row["phase"] = phase
        row["start_time"] = row.get("start_time") or timestamp
        row["end_time"] = row.get("end_time") or timestamp
        row["duration_ms"] = int(_numeric_score(row.get("duration_ms", 0)))
        row["trust_score"] = _numeric_score(row.get("trust_score", 0)) or None
        row["confidence"] = _numeric_score(row.get("confidence", 0)) or None
        if key not in merged:
            merged[key] = row
            order.append(key)
        else:
            current = merged[key]
            preferred, other = (row, current) if row["duration_ms"] > current.get("duration_ms", 0) else (current, row)
            for field, value in other.items():
                if preferred.get(field) in (None, "", 0) and value not in (None, "", 0):
                    preferred[field] = value
            merged[key] = preferred
    return [merged[key] for key in order]


def _execution_event_display_rows(events):
    """Display runtime events with clean time columns instead of raw mixed timestamp fields."""
    if isinstance(events, pd.DataFrame):
        records = events.to_dict("records")
    elif isinstance(events, dict):
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
        has_start_or_end = not _is_unknown_value(start) or not _is_unknown_value(end)
        event_time = timestamp if not _is_unknown_value(timestamp) else end if not _is_unknown_value(end) else start
        rows.append({
            "Phase": raw.get("phase") or raw.get("stage") or raw.get("event") or "Unknown",
            "Status": raw.get("status") or raw.get("state") or "-",
            "Start Time": "" if _is_unknown_value(start) else start,
            "End Time": "" if _is_unknown_value(end) else end,
            "Event Time": "" if _is_unknown_value(event_time) else event_time,
            "Duration (ms)": "Not timed" if _is_unknown_value(raw.get("duration_ms")) else raw.get("duration_ms"),
            "Trust": "" if _is_unknown_value(raw.get("trust_score")) else raw.get("trust_score"),
            "Confidence": "" if _is_unknown_value(raw.get("confidence")) else raw.get("confidence"),
        })
    return rows


def _timeline_display_duration(raw):
    duration = raw.get("duration_ms")
    if _is_unknown_value(duration):
        return "Not timed"
    duration_ms = int(_numeric_score(duration, 0))
    if duration_ms <= 0:
        start = raw.get("start_time")
        end = raw.get("end_time")
        if (
            not _is_unknown_value(start)
            and not _is_unknown_value(end)
            and str(start).strip() == str(end).strip()
        ):
            return "Instant"
        return "Not timed"
    if duration_ms >= 1000:
        return f"{duration_ms / 1000:.2f} s"
    return f"{duration_ms} ms"


def _execution_timeline_display_rows(timeline):
    rows = []
    for raw in timeline:
        if not isinstance(raw, dict):
            continue
        event_time = (
            raw.get("timestamp")
            if not _is_unknown_value(raw.get("timestamp"))
            else raw.get("end_time")
            if not _is_unknown_value(raw.get("end_time"))
            else raw.get("start_time")
        )
        rows.append({
            "Phase": raw.get("phase") or "Unknown",
            "Status": raw.get("status") or "-",
            "Start Time": "" if _is_unknown_value(raw.get("start_time")) else raw.get("start_time"),
            "End Time": "" if _is_unknown_value(raw.get("end_time")) else raw.get("end_time"),
            "Duration": _timeline_display_duration(raw),
            "Event Time": "" if _is_unknown_value(event_time) else event_time,
        })
    return rows


def _clean_display_dataframe(df):
    """Remove empty-only columns and show partial missing values consistently."""
    if df is None or df.empty:
        return df

    cleaned = df.copy()
    for column in list(cleaned.columns):
        if cleaned[column].map(_is_unknown_value).all():
            cleaned = cleaned.drop(columns=[column])

    for column in cleaned.columns:
        cleaned[column] = cleaned[column].map(
            lambda value: "-" if _is_unknown_value(value) else value
        )
    return cleaned


def render_top_runtime_alerts(result):
    customer_id = result.get("customer_id", "-") if isinstance(result, dict) else "-"
    if _customer_not_found(result):
        st.error(
            f"Customer '{customer_id}' is not present in the current dataset. "
            "AEGIS blocked risk classification and recommendation automation for this run."
        )
        st.stop()

    security_rows = _security_findings_rows(result)
    critical_rows = [
        row for row in security_rows
        if str(row.get("Status", "")).upper() in {"FAIL", "ERROR"}
        or str(row.get("Status", "")).upper() == "DETECTED"
    ]
    review_rows = [
        row for row in security_rows
        if row not in critical_rows
    ]
    if critical_rows:
        st.error(
            "OWASP AI vulnerability detected. Review the security findings before presenting or using this investigation output."
        )
        render_table("Critical OWASP AI Findings", critical_rows)
    elif review_rows:
        st.warning(
            "OWASP AI runtime review items detected. These are observability or control-review signals, not confirmed vulnerabilities."
        )
        render_table("OWASP AI Review Items", review_rows)


def _canonical_quality_scores(result):
    """Single UI authority for trust, confidence, grounding, coverage, and hallucination."""
    return service_canonical_quality_scores(result)


def _legacy_security_analysis(query_security):
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


def _operational_control_rows(result):
    ops = _safe_dict(result.get("control_tower_operations"))
    decision = _safe_dict(ops.get("decision_response"))
    hitl = _safe_dict(ops.get("hitl_queue_item"))
    return [
        {"Capability": "Response Return File", "Status": "WRITTEN" if decision.get("response_path") else "NOT WRITTEN", "Location / Value": decision.get("response_path", "-"), "Purpose": "Final ACCEPT / REJECT / RETRY / HITL packet for the onboarded app."},
        {"Capability": "HITL Review Queue", "Status": hitl.get("queue_status", "NOT REQUIRED"), "Location / Value": hitl.get("review_id", "-"), "Purpose": "Human review queue when AEGIS routes the run to HITL."},
        {"Capability": "Agent Registry", "Status": "UPDATED", "Location / Value": ops.get("agent_registry_count", 0), "Purpose": "Observed agents maintained for onboarding governance."},
        {"Capability": "Prompt Template Registry", "Status": "UPDATED", "Location / Value": ops.get("prompt_registry_count", 0), "Purpose": "Observed prompt template IDs and hashes tracked for optimization."},
        {"Capability": "Runtime History Store", "Status": "APPENDED", "Location / Value": "runtime_history/runs.jsonl", "Purpose": "Persistent execution history across apps and runs."},
        {"Capability": "Decision Webhook/API Contract", "Status": "AVAILABLE", "Location / Value": ops.get("api_contract_path", "docs1/aegis_decision_api_contract.json"), "Purpose": "Contract for event submission, decision return, and HITL callback."},
        {"Capability": "Alerting", "Status": f"{len(_safe_list(ops.get('alerts')))} emitted", "Location / Value": "alerts/alerts.jsonl", "Purpose": "Open alerts for HITL, OWASP, RAGAS, and policy blockers."},
    ]


def render_operational_control_loop(result):
    st.header("Operational Control Loop")
    st.caption("File-backed integration outputs created by AEGIS for onboarded agentic applications.")
    render_table("Operational Control Outputs", _operational_control_rows(result))
    rows_by_name = operation_rows()
    for title in ["Runtime History", "HITL Queue", "Alerts", "Agent Registry", "Prompt Registry", "Policy Config"]:
        render_table(title, rows_by_name.get(title, []))


def _normalize_runtime_result_for_ui(result):
    """Normalize current and legacy runtime payloads before rendering."""
    if not isinstance(result, dict):
        return {}

    consistency_audit = []

    # Rehydrate live Streamlit projections from the same terminal authorities
    # serialized by the artifact exporter. Never prefer stale phase snapshots.
    canonical_recommendation = str(result.get("recommendation") or "").upper()
    if canonical_recommendation not in {"APPROVE", "MONITOR", "ESCALATE"}:
        canonical_recommendation = str(
            _safe_get(result, "recommendation_package", {}).get("recommendation")
            or _safe_get(result, "decision_snapshot", {}).get("recommendation")
            or canonical_recommendation
            or "UNKNOWN"
        ).upper()
    if canonical_recommendation:
        result["recommendation"] = canonical_recommendation

    executive = _safe_dict(result.get("executive_narrative", {}))
    if not isinstance(executive, dict):
        executive = {}
    canonical_health = result.get("customer_health")
    if isinstance(canonical_health, dict) and canonical_health:
        executive["customer_health"] = canonical_health
    executive["recommendation"] = result.get("recommendation", executive.get("recommendation"))
    executive["trust_score"] = result.get("trust_score", executive.get("trust_score"))
    executive["confidence"] = result.get("confidence", executive.get("confidence"))
    risk_authority = result.get("risk_authority", {})
    if isinstance(risk_authority, dict):
        executive["risk_score"] = risk_authority.get("score", executive.get("risk_score"))
        executive["risk_level"] = risk_authority.get("level", executive.get("risk_level"))
    review_authority = result.get("human_review_authority", {})
    if isinstance(review_authority, dict):
        executive["human_review_required"] = review_authority.get("required")
    result["executive_narrative"] = executive
    canonical_quality = _canonical_quality_scores(result)
    result["trust_score"] = canonical_quality["trust_score"]
    result["confidence"] = canonical_quality["confidence"]
    if canonical_quality["hallucination_risk"] not in {"", "-"}:
        result["hallucination_risk"] = canonical_quality["hallucination_risk"]
    if canonical_quality["groundedness"] is not None:
        result["groundedness_score"] = canonical_quality["groundedness"]
    if canonical_quality["coverage"] is not None:
        result["coverage_score"] = canonical_quality["coverage"]
    executive["trust_score"] = canonical_quality["trust_score"]
    executive["confidence"] = canonical_quality["confidence"]
    for projection_key in ("executive_package", "decision_snapshot", "control_tower_summary", "runtime_telemetry", "telemetry"):
        projection = result.get(projection_key)
        if isinstance(projection, dict):
            projection["trust_score"] = canonical_quality["trust_score"]
            projection["confidence"] = canonical_quality["confidence"]
    enterprise_trust = result.get("enterprise_trust")
    if isinstance(enterprise_trust, dict):
        enterprise_trust["overall"] = canonical_quality["trust_score"]
        enterprise_trust["confidence"] = canonical_quality["confidence"]
        if canonical_quality["groundedness"] is not None:
            enterprise_trust["grounding"] = canonical_quality["groundedness"]
    confidence_scores = result.get("confidence_scores")
    if isinstance(confidence_scores, dict):
        confidence_scores["overall_confidence"] = canonical_quality["confidence"]
        confidence_scores["confidence"] = canonical_quality["confidence"]
    if canonical_recommendation:
        canonical_type = {"APPROVE": "APPROVAL", "MONITOR": "MONITORING", "ESCALATE": "ESCALATION"}.get(canonical_recommendation, "MANUAL_REVIEW")
        canonical_action = {"APPROVE": "Proceed with standard servicing", "MONITOR": "Schedule enhanced monitoring review", "ESCALATE": "Escalate for senior compliance review"}.get(canonical_recommendation, "Manual review required")
        canonical_hitl = canonical_recommendation != "APPROVE"
        canonical_decision_mode = "HUMAN_REVIEW_REQUIRED" if canonical_hitl else "AUTOMATED_APPROVAL"

        def sync_recommendation(value, seen=None):
            seen = seen if seen is not None else set()
            if isinstance(value, (dict, list)):
                identity = id(value)
                if identity in seen:
                    return
                seen.add(identity)
            if isinstance(value, dict):
                for key, child in list(value.items()):
                    normalized = str(key).lower()
                    if normalized in {"recommendation", "final_recommendation"}:
                        value[key] = canonical_recommendation
                    elif normalized == "trust_score":
                        value[key] = result.get("trust_score")
                    elif normalized in {"confidence", "overall_confidence"}:
                        value[key] = result.get("confidence")
                    elif normalized == "recommendation_type":
                        value[key] = canonical_type
                    elif normalized in {"next_best_action", "business_impact"}:
                        value[key] = canonical_action
                    elif normalized in {"human_review_required", "hitl_required"}:
                        value[key] = canonical_hitl
                    elif normalized == "decision_mode":
                        value[key] = canonical_decision_mode
                    elif isinstance(child, (dict, list)):
                        sync_recommendation(child, seen)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, (dict, list)):
                        sync_recommendation(child, seen)

        for projection_key in (
            "executive_package", "executive_narrative", "recommendation_package",
            "decision_snapshot", "control_tower_summary", "runtime_health",
            "runtime_health_v2", "trust", "confidence_scores", "banking_intelligence",
        ):
            sync_recommendation(result.get(projection_key), set())

    compliance_status = _canonical_compliance_status(result)
    expected_governance_status = {
        "APPROVE": "PASS",
        "MONITOR": "REVIEW",
        "ESCALATE": "ESCALATE",
    }.get(canonical_recommendation, "REVIEW_REQUIRED")
    compliance = result.setdefault("compliance", {})
    if isinstance(compliance, dict):
        existing = str(compliance.get("status") or "").upper()
        if existing and existing not in {"", "UNKNOWN", compliance_status}:
            consistency_audit.append({
                "object": "compliance",
                "field": "status",
                "previous": existing,
                "canonical": compliance_status,
            })
        compliance["status"] = compliance_status
        compliance["compliance_status"] = compliance_status
        compliance["decision"] = "PASS" if compliance_status == "COMPLIANT" else expected_governance_status
    governance = result.setdefault("governance", {})
    if isinstance(governance, dict):
        review_required = bool(
            result.get("hitl_required")
            or _safe_get(result, "human_review_authority", {}).get("required")
            or canonical_recommendation != "APPROVE"
        )
        approved = canonical_recommendation == "APPROVE" and not review_required
        governance["status"] = expected_governance_status
        governance["decision"] = canonical_recommendation
        governance["approved"] = approved
        governance["review_required"] = review_required
    for projection_key in ("recommendation_package", "executive_package", "executive_narrative", "decision_snapshot", "governance_authority"):
        projection = result.get(projection_key)
        if isinstance(projection, dict):
            previous = str(projection.get("compliance_status") or "").upper()
            if previous and previous != "UNKNOWN" and previous != compliance_status:
                consistency_audit.append({
                    "object": projection_key,
                    "field": "compliance_status",
                    "previous": previous,
                    "canonical": compliance_status,
                })
            projection["compliance_status"] = compliance_status
            if projection_key in {"recommendation_package", "executive_package", "executive_narrative", "decision_snapshot"}:
                projection["governance_status"] = governance.get("status", expected_governance_status)
    executive_explanation = result.get("executive_explanation")
    if isinstance(executive_explanation, dict):
        executive_explanation["key_factors"] = _clean_recommendation_key_factors(
            result,
            executive_explanation.get("key_factors", []),
        )

    result["agent_trace"] = _normalized_agent_trace(result)

    if not isinstance(result.get("live_runtime"), list) or not result.get("live_runtime"):
        result["live_runtime"] = list(result["agent_trace"])

    telemetry = result.get("runtime_telemetry", {})
    if not isinstance(telemetry, dict):
        telemetry = {}
        result["runtime_telemetry"] = telemetry

    timeline = result.get("execution_timeline")
    if not isinstance(timeline, list):
        timeline = telemetry.get("execution_timeline", [])
    result["execution_timeline"] = timeline if isinstance(timeline, list) else []
    retrieval_contract = result.get("retrieval", {})
    if isinstance(retrieval_contract, dict) and not result.get("retrieved_chunks"):
        nested_chunks = retrieval_contract.get("retrieved_chunks", [])
        if isinstance(nested_chunks, list) and nested_chunks:
            result["retrieved_chunks"] = nested_chunks
    if not result.get("evidence_pack"):
        evidence_contract = result.get("evidence_analysis") or result.get("evidence") or {}
        if isinstance(evidence_contract, dict):
            nested_evidence = evidence_contract.get("evidence_pack", [])
            if isinstance(nested_evidence, list) and nested_evidence:
                result["evidence_pack"] = nested_evidence
    customer_id = result.get("customer_id")
    result["retrieved_chunks"] = _filter_customer_scoped_records(
        result.get("retrieved_chunks", []),
        customer_id,
    )
    result["evidence_pack"] = _filter_customer_scoped_records(
        result.get("evidence_pack", []),
        customer_id,
    )
    for evidence_key in ("evidence_analysis", "evidence"):
        evidence_payload = result.get(evidence_key)
        if isinstance(evidence_payload, dict):
            evidence_payload["evidence_pack"] = _filter_customer_scoped_records(
                evidence_payload.get("evidence_pack", []),
                customer_id,
            )
            evidence_payload["validated_evidence"] = _filter_customer_scoped_records(
                evidence_payload.get("validated_evidence", []),
                customer_id,
            )
            if evidence_payload.get("dataframe") is not None:
                evidence_payload["dataframe"] = _filter_customer_scoped_records(
                    evidence_payload.get("dataframe"),
                    customer_id,
                )
    result["evidence_count"] = len(result.get("evidence_pack", []) or [])
    # Rebuild for legacy snapshots; current runtimes already publish this contract.
    result["agent_execution_graph"] = build_agent_execution_graph(result)

    runtime_health = (
        result.get("runtime_health_v2")
        or result.get("runtime_health")
        or telemetry.get("runtime_health")
        or {}
    )
    if isinstance(runtime_health, dict):
        final_recommendation = result.get("recommendation")
        if final_recommendation:
            runtime_health["recommendation"] = final_recommendation
        result["runtime_health_v2"] = runtime_health
        result["runtime_health"] = runtime_health

    runtime_summary = result.get("runtime_summary", {})
    if not isinstance(runtime_summary, dict):
        runtime_summary = {}
    final_status = (
        runtime_summary.get("status")
        or runtime_health.get("execution_status")
        or result.get("runtime_status")
        or result.get("status")
        or "UNKNOWN"
    )
    if str(final_status).upper() in {"SUCCESS", "SUCCEEDED"}:
        final_status = "COMPLETED"
    result["runtime_status"] = str(final_status).upper()
    runtime_summary["status"] = result["runtime_status"]
    result["runtime_summary"] = runtime_summary
    if consistency_audit:
        result["ui_consistency_audit"] = consistency_audit

    security = result.get("security", {})
    if isinstance(security, dict):
        security.setdefault("prompt_injection", security.get("prompt_security", {}))
        security.setdefault("jailbreak_detection", security.get("jailbreak_security", {}))
        security.setdefault("pii_exposure", security.get("pii_security", {}))
        security.setdefault("security_llm", result.get("security_llm", security.get("llm_security", {})))

    package = result.get("recommendation_package", {})
    if isinstance(package, dict) and package:
        recommendation = str(
            package.get("recommendation") or result.get("recommendation") or "UNKNOWN"
        ).upper()
        package.setdefault("decision", recommendation)
        package.setdefault("recommendation_type", {
            "APPROVE": "APPROVAL",
            "MONITOR": "MONITORING",
            "ESCALATE": "ESCALATION",
        }.get(recommendation, "MANUAL_REVIEW"))
        package.setdefault("business_impact", package.get("next_best_action", "Manual review required"))
        risk_profile = result.get("risk_profile", {})
        if not isinstance(risk_profile, dict):
            risk_profile = {}
        package.setdefault("risk_level", (
            risk_profile.get("risk_level")
            or risk_profile.get("overall_health")
            or risk_profile.get("health")
            or "UNKNOWN"
        ))
        package.setdefault("priority", {
            "APPROVE": "LOW",
            "MONITOR": "MEDIUM",
            "ESCALATE": "HIGH",
        }.get(recommendation, "MEDIUM"))

    token_metrics = _safe_dict(result.get("token_metrics") or telemetry.get("token_metrics"))
    cost_payload = _safe_dict(result.get("cost_monitoring") or result.get("cost_metrics"))
    canonical_cost = _numeric_score(
        token_metrics.get(
            "estimated_cost_usd",
            cost_payload.get("estimated_cost_usd", result.get("estimated_cost_usd", 0)),
        ),
        0,
    )
    canonical_evidence_count = _safe_count(result.get("evidence_pack") or [])
    if canonical_evidence_count <= 0:
        canonical_evidence_count = _safe_count(result.get("retrieved_chunks") or [])
    canonical_risk = (
        result.get("risk_level")
        or _safe_get(result, "risk_authority", {}).get("risk_level")
        or _safe_get(result, "risk_authority", {}).get("level")
        or _safe_get(result, "recommendation_package", {}).get("risk_level")
        or "UNKNOWN"
    )
    result["canonical_display"] = {
        "trust_score": result.get("trust_score"),
        "confidence": result.get("confidence"),
        "risk_level": str(canonical_risk).upper(),
        "recommendation": result.get("recommendation", "UNKNOWN"),
        "evidence_count": canonical_evidence_count,
        "runtime_status": result.get("runtime_status", "UNKNOWN"),
        "estimated_cost_usd": round(canonical_cost, 6),
        "cost_source": "token_metrics.estimated_cost_usd",
    }
    result["risk_level"] = result["canonical_display"]["risk_level"]
    result["evidence_count"] = canonical_evidence_count
    result["estimated_cost_usd"] = result["canonical_display"]["estimated_cost_usd"]
    result.setdefault("canonical_values", {}).update({
        "recommendation": result["canonical_display"]["recommendation"],
        "risk_level": result["canonical_display"]["risk_level"],
        "trust_score": result["canonical_display"]["trust_score"],
        "confidence": result["canonical_display"]["confidence"],
        "evidence_count": result["canonical_display"]["evidence_count"],
        "runtime_status": result["canonical_display"]["runtime_status"],
        "estimated_cost_usd": result["canonical_display"]["estimated_cost_usd"],
        "cost_basis": "Token telemetry / configured rate card. Execution time is not used for cost allocation.",
    })

    canonical_hitl = bool(
        result.get("hitl_required")
        or _safe_get(result, "human_review_authority", {}).get("required")
        or _safe_get(result, "governance", {}).get("review_required")
        or result["canonical_display"]["recommendation"] != "APPROVE"
        or result["canonical_display"]["risk_level"] in {"INSUFFICIENT_EVIDENCE", "REVIEW_REQUIRED", "CUSTOMER_NOT_FOUND", "UNKNOWN"}
    )
    result["hitl_required"] = canonical_hitl
    if isinstance(result.get("human_review_authority"), dict):
        result["human_review_authority"]["required"] = canonical_hitl
    if isinstance(result.get("hitl_workflow"), dict):
        result["hitl_workflow"]["required"] = canonical_hitl
        result["hitl_workflow"].setdefault("status", "PENDING_REVIEW" if canonical_hitl else "NOT_REQUIRED")
    if isinstance(result.get("publication_gate"), dict):
        result["publication_gate"].setdefault("release_allowed", not canonical_hitl)

    runtime_ingestion = events_from_agent_trace(result)
    result["runtime_ingestion"] = runtime_ingestion
    result["canonical_runtime_event_contract"] = {
        "status": runtime_ingestion.get("status"),
        "schema_version": runtime_ingestion.get("schema_version"),
        "event_count": runtime_ingestion.get("event_count"),
        "invalid_count": runtime_ingestion.get("invalid_count"),
        "required_fields": runtime_ingestion.get("required_fields"),
    }
    policy_evaluation = evaluate_policy_as_code(result)
    result["policy_as_code"] = policy_evaluation
    release_assessment = _governance_release_assessment(result)
    result["hitl_required"] = bool(release_assessment["review_required"])
    policy_evaluation["hitl_required"] = result["hitl_required"]
    policy_evaluation["release_allowed"] = bool(release_assessment["release_allowed"])
    if isinstance(result.get("human_review_authority"), dict):
        result["human_review_authority"]["required"] = result["hitl_required"]
    if isinstance(result.get("hitl_workflow"), dict):
        result["hitl_workflow"]["required"] = result["hitl_required"]
        result["hitl_workflow"].setdefault("trigger", policy_evaluation.get("status"))
        result["hitl_workflow"].setdefault(
            "review_packet",
            "policy checks, runtime events, evidence pack, judge verdicts, audit artifacts",
        )
    if isinstance(result.get("publication_gate"), dict):
        result["publication_gate"]["release_allowed"] = bool(policy_evaluation.get("release_allowed") and not result["hitl_required"])

    final_hitl_required = bool(result.get("hitl_required"))
    for projection_key in (
        "runtime_summary", "decision_snapshot", "recommendation_package",
        "executive_package", "executive_narrative", "control_tower_summary",
        "runtime_health", "runtime_health_v2", "runtime_telemetry", "telemetry",
    ):
        projection = result.get(projection_key)
        if not isinstance(projection, dict):
            continue
        projection["recommendation"] = result["canonical_display"]["recommendation"]
        projection["risk_level"] = result["canonical_display"]["risk_level"]
        projection["trust_score"] = result["canonical_display"]["trust_score"]
        projection["confidence"] = result["canonical_display"]["confidence"]
        projection["evidence_count"] = result["canonical_display"]["evidence_count"]
        projection["runtime_status"] = result["canonical_display"]["runtime_status"]
        projection["estimated_cost_usd"] = result["canonical_display"]["estimated_cost_usd"]
        projection["hitl_required"] = final_hitl_required
        projection["human_review_required"] = final_hitl_required

    portable_measurements = attach_control_tower_measurements(result)
    result["canonical_control_tower_measurements"] = portable_measurements.get(
        "canonical_control_tower_measurements",
        {},
    )
    result["canonical_object_audit"] = portable_measurements.get("canonical_object_audit", [])
    result["canonical_consistency_audit"] = portable_measurements.get("canonical_consistency_audit", [])
    result["canonical_values"] = portable_measurements.get("canonical_values", result.get("canonical_values", {}))
    result["customer_health"] = portable_measurements.get("customer_health", result.get("customer_health", {}))
    for field in (
        "trust_score",
        "confidence",
        "risk_level",
        "recommendation",
        "final_recommendation",
        "control_status",
        "error_code",
        "hitl_required",
        "human_review_required",
        "hitl_decision",
        "hitl_decision_source",
        "hitl_reasons",
        "evidence_count",
        "estimated_cost_usd",
    ):
        if field in portable_measurements:
            result[field] = portable_measurements[field]
    result["canonical_runtime_events"] = portable_measurements.get(
        "canonical_runtime_event_contract",
        {},
    ).get("events", runtime_ingestion.get("events", []))

    if not isinstance(result.get("query_security"), dict):
        query_security = validate_user_queries(result)
        result["query_security"] = query_security
    else:
        query_security = result["query_security"]
    if not isinstance(result.get("security_analysis"), dict) or not result.get("security_analysis"):
        result["security_analysis"] = _legacy_security_analysis(query_security)
    else:
        result["security_analysis"].update({
            key: value
            for key, value in _legacy_security_analysis(query_security).items()
            if key not in result["security_analysis"] or result["security_analysis"].get(key) in (None, "", "-", [], {})
        })

    if not isinstance(result.get("ragas_scores"), dict):
        result["ragas_scores"] = evaluate_rag_quality(result)
    result["ragas_success"] = bool(_safe_dict(result.get("ragas_scores")).get("status") == "PASS")

    if not isinstance(result.get("llm_judge_assurance"), dict):
        result["llm_judge_assurance"] = run_llm_judge_assurance(result, use_llm=True)

    security_judge = next(
        (
            row for row in _safe_list(_safe_dict(result.get("llm_judge_assurance")).get("judge_verdicts"))
            if isinstance(row, dict) and row.get("judge_id") == "security_owasp"
        ),
        {},
    )
    result["owasp_ai"] = {
        "status": security_judge.get("verdict") or _safe_dict(result.get("security_analysis")).get("status", "UNKNOWN"),
        "security_score": security_judge.get("score") or _safe_dict(result.get("security_analysis")).get("security_score", 0),
        "risk_level": "LOW" if security_judge.get("verdict") == "PASS" else "HIGH" if security_judge.get("verdict") == "FAIL" else _safe_dict(result.get("security_analysis")).get("risk_level", "REVIEW"),
        "findings": security_judge.get("evidence_refs") or _safe_dict(result.get("security_analysis")).get("findings", []),
        "rationale": security_judge.get("rationale") or _safe_dict(result.get("security_analysis")).get("rationale", "-"),
    }

    result["policy_as_code"] = evaluate_policy_as_code(result)
    result["final_arbitration"] = run_final_arbitration(result)
    if not result.get("_aegis_operations_completed"):
        complete_operational_cycle(result)
        result["_aegis_operations_completed"] = True

    return result

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AEGIS | DBS Control Tower",
    page_icon="AEGIS",
    layout="wide"
)


def _apply_dbs_page_theme():
    """Page-scoped visual system inspired by DBS digital banking surfaces."""
    st.markdown(
        """
        <style>
        :root {
            --aegis-red: #e31837;
            --aegis-red-dark: #b70f2b;
            --aegis-ink: #252b36;
            --aegis-muted: #667085;
            --aegis-line: #dfe3e8;
            --aegis-soft: #f6f7f9;
        }
        [data-testid="stAppViewContainer"] {
            background: #f7f8fa;
            color: var(--aegis-ink);
        }
        [data-testid="stAppViewContainer"],
        [data-testid="stAppViewContainer"] button,
        [data-testid="stAppViewContainer"] input,
        [data-testid="stAppViewContainer"] textarea,
        [data-testid="stAppViewContainer"] table {
            font-family: "Segoe UI", Arial, sans-serif !important;
        }
        .block-container {
            max-width: 1540px;
            padding-top: 1.5rem;
            padding-bottom: 3rem;
        }
        /* Every top-level dashboard section is emitted as a bordered container. */
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: #ffffff;
            border: 1px solid var(--aegis-line) !important;
            border-radius: 10px !important;
            box-shadow: 0 2px 8px rgba(16, 24, 40, 0.045);
            margin-bottom: 1rem;
        }
        [data-testid="stVerticalBlockBorderWrapper"] > div {
            padding: 1.15rem 1.25rem 1.25rem;
        }
        h1, h2, h3, h4 {
            color: var(--aegis-ink) !important;
            font-family: "Segoe UI", Arial, sans-serif !important;
            letter-spacing: -0.015em;
        }
        h1 {
            border-left: 5px solid var(--aegis-red);
            padding-left: .75rem !important;
            font-size: 1.65rem !important;
            font-weight: 700 !important;
        }
        h2 { font-size: 1.25rem !important; font-weight: 650 !important; }
        h3 { font-size: 1.05rem !important; font-weight: 650 !important; }
        [data-testid="stMetric"] {
            background: var(--aegis-soft);
            border: 1px solid #e7e9ee;
            border-top: 3px solid var(--aegis-red);
            border-radius: 7px;
            padding: .75rem .9rem;
        }
        [data-testid="stMetricLabel"] { color: var(--aegis-muted); }
        [data-testid="stMetricValue"] {
            color: var(--aegis-ink);
            font-weight: 650;
            font-size: clamp(1.15rem, 1.55vw, 1.9rem) !important;
            white-space: normal !important;
            overflow-wrap: anywhere !important;
            word-break: break-word !important;
            text-overflow: clip !important;
            max-width: 100% !important;
            line-height: 1.12 !important;
        }
        [data-testid="stMetricValue"] > div {
            white-space: normal !important;
            overflow-wrap: anywhere !important;
            word-break: break-word !important;
            text-overflow: clip !important;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 1.25rem;
            border-bottom: 1px solid var(--aegis-line);
        }
        .stTabs [data-baseweb="tab"] {
            color: #4b5565;
            font-weight: 600;
            padding-left: .1rem;
            padding-right: .1rem;
        }
        .stTabs [aria-selected="true"] { color: var(--aegis-red) !important; }
        .stTabs [data-baseweb="tab-highlight"] { background: var(--aegis-red); }
        [data-testid="stDataFrame"] {
            border: 1px solid var(--aegis-line);
            border-radius: 7px;
            overflow: hidden;
        }
        [data-testid="stExpander"] {
            border-color: var(--aegis-line) !important;
            border-radius: 7px !important;
        }
        hr { border-color: #e8eaee !important; }
        .stButton > button[kind="primary"] {
            background: var(--aegis-red);
            border-color: var(--aegis-red);
        }
        .stButton > button[kind="primary"]:hover {
            background: var(--aegis-red-dark);
            border-color: var(--aegis-red-dark);
        }
        .decision-policy-path {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: .75rem 0 1rem;
        }
        .decision-policy-card {
            background: var(--aegis-soft);
            border: 1px solid #e7e9ee;
            border-top: 3px solid var(--aegis-red);
            border-radius: 7px;
            padding: .85rem .9rem;
            min-height: 8.5rem;
            display: flex;
            flex-direction: column;
            gap: .55rem;
        }
        .decision-policy-card span {
            color: var(--aegis-muted);
            font-size: .85rem;
            line-height: 1.2;
        }
        .decision-policy-card strong {
            color: var(--aegis-ink);
            font-size: clamp(1.2rem, 1.65vw, 1.75rem);
            line-height: 1.08;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
        }
        .decision-policy-card em {
            margin-top: auto;
            border-radius: 7px;
            padding: .55rem .65rem;
            font-style: normal;
            font-weight: 600;
        }
        .decision-policy-card em.pass {
            background: #e7f8f0;
            color: #087443;
        }
        .decision-policy-card em.review {
            background: #fff8db;
            color: #946200;
        }
        .score-explain-card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: .85rem;
            margin: .75rem 0 1.25rem;
        }
        .score-explain-card {
            background: #fff;
            border: 1px solid #e7e9ee;
            border-top: 3px solid var(--aegis-red);
            border-radius: 7px;
            padding: .85rem;
            min-height: 12.5rem;
            display: flex;
            flex-direction: column;
            gap: .55rem;
            box-shadow: 0 2px 8px rgba(16, 24, 40, .04);
        }
        .score-explain-card span {
            color: var(--aegis-muted);
            font-size: .76rem;
            font-weight: 650;
        }
        .score-explain-card strong {
            color: var(--aegis-ink);
            font-size: 1.2rem;
            line-height: 1.05;
            overflow-wrap: anywhere;
        }
        .score-explain-card p {
            color: #344054;
            font-size: .82rem;
            line-height: 1.3;
            margin: 0;
        }
        .score-explain-card em {
            color: #175cd3;
            background: #e8f1ff;
            border-radius: 7px;
            padding: .45rem .55rem;
            font-size: .8rem;
            font-style: normal;
            font-weight: 600;
            margin-top: auto;
        }
        .score-explain-card small {
            color: var(--aegis-muted);
            font-size: .74rem;
            line-height: 1.25;
        }
        .decision-lineage-flow {
            display: flex;
            gap: 1.15rem;
            align-items: stretch;
            overflow-x: auto;
            padding: .75rem .15rem 1rem;
        }
        .decision-lineage-card {
            min-width: 235px;
            flex: 1 0 235px;
            background: #12395f;
            color: #f3f6fb;
            border: 2px solid #2f80ed;
            border-radius: 8px;
            padding: 1.15rem 1.2rem;
            min-height: 10.5rem;
            display: flex;
            flex-direction: column;
            gap: .65rem;
            box-shadow: 0 2px 8px rgba(16, 24, 40, .08);
        }
        .decision-lineage-card.final {
            background: #062f27;
            border-color: #21d4a7;
        }
        .decision-lineage-card span {
            color: #c9d8ea;
            font-size: .82rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .decision-lineage-card strong {
            font-size: clamp(1.35rem, 2vw, 1.85rem);
            line-height: 1.12;
            white-space: normal;
            overflow-wrap: anywhere;
        }
        .decision-lineage-card em {
            color: #dce6f7;
            font-style: normal;
            font-size: 1rem;
            line-height: 1.35;
            margin-top: auto;
            overflow-wrap: anywhere;
        }
        .decision-lineage-arrow {
            flex: 0 0 34px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #7f8aa3;
            font-size: 1.75rem;
            font-weight: 700;
        }
        .agent-card-flow {
            display: flex;
            gap: 1rem;
            align-items: stretch;
            overflow-x: auto;
            padding: .75rem .15rem 1rem;
        }
        .agent-flow-card {
            min-width: 255px;
            flex: 1 0 255px;
            background: #062f27;
            color: #f3f6fb;
            border: 2px solid #21d4a7;
            border-radius: 8px;
            padding: 1rem 1.05rem;
            min-height: 10rem;
            display: flex;
            flex-direction: column;
            gap: .6rem;
            box-shadow: 0 2px 8px rgba(16, 24, 40, .08);
        }
        .agent-flow-card.selected {
            border-color: #f6c343;
            box-shadow: 0 0 0 3px rgba(246, 195, 67, .18);
        }
        .agent-flow-card.skipped {
            background: #242938;
            border-color: #7f8aa3;
        }
        .agent-flow-card.failed {
            background: #471b25;
            border-color: #ff5c7a;
        }
        .agent-flow-card.running {
            background: #102f52;
            border-color: #52a8ff;
        }
        .agent-flow-card span {
            color: #c9d8ea;
            font-size: .78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .04em;
        }
        .agent-flow-card strong {
            color: #f8fafc;
            font-size: clamp(1.1rem, 1.7vw, 1.45rem);
            line-height: 1.15;
            white-space: normal;
            overflow-wrap: anywhere;
        }
        .agent-flow-card em {
            color: #dce6f7;
            font-style: normal;
            font-size: .95rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .agent-flow-card small {
            color: #c9d8ea;
            margin-top: auto;
            font-size: .9rem;
            line-height: 1.25;
        }
        .agent-flow-arrow {
            flex: 0 0 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #7f8aa3;
            font-size: 1.6rem;
            font-weight: 700;
        }
        .agent-vertical-stage {
            background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%);
            border: 1px solid #dfe3e8;
            border-radius: 12px;
            padding: 1.1rem;
            margin: .65rem 0 1rem;
        }
        .agent-vertical-wrap {
            display: grid;
            grid-template-columns: minmax(280px, 1fr) minmax(220px, .58fr);
            gap: 1.25rem;
            align-items: start;
        }
        .agent-main-path {
            position: relative;
            display: grid;
            gap: 1rem;
        }
        .agent-main-path::before {
            content: "";
            position: absolute;
            top: 1.25rem;
            bottom: 1.25rem;
            left: 1.05rem;
            width: 3px;
            background: linear-gradient(180deg, #21d4a7, #2f80ed);
            border-radius: 999px;
        }
        .agent-vertical-node {
            position: relative;
            display: grid;
            grid-template-columns: 2.25rem 1fr;
            gap: .85rem;
            align-items: stretch;
        }
        .agent-lane {
            position: relative;
            display: grid;
            grid-template-columns: 2.25rem 1fr;
            gap: .85rem;
            align-items: start;
        }
        .agent-lane:not(:last-child)::after {
            content: "";
            position: absolute;
            left: .68rem;
            bottom: -1.05rem;
            width: 0;
            height: 0;
            border-left: .42rem solid transparent;
            border-right: .42rem solid transparent;
            border-top: .72rem solid #21d4a7;
            filter: drop-shadow(0 2px 2px rgba(16, 24, 40, .18));
            z-index: 2;
        }
        .agent-lane > div:nth-child(2) {
            position: relative;
        }
        .agent-lane > div:nth-child(2)::before {
            content: "";
            position: absolute;
            left: -.85rem;
            top: 1.55rem;
            width: .85rem;
            border-top: 2px solid #21d4a7;
        }
        .agent-lane-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(255px, 1fr));
            gap: .75rem;
        }
        .agent-lane-label {
            color: #344054;
            font-size: .78rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .04em;
            margin: .2rem 0 .45rem;
        }
        .agent-vertical-dot {
            z-index: 1;
            width: 2.1rem;
            height: 2.1rem;
            border-radius: 999px;
            background: #062f27;
            color: #f8fafc;
            border: 3px solid #21d4a7;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            margin-top: .55rem;
        }
        .agent-vertical-card {
            position: relative;
            background: #062f27;
            color: #f8fafc;
            border: 2px solid #21d4a7;
            border-radius: 10px;
            padding: .95rem 1.05rem;
            min-height: 7rem;
            box-shadow: 0 8px 18px rgba(16, 24, 40, .10);
        }
        .agent-vertical-card.selected {
            border-color: #f6c343;
            box-shadow: 0 0 0 3px rgba(246, 195, 67, .22), 0 8px 18px rgba(16, 24, 40, .10);
        }
        .agent-vertical-card.failed { background: #471b25; border-color: #ff5c7a; }
        .agent-vertical-card.running { background: #102f52; border-color: #52a8ff; }
        .agent-vertical-card.skipped {
            background: #242938;
            border-color: #8a94a8;
            color: #f8fafc;
        }
        .agent-vertical-card.skipped::before {
            content: "";
            position: absolute;
            left: -.78rem;
            top: 1.5rem;
            width: .78rem;
            border-top: 2px dashed #8a94a8;
        }
        .agent-vertical-card.skipped::after {
            content: "";
            position: absolute;
            left: -.18rem;
            top: 1.18rem;
            width: 0;
            height: 0;
            border-top: .32rem solid transparent;
            border-bottom: .32rem solid transparent;
            border-left: .46rem solid #8a94a8;
        }
        .agent-vertical-card.skipped strong {
            color: #f8fafc;
        }
        .agent-vertical-card.skipped em {
            color: #d3dae8;
        }
        .agent-vertical-card span, .side-branch-card span, .feedback-loop-card span {
            display: block;
            color: #c9d8ea;
            font-size: .76rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .04em;
            margin-bottom: .32rem;
        }
        .agent-vertical-card strong {
            display: block;
            font-size: clamp(1.05rem, 1.6vw, 1.45rem);
            line-height: 1.18;
            overflow-wrap: anywhere;
        }
        .agent-vertical-card em {
            display: block;
            color: #dce6f7;
            font-style: normal;
            margin-top: .42rem;
            line-height: 1.32;
        }
        .agent-side-panel {
            display: grid;
            gap: .8rem;
        }
        .agent-side-panel h4 {
            margin: 0 !important;
            font-size: 1rem !important;
        }
        .side-branch-card, .feedback-loop-card {
            background: #242938;
            border: 1px solid #7f8aa3;
            border-left: 4px solid #7f8aa3;
            border-radius: 9px;
            padding: .85rem .95rem;
            color: #f8fafc;
        }
        .feedback-loop-card {
            background: #fff8eb;
            color: #252b36;
            border-color: #f79009;
            border-left-color: #f79009;
        }
        .feedback-loop-card span { color: #946200; }
        .side-branch-card strong, .feedback-loop-card strong {
            display: block;
            font-size: 1rem;
            line-height: 1.18;
            overflow-wrap: anywhere;
        }
        .side-branch-card em, .feedback-loop-card em {
            display: block;
            color: inherit;
            opacity: .82;
            font-style: normal;
            margin-top: .42rem;
            line-height: 1.3;
        }
        .compact-status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: .75rem;
            margin: .55rem 0 .8rem;
        }
        .compact-status-item {
            background: #f8fafc;
            border: 1px solid #e7e9ee;
            border-left: 4px solid var(--aegis-red);
            border-radius: 7px;
            padding: .8rem .9rem;
            min-height: 5.3rem;
        }
        .compact-status-item span {
            display: block;
            color: var(--aegis-muted);
            font-size: .78rem;
            font-weight: 650;
            line-height: 1.2;
            margin-bottom: .35rem;
        }
        .compact-status-item strong {
            display: block;
            color: var(--aegis-ink);
            font-size: 1.25rem;
            line-height: 1.18;
            font-weight: 700;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: normal;
        }
        .aegis-positioning-hero {
            border: 1px solid #b7d7ff;
            border-left: 6px solid #1f73d2;
            background: linear-gradient(90deg, #eef6ff 0%, #ffffff 100%);
            border-radius: 10px;
            padding: 1rem 1.15rem;
            margin: .35rem 0 1rem;
        }
        .aegis-positioning-hero strong {
            display: block;
            color: #17324d;
            font-size: 1.22rem;
            line-height: 1.25;
            margin-bottom: .45rem;
        }
        .aegis-positioning-hero span {
            display: block;
            color: #344054;
            font-size: .95rem;
            line-height: 1.45;
        }
        .pillar-coverage {
            border: 1px solid #cfe0ff;
            border-left: 5px solid #2f80ed;
            background: #f3f8ff;
            border-radius: 9px;
            padding: .8rem .95rem;
            margin: .2rem 0 1rem;
        }
        .pillar-coverage p {
            color: #344054;
            margin: .55rem 0 0;
            line-height: 1.38;
        }
        .pillar-chip {
            display: inline-block;
            margin: .15rem .35rem .15rem 0;
            padding: .28rem .55rem;
            border-radius: 999px;
            background: #e8f1ff;
            color: #175cd3;
            border: 1px solid #b7d7ff;
            font-size: .78rem;
            font-weight: 700;
        }
        .agent-brief {
            background: #f8fafc;
            border: 1px solid #e7e9ee;
            border-left: 4px solid #2f80ed;
            border-radius: 8px;
            padding: 1rem 1.1rem;
            min-height: 12rem;
        }
        .agent-brief h4 {
            margin: 0 0 .5rem 0 !important;
            font-size: 1.15rem !important;
        }
        .agent-brief p {
            color: #344054;
            line-height: 1.45;
            margin: .4rem 0 .8rem;
        }
        .agent-brief-strip {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: .65rem;
            margin-top: .75rem;
        }
        .agent-brief-chip {
            background: #fff;
            border: 1px solid #e7e9ee;
            border-radius: 7px;
            padding: .65rem .75rem;
        }
        .agent-brief-chip span {
            display: block;
            color: var(--aegis-muted);
            font-size: .74rem;
            font-weight: 650;
            margin-bottom: .2rem;
        }
        .agent-brief-chip strong {
            color: var(--aegis-ink);
            font-size: .98rem;
            line-height: 1.2;
            overflow-wrap: anywhere;
        }
        .story-strip {
            display: flex;
            gap: .85rem;
            align-items: stretch;
            overflow-x: auto;
            padding: .6rem .05rem .9rem;
            margin: .4rem 0 1rem;
        }
        .story-card {
            min-width: 190px;
            flex: 1 0 190px;
            border: 1px solid #e7e9ee;
            border-top: 4px solid #2f80ed;
            border-radius: 8px;
            background: #fff;
            padding: .9rem 1rem;
        }
        .story-card.pass { border-top-color: #21a67a; background: #f2fbf7; }
        .story-card.review { border-top-color: #f79009; background: #fff8eb; }
        .story-card.fail { border-top-color: var(--aegis-red); background: #fff5f6; }
        .story-card span {
            display: block;
            color: var(--aegis-muted);
            font-size: .76rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .03em;
            margin-bottom: .35rem;
        }
        .story-card strong {
            color: var(--aegis-ink);
            display: block;
            font-size: 1.25rem;
            line-height: 1.15;
            overflow-wrap: anywhere;
        }
        .story-card em {
            color: #344054;
            display: block;
            font-style: normal;
            margin-top: .55rem;
            line-height: 1.3;
        }
        .story-arrow {
            flex: 0 0 34px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            min-height: 92px;
        }
        .story-arrow::before {
            content: "";
            width: 24px;
            height: 2px;
            background: #8a96ad;
            border-radius: 999px;
        }
        .story-arrow::after {
            content: "";
            position: absolute;
            right: 4px;
            width: 9px;
            height: 9px;
            border-top: 2px solid #8a96ad;
            border-right: 2px solid #8a96ad;
            transform: rotate(45deg);
        }
        @media (max-width: 900px) {
            .decision-lineage-flow {
                display: grid;
                grid-template-columns: 1fr;
                overflow-x: visible;
            }
            .agent-card-flow {
                display: grid;
                grid-template-columns: 1fr;
                overflow-x: visible;
            }
            .agent-vertical-wrap {
                grid-template-columns: 1fr;
            }
            .decision-lineage-card {
                min-width: 0;
            }
            .agent-flow-card {
                min-width: 0;
            }
            .story-strip {
                display: grid;
                grid-template-columns: 1fr;
                overflow-x: visible;
            }
            .story-card {
                min-width: 0;
            }
            .decision-lineage-arrow, .agent-flow-arrow, .story-arrow {
                display: none;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


_apply_dbs_page_theme()

# ============================================================
# Runtime Monitoring V3
# Phase 1
# ============================================================

def render_runtime_monitoring_v3(result):
    # -------------------------------------------------------
# Normalize input
# -------------------------------------------------------

    if isinstance(result, list):
        result = result[0] if result else {}

    if not isinstance(result, dict):
        result = {}

    runtime_state = result

    telemetry = result.get("runtime_telemetry", {})
    if not isinstance(telemetry, dict):
        telemetry = {}
    st.header("Runtime Monitoring Center")


    runtime = (
        result.get("runtime_health_v2")
        or result.get("runtime_health")
        or telemetry.get("runtime_health")
        or {}
    )
    if not isinstance(runtime, dict):
        runtime = {}

    if not runtime:
        st.warning("Runtime Health not available.")
        return

    agent_counts = _canonical_agent_counts(result)

    # ========================================================
    # Executive Runtime KPI
    # ========================================================

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Health Score",
        runtime.get("health_score", 0)
    )

    c2.metric(
        "Execution",
        runtime.get(
            "execution_status",
            "-"
        )
    )

    c3.metric(
        "Success Rate",
        f'{runtime.get("agent_success_rate",0)}%'
    )

    c4.metric(
        "Avg Latency",
        f'{runtime.get("avg_latency_ms",0):.2f} ms'
    )

    st.divider()

    # ========================================================
    # Runtime Health Summary
    # ========================================================

    st.subheader("Platform Runtime Health")

    left, right = st.columns([2,1])

    with left:

        rows = [

            {
                "Metric":"Status",
                "Value":runtime.get("status")
            },

            {
                "Metric":"Health Level",
                "Value":runtime.get("health_level")
            },

            {
                "Metric":"Recommendation",
                "Value":runtime.get("recommendation")
            },

            {
                "Metric":"Total Agents",
                "Value":agent_counts["total"]
            },

            {
                "Metric":"Successful Agents",
                "Value":agent_counts["completed"]
            },

            {
                "Metric":"Failed Agents",
                "Value":agent_counts["failed"]
            }

        ]

        st.dataframe(

            pd.DataFrame(rows),

            use_container_width=True,

            hide_index=True

        )

    with right:

        score = runtime.get(
            "health_score",
            0
        )

        st.metric(
            "Platform Score",
            score
        )

        st.progress(
            min(score/100,1.0)
        )

        st.metric(
            "Trust",
            runtime.get(
                "trust_score",
                0
            )
        )

        st.metric(
            "Confidence",
            runtime.get(
                "confidence",
                0
            )
        )

    st.divider()

    # ========================================================
    # Runtime Summary
    # ========================================================

    summary = runtime.get(
        "summary",
        ""
    )

    if summary:

        st.subheader(
            "Executive Runtime Summary"
        )

        st.info(summary)

    st.divider()

    # ========================================================
    # Runtime Resource Summary
    # ========================================================

    st.subheader(
        "Runtime Resources"
    )

    a1,a2,a3,a4 = st.columns(4)

    agent_counts = _canonical_agent_counts(result)

    a1.metric(
    "Agents",
    agent_counts["total"]
    )

    a2.metric(
        "Completed",
        agent_counts["completed"]
    )

    a3.metric(
        "Failed",
        agent_counts["failed"]
    )

    a4.metric(
        "Running",
        agent_counts["running"]
    )


    running = max(

        runtime.get(
            "total_agents",
            0
        )

        -

        runtime.get(
            "successful_agents",
            0
        )

        -

        runtime.get(
            "failed_agents",
            0
        ),

        0

    )



    st.divider()

    # ========================================================
    # Runtime Warnings
    # ========================================================

  #  warnings = runtime.get(
  #      "warnings",
  #      []
   # )

   # st.subheader(
   #     "Runtime Alerts"
    #)

    #if warnings:

    #    for item in warnings:

    #        st.warning(item)

    #else:

    #    st.success(
    #        "No runtime warnings detected."
    #    )

    # st.divider()

    # ========================================================
    # Live Runtime Snapshot
    # ========================================================

    st.subheader(
        "Live Runtime Snapshot"
    )


    live = result.get(

        "live_runtime",

        result.get(

            "agent_trace",

            []

        )

    )
    if live:

        live_df = pd.DataFrame(live)

        st.dataframe(

            live_df,

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "No live runtime available."
        )

    st.divider()

    # ========================================================
    # Runtime Health Timeline
    # ========================================================

    # ========================================================
    # Runtime Timeline
    # ========================================================

    timeline = runtime.get("timeline_events")

    if timeline is None:
        timeline = result.get("execution_timeline", [])

    st.subheader("Runtime Timeline")

    if isinstance(timeline, list):

        if len(timeline) > 0:

            st.dataframe(
                pd.DataFrame(timeline),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("No runtime timeline available.")

    elif isinstance(timeline, dict):

        st.dataframe(
            pd.DataFrame([timeline]),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.write(timeline)

    st.divider()

    # ========================================================
    # Phase 2 Starts Here
    # ========================================================
        # ========================================================
    # TOKEN MONITORING
    # ========================================================

        # --------------------------------------------------------
# Token Metrics
# --------------------------------------------------------

    token = telemetry.get(
        "token_metrics",
        result.get(
            "token_metrics",
            {}
        )
    )
    if not token and telemetry:
        token = telemetry.get("token_metrics", {})

    st.subheader("Token Consumption")

    if token:

        t1, t2, t3, t4 = st.columns(4)

        t1.metric(
            "Prompt Tokens",
            token.get("prompt_tokens", 0)
        )

        t2.metric(
            "Completion Tokens",
            token.get("completion_tokens", 0)
        )

        t3.metric(
            "Embedding Tokens",
            token.get("embedding_tokens", 0)
        )

        t4.metric(
            "Total Tokens",
            token.get("total_tokens", 0)
        )

        observed_provider, observed_model = _observed_llm_identity(result, token)

        token_rows = [

            {
                "Metric":"Provider",
                "Value":observed_provider
            },

            {
                "Metric":"Model",
                "Value":observed_model
            },

            {
                "Metric":"Status",
                "Value":token.get("status","-")
            },

            {
                "Metric":"Estimated Cost (USD)",
                "Value":token.get(
                    "estimated_cost_usd",
                    0
                )
            },

            {
                "Metric":"Token Efficiency",
                "Value":token.get(
                    "token_efficiency",
                    0
                )
            },

            {
                "Metric":"Agents",
                "Value":token.get(
                    "agents",
                    0
                )
            },

            {
                "Metric":"Average Tokens / Agent",
                "Value":token.get(
                    "avg_tokens_per_agent",
                    0
                )
            }

        ]

        st.dataframe(

            pd.DataFrame(token_rows),

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Token metrics unavailable."
        )

    st.divider()

    # ========================================================
    # COST MONITORING
    # ========================================================

    st.subheader("Cost Monitoring")

    cost = telemetry.get(
        "cost_metrics",
        {}
    )

    if cost:

        cost_df = pd.DataFrame(

            [

                {
                    "Metric": _cost_metric_label(k),
                    "Value":v
                }

                for k,v in cost.items()

            ]

        )

        st.dataframe(

            cost_df,

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Cost metrics not available."
        )

    st.divider()

    # ========================================================
    # CACHE MONITORING
    # ========================================================

    st.subheader("Cache Monitoring")

    cache = (
        telemetry.get("cache_metrics")
        or result.get("cache_metrics")
        or result.get("cache_lookup")
        or {}
    )

    if cache:

        cache_statistics = result.get("cache_statistics", {})
        if not isinstance(cache_statistics, dict):
            cache_statistics = {}

        quality = _canonical_quality_scores(result)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Lookup", cache.get("status", "ANALYZED"))
        c2.metric("Hit Ratio", f"{cache.get('cache_hit_ratio', 0)}%")
        c3.metric("Hits / Misses", f"{cache.get('cache_hits', cache_statistics.get('cache_hits', 0))} / {cache.get('cache_misses', cache_statistics.get('cache_misses', 0))}")
        c4.metric("Entries / TTL", f"{cache.get('entries', 0)} / {cache.get('ttl_seconds', 0)}s")

        if cache.get("status") == "HIT":
            st.success(
                f"Result served from runtime cache in this execution "
                f"(age: {cache.get('age_seconds', 0)}s, "
                f"remaining TTL: {cache.get('remaining_ttl_seconds', 0)}s)."
            )
        elif cache.get("status") == "STORED":
            st.info("Fresh investigation result stored for reuse by an identical request.")

        cache_df = pd.DataFrame(

            [

                {
                    "Metric":k.replace(
                        "_",
                        " "
                    ).title(),
                    "Value":v
                }

                for k,v in cache.items()

            ]

        )

        st.dataframe(

            cache_df,

            use_container_width=True,

            hide_index=True

        )

        layers = cache.get("layers") or result.get("cache_layers") or {}
        if isinstance(layers, dict) and layers:
            st.caption("Live Cache Layers")
            layer_rows = []
            for layer_name, layer in layers.items():
                if not isinstance(layer, dict):
                    continue
                layer_rows.append({
                    "Layer": layer_name.title(),
                    "Entries": layer.get("entries", 0),
                    "Lookups": layer.get("lookups", 0),
                    "Hits": layer.get("hits", 0),
                    "Misses": layer.get("misses", 0),
                    "Hit Ratio": f"{layer.get('hit_ratio', 0)}%",
                    "Stores": layer.get("stores", 0),
                    "Expired": layer.get("expired", 0),
                    "Evictions": layer.get("evictions", 0),
                    "TTL (s)": layer.get("ttl_seconds", 0),
                    "Capacity": layer.get("max_entries", 0),
                })
            if layer_rows:
                st.dataframe(pd.DataFrame(layer_rows), use_container_width=True, hide_index=True)

    else:

        st.info(
            "Cache metrics unavailable."
        )

    st.divider()

    # ========================================================
    # LATENCY MONITORING
    # ========================================================

    st.subheader("Latency Monitoring")

    latency = telemetry.get(
        "latency_metrics",
        {}
    )

    if latency:

        latency_df = pd.DataFrame(

            [

                {
                    "Metric":k.replace(
                        "_",
                        " "
                    ).title(),
                    "Value":v
                }

                for k,v in latency.items()

            ]

        )

        st.dataframe(

            latency_df,

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Latency metrics unavailable."
        )

    st.divider()

    # ========================================================
    # RUNTIME TELEMETRY
    # ========================================================

    st.subheader("Runtime Telemetry")

    telemetry_rows = []

    for key in [

        "telemetry_score",

        "trust_score",

        "confidence",

        "health_summary",

        "generated_at"

    ]:

        if key in telemetry:

            telemetry_rows.append(

                {

                    "Metric":key.replace(
                        "_",
                        " "
                    ).title(),

                    "Value":telemetry[key]

                }

            )

    if telemetry_rows:

        st.dataframe(

            pd.DataFrame(

                telemetry_rows

            ),

            use_container_width=True,

            hide_index=True

        )

    st.divider()

    # ========================================================
    # EXECUTION EVENTS
    # ========================================================
    # ========================================================
    # EXECUTION EVENTS
    # ========================================================

    st.subheader("Runtime Execution Events")

    events = (
        result.get("execution_events")
        or result.get("execution_timeline")
        or telemetry.get("execution_timeline")
        or []
    )

    if not isinstance(events, (list, dict, pd.DataFrame)):
        events = result.get("execution_timeline", [])

    event_rows = _execution_event_display_rows(events)

    if not event_rows:

        st.info("No execution events available.")

    else:

        st.dataframe(
            _arrow_safe_dataframe(event_rows),
            use_container_width=True,
            hide_index=True
        )

    # ========================================================
    # Phase 3 Starts Here
    # ========================================================
        # ========================================================
    # LIVE AGENT MONITORING
    # ========================================================

    st.subheader("Live Agent Monitoring")

    agent_trace = _normalized_agent_trace(result)

    if not agent_trace:
        fallback_trace = result.get(
            "agent",
            {}
        )
        fallback_trace = _safe_get(
            fallback_trace,
            "agent_trace",
            []
        )
        agent_trace = _normalized_agent_trace({"agent_trace": fallback_trace})

    if agent_trace:

        rows = []

        completed = 0
        running = 0
        failed = 0

        for row in agent_trace:

            status = str(
                row.get(
                    "status",
                    ""
                )
            ).upper()

            if status == "COMPLETED":
                completed += 1

            elif status in (
                "RUNNING",
                "IN_PROGRESS"
            ):
                running += 1

            elif status == "FAILED":
                failed += 1

            trust = row.get(
                "trust_score",
                "-"
            )

            if isinstance(
                trust,
                dict
            ):
                trust = trust.get(
                    "overall",
                    "-"
                )

            rows.append(

                {

                    "Order":
                    row.get(
                        "execution_order"
                    ),

                    "Phase":
                    row.get(
                        "phase"
                    ),

                    "Agent":
                    row.get(
                        "agent"
                    ),

                    "Status":
                    status,

                    "Latency":
                    _format_agent_latency(row.get("duration_ms")),

                    "Agent Trust":
                    "-" if _is_unknown_value(trust) else trust,

                    "Agent Confidence":
                    "-" if _is_unknown_value(row.get("confidence")) else row.get("confidence"),

                    "Tool":
                    row.get(
                        "tool_used"
                    )

                }

            )

        a1,a2,a3,a4 = st.columns(4)

        a1.metric(
            "Completed",
            completed
        )

        a2.metric(
            "Running",
            running
        )

        a3.metric(
            "Failed",
            failed
        )

        a4.metric(
            "Total",
            len(rows)
        )

        st.dataframe(

            _arrow_safe_dataframe(rows),

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Agent trace unavailable."
        )

    st.divider()

    # ========================================================
    # LIVE RUNTIME SNAPSHOT
    # ========================================================

    st.subheader(
        " Live Runtime Snapshot"
    )

    runtime_rows = []

    live = result.get(
        "live_runtime",
        []
    )

    for row in live:

        runtime_rows.append(

            {

                "Timestamp":
                row.get(
                    "timestamp"
                ),

                "Agent":
                row.get(
                    "agent"
                ),

                "Phase":
                row.get(
                    "phase"
                ),

                "Status":
                row.get(
                    "status"
                ),

                "Latency":
                _format_agent_latency(row.get("duration_ms")),

                "Trust":
                "-" if _is_unknown_value(row.get("trust_score")) else row.get("trust_score"),

                "Confidence":
                "-" if _is_unknown_value(row.get("confidence")) else row.get("confidence")

            }

        )

    if runtime_rows:

        st.dataframe(

            _arrow_safe_dataframe(runtime_rows),

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Live runtime not available."
        )

    st.divider()

    # ========================================================
    # EXECUTION TIMELINE
    # ========================================================

    st.subheader(
        " Execution Timeline"
    )

    timeline = _normalized_execution_timeline(result)

    if timeline:

        timeline_df = pd.DataFrame(
            timeline
        )

        st.dataframe(

            timeline_df,

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(
            "Execution timeline unavailable."
        )

    st.divider()

    # ========================================================
    # AGENT EXECUTION SUMMARY
    # ========================================================

    st.subheader(
        " Agent Execution Summary"
    )

    if agent_trace:

        summary_rows = []

        for row in agent_trace:

            summary_rows.append(

                {

                    "Agent":
                    row.get(
                        "agent"
                    ),

                    "Status":
                    row.get(
                        "status"
                    ),

                    "Duration (ms)":
                    row.get(
                        "duration_ms"
                    ),

                    "Remarks":
                    row.get(
                        "remarks",
                        "-"
                    )

                }

            )

        st.dataframe(

            pd.DataFrame(summary_rows),

            use_container_width=True,

            hide_index=True

        )

    st.divider()

    # ========================================================
    # Phase 3B Starts Here
    # ========================================================
        # ========================================================
    # AGENT WORKFLOW
    # ========================================================

    st.subheader("Agent Workflow")


    # ========================================================
    # Agent Workflow
    # ========================================================
    # -------------------------------------------------------
# Build Agent Status Lookup
# -------------------------------------------------------

    agent_status = {}

    for row in agent_trace:

        if not isinstance(row, dict):
            continue

        agent_status[
            _canonical_agent_name(row.get("agent", ""))
        ] = str(

            row.get(
                "status",
                "UNKNOWN"
            )

    ).upper()
    graph = (
        result.get("execution_plan", {}).get("graph")
        or result.get("planner_output", {}).get("graph")
        or result.get("graph")
        or []
    )

    workflow_rows = []

    if isinstance(graph, list):

        for edge in graph:

            if not isinstance(edge, dict):
                continue

            source = edge.get(
                "from",
                edge.get(
                    "source",
                    "-"
                )
            )

            target = edge.get(
                "to",
                edge.get(
                    "target",
                    "-"
                )
            )

            workflow_rows.append(

                {

                    "From": source,

                    "To": target,

                    "Target Status": agent_status.get(
                        _canonical_agent_name(target),
                        {
                            "Customer": "COMPLETED" if any(t.get("phase") == "Customer Investigation" for t in _normalized_execution_timeline(result)) else "NOT RECORDED",
                            "App Evidence Retrieval": agent_status.get("App Evidence Retrieval", agent_status.get("Evidence Retrieval Agent", agent_status.get("RAG", "NOT RECORDED"))),
                            "Compliance": agent_status.get("Compliance", "NOT RECORDED"),
                            "Governance": agent_status.get("Governance", "NOT RECORDED"),
                            "Trust": agent_status.get("Trust", "NOT RECORDED"),
                        }.get(_canonical_agent_name(target), "NOT RECORDED")
                    )

                }

            )

    elif isinstance(graph, dict):

        st.info(
            "Workflow graph not available. Showing graph metrics instead."
        )

        render_table(
            "Graph Metrics",
            graph
        )

    else:

        st.info(
            "Workflow graph unavailable."
        )

    if workflow_rows:

        st.subheader(
            "Agent Workflow"
        )

        st.dataframe(

            pd.DataFrame(
                workflow_rows
            ),

            use_container_width=True,

            hide_index=True

        )
        completed_edges = sum(1 for row in workflow_rows if row["Target Status"] == "COMPLETED")
        st.caption(f"Workflow progress: {completed_edges}/{len(workflow_rows)} transitions completed")

    st.divider()

    # ========================================================
    # AGENT STATUS MATRIX
    # ========================================================

    st.subheader(
        " Agent Status Matrix"
    )

    status_rows = []

    for row in agent_trace:

        status_rows.append(

            {

                "Execution":

                row.get(
                    "execution_order"
                ),

                "Agent":

                row.get(
                    "agent"
                ),

                "Phase":

                row.get(
                    "phase"
                ),

                "Status":

                row.get(
                    "status"
                ),

                "Trust":

                _numeric_score(row.get("trust_score")) or "-",

                "Confidence":

                _numeric_score(row.get("confidence")) or "-",

                "Duration":
                _format_agent_latency(row.get("duration_ms"))

            }

        )

    if status_rows:

        st.dataframe(

            _arrow_safe_dataframe(status_rows),

            use_container_width=True,

            hide_index=True

        )

    st.divider()

    # ========================================================
    # EXECUTIVE RUNTIME RECOMMENDATION
    # ========================================================

    st.subheader(
        " Runtime Recommendation"
    )

    runtime_status = runtime.get(
        "status",
        "-"
    )

    recommendation = runtime.get(
        "recommendation",
        "-"
    )

    success = runtime.get(
        "agent_success_rate",
        0
    )

    if success >= 90:

        st.success(

            f"""

Platform Status : {runtime_status}

Recommendation : {recommendation}

Runtime operating normally.

"""

        )

    elif success >= 70:

        st.warning(

            f"""

Platform Status : {runtime_status}

Recommendation : {recommendation}

Minor runtime degradation detected.

"""

        )

    else:

        st.error(

            f"""

Platform Status : {runtime_status}

Recommendation : {recommendation}

Immediate investigation recommended.

"""

        )

    st.divider()

    # ========================================================
    # EXECUTIVE MONITORING SUMMARY
    # ========================================================

    st.subheader(
        " Executive Monitoring Summary"
    )

    summary_rows = [

        {

            "Metric":"Platform Status",

            "Value":runtime.get(
                "status"
            )

        },

        {

            "Metric":"Health Level",

            "Value":runtime.get(
                "health_level"
            )

        },

        {

            "Metric":"Health Score",

            "Value":runtime.get(
                "health_score"
            )

        },

        {

            "Metric":"Execution",

            "Value":runtime.get(
                "execution_status"
            )

        },

        {

            "Metric":"Success Rate",

            "Value":runtime.get(
                "agent_success_rate"
            )

        },

        {

            "Metric":"Latency (ms)",

            "Value":runtime.get(
                "avg_latency_ms"
            )

        },

        {

            "Metric":"Recommendation",

            "Value":runtime.get(
                "recommendation"
            )

        }

    ]

    st.dataframe(

        pd.DataFrame(
            summary_rows
        ),

        use_container_width=True,

        hide_index=True

    )

    st.divider()

    # ========================================================
    # Phase 3B-2 Starts Here
    # ========================================================
        # ========================================================
    # LLM MONITORING
    # ========================================================

    st.subheader("LLM Monitoring")

    llm_rows = []

    planner_llm = result.get("planner_llm", {})

    runtime_llm = runtime_state.get("runtime_llm", {})

    if isinstance(runtime_llm, list):
        runtime_llm = runtime_llm[0] if runtime_llm else {}

    if runtime_llm is None:
        runtime_llm = {}
    llm_metrics = result.get("llm_metrics", {})
    llm_trace = result.get("llm_trace", {})

    if planner_llm:

        llm_rows.append({

            "LLM":"Planner",

            "Success":planner_llm.get(
                "success"
            ),

            "Confidence":planner_llm.get(
                "confidence"
            ),

            "Trust":planner_llm.get(
                "trust_score"
            )

        })

    if runtime_llm:

        llm_rows.append({

            "LLM":"Runtime",

            "Success":runtime_llm.get(
                "success",
                "-"
            ),

            "Confidence":runtime_llm.get(
                "confidence",
                "-"
            ),

            "Trust":runtime_llm.get(
                "trust_score",
                "-"
            )

        })

    if llm_rows:

        st.dataframe(

            pd.DataFrame(llm_rows),

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info(

            "LLM monitoring data not available."

        )

    st.divider()

    # ========================================================
    # LLM TRACE
    # ========================================================

    st.subheader("LLM Trace")

    if isinstance(llm_trace, list):

        if llm_trace:

            st.dataframe(
                pd.DataFrame(llm_trace),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("LLM Trace unavailable.")

    elif isinstance(llm_trace, dict):

        trace_rows = []

        for k, v in llm_trace.items():

            trace_rows.append({

                "Property": k,

                "Value": str(v)

            })

        st.dataframe(

            pd.DataFrame(trace_rows),

            use_container_width=True,

            hide_index=True

        )

    else:

        st.info("LLM Trace unavailable.")

    st.divider()

    # ========================================================
    # PLATFORM DASHBOARD
    # ========================================================

    st.subheader(
        "Platform Dashboard"
    )

    dashboard=result.get(
        "dashboard_metrics",
        {}
    )

    if dashboard:

        dashboard_df=pd.DataFrame(

            [

                {

                    "Metric":k.replace(
                        "_",
                        " "
                    ).title(),

                    "Value":v

                }

                for k,v in dashboard.items()

            ]

        )

        st.dataframe(

            dashboard_df,

            use_container_width=True,

            hide_index=True

        )

    st.divider()

    # ========================================================
    # CONTROL TOWER SUMMARY
    # ========================================================

    st.subheader(
        "Control Tower Summary"
    )

    summary=result.get(
        "control_tower_summary",
        {}
    )

    if summary:

        st.success(

            summary.get(

                "executive_summary",

                "Runtime completed successfully."

            )

        )

        executive_snapshot=summary.get(

            "executive_snapshot",

            {}

        )


        if executive_snapshot:

            snapshot_rows=[]

            for k,v in executive_snapshot.items():

                snapshot_rows.append({

                    "Metric":k.replace(
                        "_",
                        " "
                    ).title(),

                    "Value":v

                })

            st.dataframe(

                pd.DataFrame(snapshot_rows),

                use_container_width=True,

                hide_index=True

            )

    st.divider()

    # ========================================================
    # MONITORING HEALTH
    # ========================================================

    st.subheader(
        "Monitoring Health"
    )

    score=runtime.get(
        "health_score",
        0
    )

    if score>=90:

        st.success(

            " Runtime Monitoring Status : HEALTHY"

        )

    elif score>=75:

        st.warning(

            " Runtime Monitoring Status : STABLE"

        )

    else:

        st.error(

            " Runtime Monitoring Status : ATTENTION REQUIRED"

        )

    st.divider()

    # ========================================================
    # EXECUTION COMPLETE
    # ========================================================

    st.success(
        "Runtime Monitoring completed successfully."
    )

    st.divider()
# ============================================================
# IMPORTS
# ============================================================

from shared1.investigation_launcher import (
    render_investigation_launcher
)

#from runtime_ui1.control_tower_renderer import (
#    render_control_tower
#)

# ============================================================
# INVESTIGATION LAUNCHER
# ============================================================

render_investigation_launcher()

# ============================================================
# RUNTIME OUTPUT
# ============================================================

runtime_state = st.session_state.get(
    "runtime_state",
    {}
)

if not runtime_state:

    st.info(
        "Load an external app canonical JSONL runtime log from the sidebar to view the AEGIS Enterprise Control Tower."
    )

    st.stop()

# ============================================================
# PAGE HEADER
# ============================================================

st.title("AEGIS Enterprise AI Control Tower")

st.caption(
    "Trustworthy, governable, measurable and scalable Agentic AI platform"
)

st.divider()

# ============================================================
# CONTROL TOWER
# ============================================================


# ============================================================
# Generic Helpers
# ============================================================

def _arrow_safe_dataframe(data):
    """Build a display DataFrame whose object cells are safe for PyArrow."""
    df = data.copy() if isinstance(data, pd.DataFrame) else pd.DataFrame(data)

    columns = {str(column).casefold() for column in df.columns}
    if {"phase", "status", "duration_ms"}.issubset(columns):
        df = pd.DataFrame(_execution_timeline_display_rows(df.to_dict("records")))

    # Streamlit converts DataFrames to Arrow. Uploaded/saved runtime payloads can
    # contain dict/list values beside scalar values in an object column, which
    # Arrow cannot represent with one consistent type. Preserve scalar values and
    # stringify only nested cells for display; the original payload is untouched.
    for column in df.columns:
        if df[column].dtype != "object":
            continue
        df[column] = df[column].map(
            lambda value: json.dumps(value, default=str, ensure_ascii=False)
            if isinstance(value, (dict, list, tuple, set))
            else value
        )

    return _clean_display_dataframe(df)


def _arrow_safe_streamlit_dataframe(data=None, *args, **kwargs):
    """Render any page DataFrame after normalizing nested object cells."""
    if data is None:
        return _streamlit_dataframe(data, *args, **kwargs)

    try:
        data = _arrow_safe_dataframe(data)
    except (TypeError, ValueError):
        # Preserve Streamlit support for non-tabular objects that its native
        # dataframe renderer understands but pandas cannot construct directly.
        pass

    return _streamlit_dataframe(data, *args, **kwargs)


# This page has many historical direct st.dataframe calls. Routing them here
# prevents the same mixed struct/scalar Arrow failure in every dashboard block.
st.dataframe = _arrow_safe_streamlit_dataframe


def render_table(title, data):

    st.subheader(title)

    if data is None:
        st.info("No data available.")
        return

    if isinstance(data, pd.DataFrame):

        st.dataframe(
            _arrow_safe_dataframe(data),
            use_container_width=True,
            hide_index=True
        )
        return

    if isinstance(data, list):

        if len(data) == 0:
            st.info("No data available.")
            return

        cleaned = []
        for row in data:
            if not isinstance(row, dict):
                cleaned.append(row)
                continue
            compact = {
                key: value for key, value in row.items()
                if value not in (None, "", "Not reported", "Unavailable", "N/A")
            }
            if compact:
                cleaned.append(compact)
        if not cleaned:
            return

        st.dataframe(
            _arrow_safe_dataframe(cleaned),
            use_container_width=True,
            hide_index=True
        )
        return

    if isinstance(data, dict):

        if len(data) == 0:
            st.info("No data available.")
            return

        st.dataframe(
            _arrow_safe_dataframe([data]),
            use_container_width=True,
            hide_index=True
        )
        return

    st.write(data)


def render_security_control_heatmap(security):
    checks = security.get("checks", []) if isinstance(security, dict) else []
    rows = []
    if isinstance(checks, list) and checks:
        for check in checks:
            if isinstance(check, dict):
                rows.append({
                    "Control": check.get("category", check.get("owasp_control", "Control")),
                    "Status": str(check.get("status", "UNKNOWN")).upper(),
                    "Score": _numeric_score(check.get("score"), 0),
                })
    else:
        for label, key in [
            ("Prompt Injection", "prompt_injection"),
            ("Jailbreak Detection", "jailbreak_detection"),
            ("PII Exposure", "pii_exposure"),
            ("Data Leakage", "data_leakage"),
            ("Tool Security", "tool_security"),
        ]:
            control = security.get(key, {}) if isinstance(security, dict) else {}
            if isinstance(control, dict):
                rows.append({"Control": label, "Status": str(control.get("status", "UNKNOWN")).upper(), "Score": _numeric_score(control.get("score"), 0)})
    if not rows:
        return
    severity = {"PASS": 1, "OK": 1, "REVIEW": 2, "WARN": 2, "FAIL": 3, "ERROR": 3, "DETECTED": 3}
    df = pd.DataFrame(rows)
    df["Severity"] = df["Status"].map(lambda status: severity.get(str(status).upper(), 2))
    fig = px.imshow(
        [df["Severity"].tolist()],
        x=df["Control"].tolist(),
        y=["OWASP Controls"],
        color_continuous_scale=[(0, "#e7f8f0"), (0.5, "#fff4e5"), (1, "#feecef")],
        aspect="auto",
    )
    fig.update_traces(text=[df["Status"].tolist()], texttemplate="%{text}", hovertemplate="Control=%{x}<br>Status=%{text}<extra></extra>")
    fig.update_layout(height=210, margin=dict(l=10, r=10, t=20, b=10), coloraxis_showscale=False)
    st.plotly_chart(fig, use_container_width=True)


def render_decision_policy_path(result):
    st.subheader("Decision Policy Path")
    recommendation, risk_level = _runtime_recommendation_and_risk(result)
    evidence_count = len(result.get("evidence_pack", []) or result.get("retrieved_chunks", []) or [])
    review_risk_states = {"HIGH", "CRITICAL", "REVIEW", "REVIEW_REQUIRED", "INSUFFICIENT_EVIDENCE", "CUSTOMER_NOT_FOUND", "UNKNOWN", "-"}
    release_assessment = _governance_release_assessment(result)
    governance_review = bool(release_assessment["review_required"])
    governance_decision = "PASS" if recommendation in {"APPROVE", "PASS"} and not governance_review else "HITL GATE" if governance_review else str(recommendation)
    recommendation_status = release_assessment["release_route"] if recommendation == "APPROVE" else recommendation
    steps = [
        ("Evidence", f"{evidence_count} objects", evidence_count > 0),
        ("Risk", risk_level, risk_level not in review_risk_states),
        ("Governance", governance_decision, not governance_review),
        ("Release Route", recommendation_status, recommendation_status == "RELEASE"),
    ]
    card_html = ["<div class='decision-policy-path'>"]
    for label, value, passed in steps:
        status = "Pass" if passed else "Review"
        status_class = "pass" if passed else "review"
        card_html.append(
            "<div class='decision-policy-card'>"
            f"<span>{html.escape(str(label))}</span>"
            f"<strong>{html.escape(str(value))}</strong>"
            f"<em class='{status_class}'>{status}</em>"
            "</div>"
        )
    card_html.append("</div>")
    st.markdown("".join(card_html), unsafe_allow_html=True)


def render_score_explainability(result):
    st.header("Score Explainability")
    st.caption("Executive-readable explanation of how AEGIS calculated the decision, trust, quality, and customer-health scores.")

    quality = _canonical_quality_scores(result)
    emitted_fields = {
        str(field).casefold()
        for field in result.get("emitted_canonical_fields", [])
        if not _is_unknown_value(field)
    }

    def _score_source(field, *, final=False):
        key = str(field or "").casefold()
        if final:
            return "Source: AEGIS final calculation"
        if key in emitted_fields:
            return "Source: App emitted, AEGIS normalized"
        return "Source: AEGIS calculated"

    def _missing_variable_notice(variable_name):
        return f"Required variable not emitted from Onboarded App: {variable_name}"

    def _display_or_missing(value, variable_name):
        return _missing_variable_notice(variable_name) if _is_unknown_value(value) else value

    decision_explainability = _safe_dict(result.get("decision_explainability"))
    recommendation_package = _safe_dict(result.get("recommendation_package"))
    governance = _safe_dict(result.get("governance"))
    compliance = _safe_dict(result.get("compliance"))
    reflection = _safe_dict(result.get("reflection"))
    retrieval_stats = _safe_dict(result.get("retrieval_statistics"))
    risk_authority = _safe_dict(result.get("risk_authority"))
    executive = _safe_dict(result.get("executive_package") or result.get("executive_narrative"))
    customer_health = _safe_dict(result.get("customer_health") or executive.get("customer_health"))
    recommendation, risk_level = _runtime_recommendation_and_risk(result)
    compliance_status = _canonical_compliance_status(result)
    release_assessment = _governance_release_assessment(result)
    review_required = bool(release_assessment["review_required"])
    governance_status = release_assessment["governance_status"]
    risk_score = _numeric_score(
        risk_authority.get("score", result.get("risk_score", customer_health.get("risk_score"))),
        0,
    )
    anomalies = result.get("anomalies", [])
    anomaly_count = (
        len(anomalies)
        if isinstance(anomalies, list)
        else _numeric_score(_safe_dict(anomalies).get("anomaly_count", _safe_dict(anomalies).get("count")), 0)
    )
    if _is_unknown_value(customer_health.get("relationship_score")):
        customer_health["relationship_score"] = round((quality["trust_score"] * 0.60) + (quality["confidence"] * 0.40), 1)
    if _is_unknown_value(customer_health.get("engagement_score")):
        customer_health["engagement_score"] = round(max(0, 100 - (anomaly_count * 5)), 1)
    if _is_unknown_value(customer_health.get("portfolio_score")):
        customer_health["portfolio_score"] = round(
            (_numeric_score(customer_health.get("relationship_score"), 0) + _numeric_score(customer_health.get("engagement_score"), 0)) / 2,
            1,
        )
    if _is_unknown_value(customer_health.get("risk_score")):
        customer_health["risk_score"] = risk_score
    if _is_unknown_value(customer_health.get("health_score")):
        customer_health["health_score"] = round(
            (_numeric_score(customer_health.get("relationship_score"), 0) * 0.35)
            + (_numeric_score(customer_health.get("portfolio_score"), 0) * 0.30)
            + (_numeric_score(customer_health.get("engagement_score"), 0) * 0.20)
            + (max(0, 100 - _numeric_score(customer_health.get("risk_score"), 0)) * 0.15),
            1,
        )
    if _is_unknown_value(customer_health.get("status")):
        health_score_for_status = _numeric_score(customer_health.get("health_score"), 0)
        customer_health["status"] = "HEALTHY" if health_score_for_status >= 80 else "WATCH" if health_score_for_status >= 60 else "REVIEW"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Trust", f"{quality['trust_score']:.1f}")
    c1.caption(_score_source("trust_score"))
    c2.metric("Confidence", f"{quality['confidence']:.1f}")
    c2.caption(_score_source("confidence"))
    c3.metric("Grounding", "-" if quality["groundedness"] is None else f"{quality['groundedness']:.1f}")
    c3.caption(_score_source("groundedness_score"))
    c4.metric("Coverage", "-" if quality["coverage"] is None else f"{quality['coverage']:.1f}")
    c4.caption(_score_source("coverage_score"))

    st.subheader("Executive Score Cards")
    relationship_raw = customer_health.get("relationship_score", "-")
    engagement_raw = customer_health.get("engagement_score", "-")
    portfolio_raw = customer_health.get("portfolio_score", "-")
    health_raw = customer_health.get("health_score", customer_health.get("overall_score", customer_health.get("score", "-")))
    executive_cards = [
        {
            "title": "Relationship",
            "value": _display_or_missing(relationship_raw, "customer_health.relationship_score"),
            "formula": "Trust x 60% + Confidence x 40%",
            "meaning": "Measures the strength and reliability of the customer relationship using decision trust and model confidence.",
            "drivers": f"Trust {quality['trust_score']:.1f}; Confidence {quality['confidence']:.1f}",
            "source": f"Source: AEGIS calculated from trust_score and confidence. {_score_source('trust_score')} | {_score_source('confidence')}",
        },
        {
            "title": "Engagement",
            "value": _display_or_missing(engagement_raw, "customer_health.engagement_score"),
            "formula": "100 - anomaly penalty",
            "meaning": "Measures whether observed customer activity looks stable or needs closer monitoring.",
            "drivers": f"Anomaly count: {anomaly_count}",
            "source": "Source: AEGIS calculated from anomaly/runtime signals",
        },
        {
            "title": "Portfolio",
            "value": _display_or_missing(portfolio_raw, "customer_health.portfolio_score"),
            "formula": "(Relationship + Engagement) / 2",
            "meaning": "Summarizes the customer portfolio posture by blending relationship quality and engagement stability.",
            "drivers": (
                f"Relationship {_display_or_missing(relationship_raw, 'customer_health.relationship_score')}; "
                f"Engagement {_display_or_missing(engagement_raw, 'customer_health.engagement_score')}"
            ),
            "source": "Source: AEGIS calculated from relationship and engagement",
        },
        {
            "title": "Risk",
            "value": customer_health.get("risk_score", risk_score),
            "formula": "Canonical risk authority",
            "meaning": "Captures adverse risk signals such as alerts, cases, risk rating, and policy review triggers.",
            "drivers": f"Risk level: {risk_authority.get('risk_level', risk_authority.get('level', result.get('risk_level', '-')))}",
            "source": "Source: AEGIS calculated risk authority",
        },
        {
            "title": "Overall Health",
            "value": _display_or_missing(health_raw, "customer_health.health_score"),
            "formula": "Relationship 35% + Portfolio 30% + Engagement 20% + Risk inverse 15%",
            "meaning": "Board-level customer health score used to summarize relationship, portfolio, engagement, and risk posture.",
            "drivers": f"Status: {_display_or_missing(customer_health.get('status', customer_health.get('health', '-')), 'customer_health.status')}",
            "source": "Source: AEGIS calculated health summary",
        },
    ]
    cards_html = ["<div class='score-explain-card-grid'>"]
    for card in executive_cards:
        cards_html.append(
            "<div class='score-explain-card'>"
            f"<span>{html.escape(str(card['title']))}</span>"
            f"<strong>{html.escape(str(card['value']))}</strong>"
            f"<p>{html.escape(str(card['meaning']))}</p>"
            f"<em>{html.escape(str(card['formula']))}</em>"
            f"<small>{html.escape(str(card['drivers']))}</small>"
            f"<small>{html.escape(str(card.get('source', 'Source: AEGIS calculated')))}</small>"
            "</div>"
        )
    cards_html.append("</div>")
    st.markdown("".join(cards_html), unsafe_allow_html=True)

    relationship_value = customer_health.get("relationship_score", "-")
    engagement_value = customer_health.get("engagement_score", "-")
    portfolio_value = customer_health.get("portfolio_score", "-")
    health_value = customer_health.get("health_score", customer_health.get("overall_score", customer_health.get("score", "-")))
    health_contributions = _safe_dict(customer_health.get("component_contributions"))

    calculation_rows = [
        {
            "Calculation": "Trust Score",
            "Formula / Rule": "If app emits trust_score, AEGIS normalizes it. If missing, AEGIS derives: evidence 30% + control 30% + confidence 20% + error 10% + trace 10%.",
            "Inputs Used": "Evidence trust, retrieval confidence, grounding, governance/compliance controls, terminal reconciliation.",
            "Current Value": f"{quality['trust_score']:.1f}",
            "Runtime Source": _score_source("trust_score"),
            "Technical Meaning": "How much AEGIS trusts the final decision package.",
        },
        {
            "Calculation": "Confidence",
            "Formula / Rule": "If app emits confidence/model_confidence, AEGIS normalizes/averages it. If missing, confidence is 0 until evidence is emitted.",
            "Inputs Used": "Recommendation confidence, retrieval quality, evidence coverage, deterministic policy reconciliation.",
            "Current Value": f"{quality['confidence']:.1f}",
            "Runtime Source": _score_source("confidence"),
            "Technical Meaning": "How confident the system is that the decision is supported.",
        },
        {
            "Calculation": "Grounding",
            "Formula / Rule": "Evidence support score, bounded to 0-100. Uses grounding_score / groundedness_score / RAGAS context recall where present.",
            "Inputs Used": "Final claims, retrieved evidence, citation/support coverage.",
            "Current Value": "-" if quality["groundedness"] is None else f"{quality['groundedness']:.1f}",
            "Runtime Source": "runtime_state.groundedness_score / grounding_results / ragas_scores",
            "Technical Meaning": "Whether the answer is anchored in retrieved evidence.",
        },
        {
            "Calculation": "Hallucination Risk",
            "Formula / Rule": "Risk label from hallucination/reflection checks. LOW means no material unsupported contradiction was detected.",
            "Inputs Used": "Reflection narrative, hallucination checks, unsupported-claim checks.",
            "Current Value": quality["hallucination_risk"],
            "Runtime Source": "hallucination_results / reflection",
            "Technical Meaning": "Risk that the generated response contains unsupported claims.",
        },
        {
            "Calculation": "Risk Score",
            "Formula / Rule": "Canonical adverse risk score, 0-100. LOW < 25, MODERATE 25-59.99, HIGH 60-89.99, CRITICAL >= 90.",
            "Inputs Used": "Customer risk rating, alerts, cases, sanctions/AML/KYC indicators, risk authority reconciliation.",
            "Current Value": risk_score,
            "Runtime Source": "Source: AEGIS calculated risk authority",
            "Technical Meaning": "Adverse customer or decision risk. Higher is worse.",
        },
        {
            "Calculation": "Relationship Score",
            "Formula / Rule": "Trust x 60% + Confidence x 40%",
            "Inputs Used": f"Trust {quality['trust_score']:.1f}; Confidence {quality['confidence']:.1f}",
            "Current Value": relationship_value,
            "Runtime Source": "customer_health.relationship_score",
            "Technical Meaning": "Reliability of the customer relationship and decision signal.",
        },
        {
            "Calculation": "Engagement Score",
            "Formula / Rule": "max(0, 100 - anomaly_count x 5)",
            "Inputs Used": f"Anomaly count {anomaly_count}",
            "Current Value": engagement_value,
            "Runtime Source": "customer_health.engagement_score",
            "Technical Meaning": "Activity stability. More anomalies reduce this score.",
        },
        {
            "Calculation": "Portfolio Score",
            "Formula / Rule": "(Relationship Score + Engagement Score) / 2",
            "Inputs Used": f"Relationship {relationship_value}; Engagement {engagement_value}",
            "Current Value": portfolio_value,
            "Runtime Source": "customer_health.portfolio_score",
            "Technical Meaning": "Blended customer portfolio posture.",
        },
        {
            "Calculation": "Overall Health",
            "Formula / Rule": "Relationship x 35% + Portfolio x 30% + Engagement x 20% + (100 - Risk Score) x 15%",
            "Inputs Used": (
                f"Relationship contribution {health_contributions.get('relationship', '-')}; "
                f"Portfolio {health_contributions.get('portfolio', '-')}; "
                f"Engagement {health_contributions.get('engagement', '-')}; "
                f"Risk inverse {health_contributions.get('risk_inverse', '-')}"
            ),
            "Current Value": health_value,
            "Runtime Source": "customer_health.health_score",
            "Technical Meaning": "Executive-level customer health classification.",
        },
        {
            "Calculation": "Governance Status",
            "Formula / Rule": "PASS when recommendation is APPROVE and no HITL/risk-review condition is active; otherwise REVIEW.",
            "Inputs Used": f"Recommendation {recommendation}; Risk level {risk_level}; HITL required {review_required}",
            "Current Value": governance_status,
            "Runtime Source": "governance / human_review_authority / recommendation_package",
            "Technical Meaning": "Whether AEGIS allows the decision or requires governance review.",
        },
        {
            "Calculation": "Final Recommendation",
            "Formula / Rule": "Terminal reconciliation of evidence, risk, trust, confidence, governance, compliance, and next-best-action thresholds.",
            "Inputs Used": f"Recommendation {recommendation}; Compliance {compliance_status}; Governance {governance_status}",
            "Current Value": result.get("recommendation", recommendation_package.get("recommendation", "-")),
            "Runtime Source": "runtime_state.recommendation / recommendation_package",
            "Technical Meaning": "Final governed action returned by AEGIS.",
        },
    ]

    st.subheader("Technical Calculation Table")
    render_table("How Scores Are Calculated", calculation_rows)

    score_rows = [
        {
            "Score": "Trust Score",
            "Final Value": quality["trust_score"],
            "How It Is Calculated": "Combines retrieval trust, evidence support, grounding, governance/compliance controls, validation, and terminal reconciliation.",
            "Runtime Evidence": decision_explainability.get("trust_calculation") or result.get("trust") or retrieval_stats,
        },
        {
            "Score": "Confidence",
            "Final Value": quality["confidence"],
            "How It Is Calculated": "Uses confidence component scores from recommendation, retrieval quality, evidence coverage, and deterministic policy reconciliation.",
            "Runtime Evidence": decision_explainability.get("confidence_derivation") or result.get("confidence_scores"),
        },
        {
            "Score": "Grounding",
            "Final Value": quality["groundedness"],
            "How It Is Calculated": "Measures whether final claims are supported by retrieved/source evidence and citation coverage.",
            "Runtime Evidence": reflection.get("grounding_summary") or result.get("grounding_results") or reflection,
        },
        {
            "Score": "Hallucination Risk",
            "Final Value": quality["hallucination_risk"],
            "How It Is Calculated": "Checks whether final narrative claims are unsupported, contradictory, or outside retrieved evidence.",
            "Runtime Evidence": result.get("hallucination_results") or reflection,
        },
        {
            "Score": "Governance Decision",
            "Final Value": f"{recommendation} / {governance_status}",
            "How It Is Calculated": "Applies policy controls, review thresholds, approval rules, and human-in-the-loop requirements.",
            "Runtime Evidence": governance,
        },
        {
            "Score": "Compliance Decision",
            "Final Value": compliance_status,
            "How It Is Calculated": "Evaluates compliance controls such as KYC/AML status, exceptions, alerts, and policy evidence.",
            "Runtime Evidence": compliance,
        },
        {
            "Score": "Risk Level",
            "Final Value": risk_level,
            "How It Is Calculated": "Derived from customer risk indicators, alerts/cases, evidence findings, and canonical risk authority.",
            "Runtime Evidence": risk_authority or result.get("risk_profile"),
        },
        {
            "Score": "Recommendation",
            "Final Value": result.get("recommendation", recommendation_package.get("recommendation", "-")),
            "How It Is Calculated": "Terminal decision reconciles evidence, risk, trust, confidence, governance, compliance, and expected action thresholds.",
            "Runtime Evidence": result.get("recommendation_authority") or recommendation_package,
        },
    ]

    st.subheader("Decision And AI Quality Calculations")
    display_rows = []
    for row in score_rows:
        evidence = row.get("Runtime Evidence")
        if isinstance(evidence, dict):
            evidence_summary = "; ".join(
                f"{str(key).replace('_', ' ').title()}: {value}"
                for key, value in list(evidence.items())[:6]
                if value not in (None, "", [], {})
            )
        else:
            evidence_summary = str(evidence) if evidence not in (None, "") else "-"
        display_rows.append({
            "Score": row["Score"],
            "Final Value": row["Final Value"],
            "How It Is Calculated": row["How It Is Calculated"],
            "Runtime Evidence Summary": evidence_summary or "-",
        })
    render_table("Score Calculation Summary", display_rows)

    tree = decision_explainability.get("decision_tree")
    if isinstance(tree, list) and tree:
        render_table("Decision Rules Applied", tree)

    feature_contributions = decision_explainability.get("feature_contributions")
    if isinstance(feature_contributions, list) and feature_contributions:
        render_table("Feature Contributions", feature_contributions)


def render_cache_acceleration_visual(cache, layers, query_cache=None):
    st.subheader("Cache Acceleration Funnel")
    status = str(cache.get("status", "ANALYZED")).upper()
    hit = status == "HIT"
    steps = [
        ("Lookup", "DONE", True),
        ("Hit / Miss", "HIT" if hit else "MISS" if status in {"MISS", "STORED"} else status, hit),
        ("Freshness", "VALID" if hit else "N/A", hit),
        ("Outcome", "SERVED" if hit else "STORED" if status == "STORED" else "ANALYZED", status in {"HIT", "STORED"}),
    ]
    for col, (label, value, positive) in zip(st.columns(len(steps)), steps):
        col.metric(label, value)
        if positive:
            col.success("Complete")
        else:
            col.info("No cache serve")
    st.caption(_cache_miss_reason(cache, query_cache))
    layer_rows = []
    if isinstance(layers, dict):
        for layer_name, layer in layers.items():
            if isinstance(layer, dict):
                if layer_name == "kv":
                    continue
                label = str(layer_name).replace("_", " ").title()
                note = "Session-scoped cache layer"
                if layer_name == "embedding_cdc":
                    label = "Persistent Embedding CDC"
                    note = "Persistent vector reuse across runs"
                elif layer_name == "embedding":
                    label = "Session Query Embedding"
                    note = "Transient query embedding wrapper"
                elif layer_name == "prompt":
                    label = "Session Prompt/Query"
                    note = "Exact prompt/query reuse"
                elif layer_name == "runtime":
                    label = "Full Runtime Result"
                    note = "Avoids full agent traversal on exact repeat"
                elif layer_name == "retrieval":
                    label = "Retrieval Result"
                    note = "Reuses retrieved document set on exact match"
                hit_ratio = round(_numeric_score(layer.get("hit_ratio"), 0), 2)
                layer_rows.append({
                    "Layer": label,
                    "Hit Ratio": hit_ratio,
                    "Status": "Active reuse" if hit_ratio >= 50 else "Warming" if layer.get("stores", 0) else "No reuse yet",
                    "Explanation": note,
                })
    if layer_rows:
        df = pd.DataFrame(layer_rows)
        order = [
            "Persistent Embedding CDC",
            "Full Runtime Result",
            "Session Prompt/Query",
            "Retrieval Result",
            "Session Query Embedding",
        ]
        df["Layer"] = pd.Categorical(df["Layer"], categories=order, ordered=True)
        df = df.sort_values("Layer", ascending=False)
        fig = px.bar(
            df,
            x="Hit Ratio",
            y="Layer",
            color="Status",
            text=df["Hit Ratio"].map(lambda value: f"{value:.1f}%"),
            orientation="h",
            title="Cache Reuse Maturity by Layer",
            hover_data=["Explanation"],
            color_discrete_map={
                "Active reuse": "#11845b",
                "Warming": "#f79009",
                "No reuse yet": "#98a2b3",
            },
        )
        fig.update_traces(textposition="outside", cliponaxis=False)
        fig.update_layout(
            height=360,
            margin=dict(l=12, r=72, t=48, b=18),
            xaxis_title="Reuse / Hit Ratio (%)",
            yaxis_title="",
            xaxis=dict(range=[0, 105], ticksuffix="%"),
            legend_title_text="Cache State",
        )
        st.plotly_chart(fig, use_container_width=True)
        empty_notes = []
        for row in df.to_dict("records"):
            if _numeric_score(row.get("Hit Ratio"), 0) > 0:
                continue
            layer = str(row.get("Layer"))
            if layer == "Full Runtime Result":
                empty_notes.append("Full Runtime Result should serve on the next exact repeat of the same customer, investigation type, query, and knowledge version. If it still misses, the cache key inputs are changing.")
            elif layer == "Retrieval Result":
                empty_notes.append("Retrieval Result is empty until an exact retrieval request repeats with the same query, index fingerprint, embedding model, and top-k.")
            elif layer == "Session Query Embedding":
                empty_notes.append("Session Query Embedding only counts transient query embedding wrapper calls; persistent embedding reuse is shown by Embedding CDC.")
            elif layer == "Session Prompt/Query":
                empty_notes.append("Session Prompt/Query requires an exact prompt key match; dynamic runtime context can create a new prompt key.")
        if empty_notes:
            with st.expander("Why some cache layers show no reuse yet", expanded=False):
                for note in empty_notes:
                    st.markdown(f"- {note}")


def _cache_layer_display_rows(layers, query_cache=None):
    query_cache = query_cache if isinstance(query_cache, dict) else {}
    rows = []
    if not isinstance(layers, dict):
        return rows
    for layer_name, layer in layers.items():
        if not isinstance(layer, dict):
            continue
        if layer_name == "kv":
            continue
        display_name = str(layer_name).replace("_", " ").title()
        role = "Session cache"
        interpretation = "Exact-match cache for this running app process."
        hit_ratio = _numeric_score(layer.get("hit_ratio"), 0)
        hits = layer.get("hits", 0)
        misses = layer.get("misses", 0)
        lookups = layer.get("lookups", 0)
        stores = layer.get("stores", 0)
        if layer_name == "embedding_cdc":
            display_name = "Persistent Embedding CDC"
            role = "Persistent embedding reuse"
            interpretation = "Authoritative embedding reuse across runs. This is the primary embedding-cache signal."
        elif layer_name == "embedding":
            display_name = "Session Query Embedding"
            role = "Transient query embedding wrapper"
            interpretation = "Only counts ad-hoc query embedding lookups in this session; persistent reuse is shown by Embedding CDC."
        elif layer_name == "prompt":
            display_name = "Session Prompt/Query"
            role = "Exact prompt cache"
            if str(query_cache.get("status", "")).upper() == "HIT":
                interpretation = "Query rewrite was served from prompt cache for this run."
            elif stores and not hits:
                interpretation = "Prompt/query results are warmed. A later exact same prompt should show HIT."
            else:
                interpretation = "Exact model prompt cache. Dynamic runtime context can create distinct prompt keys."
        elif layer_name == "runtime":
            display_name = "Full Runtime Result"
            role = "Completed investigation cache"
            interpretation = "Expected to serve the full result on the next exact repeat of customer, investigation type, query, and knowledge version."
        elif layer_name == "retrieval":
            display_name = "Retrieval Result"
            role = "Retrieved document cache"
            interpretation = "Exact retrieval cache; key includes query, index/version, embedding model, and top-k."
        rows.append({
            "Layer": display_name,
            "Role": role,
            "Entries": layer.get("entries", 0),
            "Lookups": lookups,
            "Hits": hits,
            "Misses": misses,
            "Hit Ratio": f"{hit_ratio}%",
            "Stores": stores,
            "TTL (s)": layer.get("ttl_seconds", 0),
            "Interpretation": interpretation,
        })
    order = {
        "Persistent Embedding CDC": 0,
        "Full Runtime Result": 1,
        "Session Prompt/Query": 2,
        "Retrieval Result": 3,
        "Session Query Embedding": 4,
    }
    return sorted(rows, key=lambda row: order.get(row["Layer"], 99))


def render_token_execution_chart(result, token):
    rows = []
    llm_trace = result.get("llm_trace", [])
    if isinstance(llm_trace, list):
        for row in llm_trace:
            if not isinstance(row, dict):
                continue
            telemetry = row.get("telemetry", {}) if isinstance(row.get("telemetry"), dict) else {}
            prompt_tokens = _numeric_score(
                row.get("prompt_tokens", row.get("input_tokens", telemetry.get("prompt_tokens", telemetry.get("input_tokens")))),
                0,
            )
            completion_tokens = _numeric_score(
                row.get("completion_tokens", row.get("output_tokens", telemetry.get("completion_tokens", telemetry.get("output_tokens")))),
                0,
            )
            if prompt_tokens <= 0 and completion_tokens <= 0:
                continue
            rows.append({
                "Agent": row.get("agent") or row.get("agent_name") or row.get("name") or "LLM Call",
                "Prompt Tokens": prompt_tokens,
                "Completion Tokens": completion_tokens,
            })
    prompt_total = _numeric_score(token.get("prompt_tokens"), 0) if isinstance(token, dict) else 0
    completion_total = _numeric_score(token.get("completion_tokens"), 0) if isinstance(token, dict) else 0
    embedding_total = _numeric_score(token.get("embedding_tokens"), 0) if isinstance(token, dict) else 0
    if not rows:
        if prompt_total > 0 or completion_total > 0 or embedding_total > 0:
            st.info("Per-agent token telemetry was not reported. Showing aggregate runtime token breakdown instead.")
            total_df = pd.DataFrame([
                {"Token Type": "Prompt", "Tokens": prompt_total},
                {"Token Type": "Completion", "Tokens": completion_total},
                {"Token Type": "Embedding", "Tokens": embedding_total},
            ])
            fig = px.bar(total_df, x="Token Type", y="Tokens", text="Tokens", title="Runtime Token Consumption")
            fig.update_layout(height=320, margin=dict(l=10, r=10, t=45, b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Token telemetry is not available for this run.")
        return
    df = pd.DataFrame(rows)
    fig = px.bar(df, x="Agent", y=["Prompt Tokens", "Completion Tokens"], title="Token Consumption by Agent", barmode="stack")
    fig.update_layout(height=360, margin=dict(l=10, r=10, t=45, b=10), xaxis_tickangle=-25)
    st.plotly_chart(fig, use_container_width=True)


def _estimate_text_tokens(value):
    """Conservative token estimate for legacy traces that missed token telemetry."""
    if value is None:
        return 0
    text = str(value).strip()
    if not text:
        return 0
    return max(1, int(len(text) / 4))


def _estimate_legacy_llm_tokens(row, telemetry):
    prompt_text = (
        row.get("prompt")
        or row.get("user_prompt")
        or row.get("input")
        or telemetry.get("prompt")
        or telemetry.get("input")
        or ""
    )
    response_text = (
        row.get("response")
        or row.get("content")
        or row.get("output")
        or telemetry.get("response")
        or telemetry.get("content")
        or telemetry.get("output")
        or ""
    )
    input_tokens = _estimate_text_tokens(prompt_text)
    output_tokens = _estimate_text_tokens(response_text)
    if input_tokens or output_tokens:
        return input_tokens, output_tokens, input_tokens + output_tokens, "Estimated from captured prompt/response text"
    return 256, 128, 384, "Estimated fallback - token telemetry not attributed by this legacy trace"


def _cost_metric_label(key):
    labels = {
        "estimated_cost_usd": "Estimated Cost (USD)",
        "cost_per_1k_tokens": "Cost per 1K Tokens (USD)",
        "estimated_cost_saved": "Estimated Cost Saved (USD)",
        "model_cost_usd": "Model Cost (USD)",
        "total_cost_usd": "Total Cost (USD)",
    }
    key_text = str(key)
    if key_text in labels:
        return labels[key_text]
    label = key_text.replace("_", " ").title()
    if "cost" in key_text.casefold() and "usd" not in key_text.casefold():
        label = f"{label} (USD)"
    return label.replace("Usd", "USD")


def _llm_trace_rows_with_cost(result, token=None, cost=None):
    """Return LLM trace rows with per-agent estimated USD cost."""
    token = token if isinstance(token, dict) else {}
    cost = cost if isinstance(cost, dict) else {}
    llm_trace = result.get("llm_trace", [])
    rows = llm_trace if isinstance(llm_trace, list) else []
    rows = [row for row in rows if isinstance(row, dict)]
    if not rows:
        return []

    total_cost = _numeric_score(
        token.get("estimated_cost_usd", cost.get("estimated_cost_usd", result.get("estimated_cost_usd"))),
        0,
    )
    total_runtime_tokens = _numeric_score(token.get("total_tokens"), 0)
    if total_cost > 0 and total_runtime_tokens > 0:
        cost_per_token = total_cost / total_runtime_tokens
    else:
        cost_per_token = 0.005 / 1000

    for row in rows:
        telemetry = row.get("telemetry", {}) if isinstance(row.get("telemetry"), dict) else {}
        input_tokens = _numeric_score(
            row.get("input_tokens", row.get("prompt_tokens", telemetry.get("input_tokens", telemetry.get("prompt_tokens")))),
            0,
        )
        output_tokens = _numeric_score(
            row.get("output_tokens", row.get("completion_tokens", telemetry.get("output_tokens", telemetry.get("completion_tokens")))),
            0,
        )
        total_tokens = _numeric_score(row.get("total_tokens", telemetry.get("total_tokens")), input_tokens + output_tokens)
        basis = str(row.get("cost_basis") or telemetry.get("cost_basis") or "Token telemetry")
        if total_tokens <= 0:
            input_tokens, output_tokens, total_tokens, basis = _estimate_legacy_llm_tokens(row, telemetry)
        latency_ms = _numeric_score(row.get("latency_ms", telemetry.get("latency_ms")), 0)
        if total_tokens > 0:
            estimated_cost = total_tokens * cost_per_token
        else:
            estimated_cost = 0
            basis = "Not attributable - token telemetry not available"
        prepared_row = dict(row)
        prepared_row.update({
            "Agent": row.get("agent") or row.get("agent_name") or row.get("name") or "LLM Call",
            "Provider": row.get("provider", "-"),
            "Model": row.get("model", "-"),
            "Status": row.get("status", "-"),
            "Latency (ms)": int(latency_ms),
            "Input Tokens": int(input_tokens),
            "Output Tokens": int(output_tokens),
            "Total Tokens": int(total_tokens),
            "Estimated Cost (USD)": round(estimated_cost, 6),
            "Cost Basis": basis,
        })
        for key in ("agent", "agent_name", "name", "provider", "model", "status", "latency_ms", "input_tokens", "output_tokens", "prompt_tokens", "completion_tokens", "total_tokens"):
            prepared_row.pop(key, None)
        rows_to_show = prepared_row
        yield rows_to_show


def render_cache_business_impact_visual(result, cache):
    st.subheader("Cache Runtime Impact")
    agent_counts = _canonical_agent_counts(result)
    live_ms = int(_numeric_score(agent_counts.get("latency_ms"), 0))
    status = str(cache.get("status", "ANALYZED")).upper()
    runtime_hits = int(_numeric_score(cache.get("cache_hits"), 0))
    runtime_misses = int(_numeric_score(cache.get("cache_misses"), 0))
    avoided_or_next_ms = live_ms if status in {"HIT", "STORED"} else 0
    render_story_strip([
        {"eyebrow": "Current Run", "title": status, "detail": "Served from cache" if status == "HIT" else "Stored for next identical request", "state": "pass" if status in {"HIT", "STORED"} else "review"},
        {"eyebrow": "Live Execution", "title": _format_agent_latency(live_ms), "detail": "Observed full traversal time", "state": "review"},
        {"eyebrow": "Runtime Saving", "title": _format_agent_latency(avoided_or_next_ms), "detail": "Avoided this run" if status == "HIT" else "Expected full-result saving on repeat run", "state": "pass" if status in {"HIT", "STORED"} else "review"},
        {"eyebrow": "Full Result Reuse", "title": f"{cache.get('cache_hit_ratio', 0)}%", "detail": f"Runtime Hits/Misses: {runtime_hits} / {runtime_misses}", "state": "pass" if _numeric_score(cache.get("cache_hit_ratio"), 0) > 0 else "review"},
    ])


def render_evidence_coverage_map(result, evidence):
    st.subheader("Evidence Coverage Map")
    evidence = evidence if isinstance(evidence, dict) else {}
    evidence_pack = result.get("evidence_pack") or evidence.get("evidence_pack", [])
    chunks = result.get("retrieved_chunks", []) or []
    profile = _safe_dict(result.get("customer_profile"))
    checks = [
        ("Customer Profile", bool(profile), "Customer master record"),
        ("Accounts", _safe_count(result.get("accounts", [])) > 0, f"{_safe_count(result.get('accounts', []))} account record(s)"),
        ("Transactions", _safe_count(result.get("transactions", [])) > 0, f"{_safe_count(result.get('transactions', []))} transaction record(s)"),
        ("KYC / AML", bool(profile.get("kyc_status") or profile.get("aml_status") or result.get("kyc_status") or result.get("aml_status")), "Control status available"),
        ("Retrieved Evidence", len(chunks) > 0, f"{len(chunks)} retrieved chunk(s)"),
        ("Evidence Pack", len(evidence_pack or []) > 0, f"{len(evidence_pack or [])} evidence object(s)"),
    ]
    render_story_strip([
        {"eyebrow": "Covered" if ok else "Gap", "title": label, "detail": detail if ok else "Not available in this runtime", "state": "pass" if ok else "review"}
        for label, ok, detail in checks
    ])


def render_evidence_flow_explainer(result, evidence):
    evidence = evidence if isinstance(evidence, dict) else {}
    retrieved = _filter_customer_scoped_records(result.get("retrieved_chunks", []) or [], result.get("customer_id"))
    reranked = _safe_get(result, "reranking", {}).get("reranked_chunks", [])
    if not reranked:
        reranked = retrieved
    reranked = _filter_customer_scoped_records(reranked, result.get("customer_id"))
    final_pack = _filter_customer_scoped_records(result.get("evidence_pack") or evidence.get("evidence_pack", []) or [], result.get("customer_id"))
    if not final_pack:
        final_pack = reranked
    render_story_strip([
        {
            "eyebrow": "Stage 1",
            "title": f"{len(retrieved)} retrieved",
            "detail": "Customer-scoped candidates from authoritative records, BM25, semantic, or hybrid retrieval.",
            "state": "pass" if retrieved else "review",
        },
        {
            "eyebrow": "Stage 2",
            "title": f"{len(reranked)} reranked",
            "detail": "Candidates reordered by source authority, RRF/fusion, customer specificity, and reranker signals.",
            "state": "pass" if reranked else "review",
        },
        {
            "eyebrow": "Stage 3",
            "title": f"{len(final_pack)} final evidence",
            "detail": "Decision-grade evidence pack used by governance, trust, and recommendation logic.",
            "state": "pass" if final_pack else "review",
        },
    ])
    render_table(
        "Retrieved vs Reranked vs Final Evidence",
        [
            {
                "Stage": "Retrieved Candidates",
                "Count": len(retrieved),
                "Primary Question": "What evidence did the retrieval layer find?",
                "Score Used": "Score / retrieval contribution",
                "Governance Meaning": "Candidate pool only; not all candidates are equally decision-worthy.",
            },
            {
                "Stage": "Reranked Evidence",
                "Count": len(reranked),
                "Primary Question": "What should be read first?",
                "Score Used": "Rerank Score / RRF / source priority",
                "Governance Meaning": "Prioritized evidence ordered by relevance and authority signals.",
            },
            {
                "Stage": "Final Evidence Pack",
                "Count": len(final_pack),
                "Primary Question": "What evidence supports the governed decision?",
                "Score Used": "Evidence Trust plus lineage",
                "Governance Meaning": "Canonical evidence used by trust, grounding, recommendation, audit, and report exports.",
            },
        ],
    )
    st.caption(
        "Reranking transparency rule: retrieval score explains candidate discovery, rerank score explains read priority, and evidence trust explains source authority."
    )


def _evidence_item_source(item):
    if not isinstance(item, dict):
        return "-"
    metadata = item.get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    source = (
        item.get("source")
        or item.get("Source")
        or item.get("source_file")
        or item.get("file_name")
        or item.get("file")
        or metadata.get("source_file")
        or metadata.get("source")
        or metadata.get("file_name")
        or metadata.get("file")
    )
    if source not in (None, "", "-"):
        return source

    chunk_id = str(item.get("chunk_id") or item.get("Chunk ID") or item.get("id") or item.get("Evidence ID") or "").upper()
    runtime_source_map = {
        "RUNTIME_CUSTOMER": "external source system",
        "CUSTOMER_": "external source system",
        "RUNTIME_ACCOUNT": "accounts.csv",
        "ACCOUNT_": "accounts.csv",
        "RUNTIME_TRANSACTION": "transactions.csv",
        "TXN_": "transactions.csv",
        "RUNTIME_CARD": "cards.csv",
        "CARD_": "cards.csv",
        "RUNTIME_LOAN": "loans.csv",
        "LOAN_": "loans.csv",
        "RUNTIME_ALERT": "alerts.csv",
        "ALERT_": "alerts.csv",
        "RUNTIME_CASE": "cases.csv",
        "CASE_": "cases.csv",
        "RUNTIME_RISK": "risk_indicators.csv",
        "RISK_": "risk_indicators.csv",
    }
    for prefix, inferred_source in runtime_source_map.items():
        if chunk_id.startswith(prefix):
            return inferred_source

    text = _evidence_item_text(item)
    try:
        parsed = json.loads(text)
    except Exception:
        try:
            parsed = ast.literal_eval(text)
        except Exception:
            parsed = {}
    if isinstance(parsed, dict):
        if parsed.get("source") or parsed.get("source_file"):
            return parsed.get("source") or parsed.get("source_file")
        if "customer_id" in parsed and "txn_id" in parsed:
            return "transactions.csv"
        if "customer_id" in parsed and "account_id" in parsed:
            return "accounts.csv"
        if "customer_id" in parsed and "card_id" in parsed:
            return "cards.csv"
        if "customer_id" in parsed and "loan_id" in parsed:
            return "loans.csv"
        if "customer_id" in parsed and "alert_id" in parsed:
            return "alerts.csv"
        if "customer_id" in parsed and "case_id" in parsed:
            return "cases.csv"
        if "customer_id" in parsed and "customer_name" in parsed:
            return "external source system"

    text_upper = text.upper()
    if "TRANSACTION ID" in text_upper or "TXN_ID" in text_upper:
        return "transactions.csv"
    if "ACCOUNT ID" in text_upper or "ACCOUNT_ID" in text_upper:
        return "accounts.csv"
    if "CARD_ID" in text_upper or "CARD ID" in text_upper:
        return "cards.csv"
    if "CUSTOMER ID" in text_upper or "CUSTOMER_ID" in text_upper:
        return "external source system"
    return "Unresolved source"


def _evidence_lineage_key(item):
    if not isinstance(item, dict):
        return str(item)[:180]
    identity = (
        item.get("chunk_id")
        or item.get("id")
        or item.get("document_id")
        or item.get("txn_id")
        or item.get("account_id")
        or item.get("card_id")
        or item.get("loan_id")
    )
    if identity not in (None, "", "-"):
        return str(identity).strip().upper()
    return re.sub(r"\s+", " ", _evidence_item_text(item)).strip().upper()[:220]


def _evidence_source_lookup(result):
    lookup = {}
    sources = []
    reranking = _safe_dict(result.get("reranking"))
    for key in ("retrieved_chunks", "evidence_pack"):
        value = result.get(key)
        if isinstance(value, list):
            sources.extend(value)
    reranked = reranking.get("reranked_chunks")
    if isinstance(reranked, list):
        sources.extend(reranked)
    for item in sources:
        if not isinstance(item, dict):
            continue
        source = _evidence_item_source(item)
        if source in (None, "", "-", "Unresolved source"):
            continue
        lookup[_evidence_lineage_key(item)] = source
        text_key = re.sub(r"\s+", " ", _evidence_item_text(item)).strip().upper()[:220]
        if text_key:
            lookup[text_key] = source
    return lookup


def _evidence_item_text(item):
    if not isinstance(item, dict):
        return str(item)
    return str(
        item.get("text")
        or item.get("content")
        or item.get("Content")
        or item.get("chunk")
        or item.get("summary")
        or item.get("document")
        or item
    )


def _evidence_item_id(item, index):
    if not isinstance(item, dict):
        return f"Evidence {index}"
    return str(
        item.get("chunk_id")
        or item.get("Chunk ID")
        or item.get("id")
        or item.get("Evidence ID")
        or item.get("document_id")
        or item.get("txn_id")
        or item.get("account_id")
        or f"Evidence {index}"
    )


def _evidence_trust_value(item):
    if not isinstance(item, dict):
        return None
    metadata = item.get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}

    # Evidence trust is an authority/validation score, not the same as retrieval
    # similarity, rerank priority, or lineage flow weight.
    source = _evidence_item_source(item)
    chunk_id = str(item.get("chunk_id") or item.get("Chunk ID") or item.get("id") or item.get("Evidence ID") or "").upper()
    provenance = str(metadata.get("provenance") or item.get("provenance") or "").upper()
    if chunk_id.startswith("RUNTIME_") or provenance == "AUTHORITATIVE_CSV":
        return 100.0

    for key in ("evidence_trust", "Evidence Trust", "evidence_authority", "source_trust", "trust"):
        value = item.get(key)
        if value not in (None, "", "-"):
            return _bounded_score(value, 0)
    for key in ("evidence_trust", "evidence_authority", "source_trust", "trust"):
        value = metadata.get(key)
        if value not in (None, "", "-"):
            return _bounded_score(value, 0)

    raw_trust = item.get("trust_score", metadata.get("trust_score"))
    if raw_trust not in (None, "", "-"):
        raw_value = _bounded_score(raw_trust, 0)
        if raw_value >= 50:
            return raw_value

    # Some retrieved CSV chunks have low trust_score values that are retrieval
    # confidence/relevance artifacts. For customer-scoped CSV evidence, use a
    # stable source-authority floor instead of averaging those retrieval signals.
    if str(source).endswith(".csv"):
        return 70.0
    return None


def _evidence_trust_basis(item):
    if not isinstance(item, dict):
        return "-"
    metadata = item.get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    source = _evidence_item_source(item)
    chunk_id = str(item.get("chunk_id") or item.get("Chunk ID") or item.get("id") or item.get("Evidence ID") or "").upper()
    provenance = str(metadata.get("provenance") or item.get("provenance") or "").upper()
    if item.get("evidence_trust") not in (None, "", "-") or item.get("Evidence Trust") not in (None, "", "-") or metadata.get("evidence_trust") not in (None, "", "-"):
        return "Explicit evidence trust"
    if chunk_id.startswith("RUNTIME_") or provenance == "AUTHORITATIVE_CSV":
        return "Authoritative customer-scoped source"
    raw_trust = item.get("trust_score", metadata.get("trust_score"))
    if raw_trust not in (None, "", "-") and _bounded_score(raw_trust, 0) >= 50:
        return "Validated trust_score field"
    if str(source).endswith(".csv"):
        return "Customer-scoped CSV authority floor"
    return "No evidence trust signal"


def _evidence_display_rows(rows):
    display_rows = []
    for index, item in enumerate(rows or [], start=1):
        if not isinstance(item, dict):
            display_rows.append({"Rank": index, "Evidence Preview": str(item)})
            continue
        preview = _evidence_item_text(item)
        preview = " ".join(str(preview or "-").split())
        if len(preview) > 180:
            preview = preview[:177] + "..."
        display_rows.append({
            "Rank": item.get("rank", index),
            "Evidence ID": _evidence_item_id(item, index),
            "Source": _evidence_item_source(item),
            "Evidence Trust": _evidence_trust_value(item),
            "Trust Basis": _evidence_trust_basis(item),
            "Evidence Preview": preview,
        })
    return display_rows


def _raw_evidence_detail_rows(rows):
    detail_rows = []
    for index, item in enumerate(rows or [], start=1):
        if not isinstance(item, dict):
            detail_rows.append({"Rank": index, "Raw Evidence": str(item)})
            continue
        detail_rows.append({
            "Rank": item.get("rank", index),
            "Evidence ID": _evidence_item_id(item, index),
            "Retrieval Method": _retrieval_method_label(item),
            "Retrieval Score": item.get("score", item.get("similarity_score", item.get("retrieval_score", "-"))),
            "Rerank Score": item.get("rerank_score", item.get("cross_encoder_score", item.get("relevance_score", "-"))),
            "Raw Content": _evidence_item_text(item),
        })
    return detail_rows


def _canonical_evidence_metrics(result, evidence):
    evidence = evidence if isinstance(evidence, dict) else {}
    customer_id = result.get("customer_id")
    evidence_rows = _filter_customer_scoped_records(
        result.get("evidence_pack") or evidence.get("evidence_pack") or [],
        customer_id,
    )
    metric_source = "Final governed evidence pack"
    if not evidence_rows:
        evidence_rows = _filter_customer_scoped_records(result.get("retrieved_chunks") or [], customer_id)
        metric_source = "Retrieved chunks fallback"

    trust_values = [
        value for value in (_evidence_trust_value(item) for item in evidence_rows)
        if value is not None
    ]
    source_values = [
        _evidence_item_source(item)
        for item in evidence_rows
        if _evidence_item_source(item) not in (None, "", "-", "Unresolved source")
    ]
    return {
        "evidence_count": len(evidence_rows),
        "average_trust": round(sum(trust_values) / len(trust_values), 2) if trust_values else "-",
        "highest_trust": round(max(trust_values), 2) if trust_values else "-",
        "lowest_trust": round(min(trust_values), 2) if trust_values else "-",
        "sources": len(set(source_values)),
        "metric_source": metric_source,
    }


def _evidence_lineage_score(item):
    if not isinstance(item, dict):
        return 1
    return max(
        _numeric_score(item.get("rerank_score"), 0),
        _numeric_score(item.get("cross_encoder_score"), 0),
        _numeric_score(item.get("relevance_score"), 0),
        _numeric_score(item.get("score"), 0),
        _numeric_score(item.get("trust_score"), 0),
        _numeric_score(item.get("evidence_trust"), 0),
        1,
    )


def _evidence_lineage_method(item, source):
    method = _retrieval_method_label(item)
    if method and method != "-":
        return method
    if isinstance(item, dict):
        raw = (
            item.get("retrieval_method")
            or item.get("method")
            or item.get("retrieval_strategy")
            or item.get("retrieval_source")
        )
        if raw not in (None, "", "-"):
            raw_text = str(raw).upper()
            if "BM25" in raw_text and ("VECTOR" in raw_text or "SEMANTIC" in raw_text):
                return "Hybrid BM25 + Semantic Vector"
            if "BM25" in raw_text:
                return "BM25 keyword retrieval"
            if "VECTOR" in raw_text or "SEMANTIC" in raw_text:
                return "Semantic vector retrieval"
            if "AUTHORITATIVE" in raw_text:
                return "Authoritative CSV"
            return str(raw).replace("_", " ").title()
        chunk_id = str(item.get("chunk_id") or item.get("id") or "").upper()
        if chunk_id.startswith("RUNTIME_"):
            return "Authoritative CSV"
        if chunk_id.startswith(("TXN_", "ACCOUNT_", "CUSTOMER_", "CARD_", "LOAN_", "ALERT_", "CASE_")):
            return "Hybrid BM25 + Semantic Vector"
    if str(source).endswith(".csv"):
        return "Authoritative CSV"
    return "Retrieval method not captured"


def _short_lineage_label(value, limit=26):
    text = re.sub(r"\s+", " ", str(value or "-")).strip()
    if len(text) <= limit:
        return text
    return text[: max(8, limit - 3)].rstrip() + "..."


def render_evidence_lineage_graph(result, evidence):
    st.subheader("Evidence Lineage Graph")
    st.caption(
        "Trace how customer data and retrieved evidence flow into reranking, governance, and the final recommendation."
    )

    customer_id = result.get("customer_id") or _safe_get(result, "customer_profile", {}).get("customer_id") or "Customer"
    recommendation, risk_level = _runtime_recommendation_and_risk(result)
    compliance_status = _canonical_compliance_status(result)
    evidence_pack = result.get("evidence_pack") or _safe_get(evidence, "evidence_pack", []) or []
    retrieved = result.get("retrieved_chunks", []) or []
    reranked = _safe_get(result.get("reranking"), "reranked_chunks") or retrieved

    evidence_items = _filter_customer_scoped_records(evidence_pack or reranked or retrieved, customer_id) or []
    if not evidence_items:
        st.info("Evidence lineage will appear after customer-scoped evidence is retrieved or packaged.")
        return

    evidence_items = evidence_items[:18]
    selected_label = f"Evidence Set ({len(evidence_items)})"
    governance_label = "Governance"
    decision_label = "Decision"
    source_lookup = _evidence_source_lookup(result)
    source_nodes = []
    evidence_nodes = []
    source_to_evidence = []
    evidence_to_selection = []
    selection_to_decision = []
    lineage_rows = []

    for index, item in enumerate(evidence_items, start=1):
        source = str(
            source_lookup.get(_evidence_lineage_key(item))
            or source_lookup.get(re.sub(r"\s+", " ", _evidence_item_text(item)).strip().upper()[:220])
            or _evidence_item_source(item)
        )
        source_label = f"Source: {_short_lineage_label(source, 24)}"
        evidence_id = _evidence_item_id(item, index)
        evidence_label = f"E{index}"
        method = _evidence_lineage_method(item, source)
        score = _evidence_lineage_score(item)
        trust = (
            item.get("trust_score")
            if isinstance(item, dict) and item.get("trust_score") is not None
            else item.get("evidence_trust") if isinstance(item, dict) else "-"
        )
        if source_label not in source_nodes:
            source_nodes.append(source_label)
        evidence_nodes.append(evidence_label)
        source_to_evidence.append((source_label, evidence_label, max(score, 1), method))
        evidence_to_selection.append((evidence_label, selected_label, max(score, 1), method))
        selection_to_decision.append((selected_label, governance_label, max(score, 1), method))
        lineage_rows.append({
            "Rank": index,
            "Evidence ID": evidence_id,
            "Source": source,
            "Retrieval / Source Method": method,
            "Lineage Score": round(score, 4),
            "Evidence Trust": trust,
            "Decision Use": "Supports final governed recommendation",
            "Recommendation": recommendation,
            "Risk Level": risk_level,
            "Evidence Preview": _evidence_item_text(item)[:260],
        })

    labels = (
        [f"Customer: {_short_lineage_label(customer_id, 18)}"]
        + source_nodes
        + evidence_nodes
        + [
            selected_label,
            governance_label,
            decision_label,
        ]
    )
    label_index = {label: idx for idx, label in enumerate(labels)}

    links = []
    source_weight = max(1, sum(value for _, _, value, _ in source_to_evidence) / max(1, len(source_nodes)))
    for source_label in source_nodes:
        links.append((f"Customer: {_short_lineage_label(customer_id, 18)}", source_label, source_weight, "customer-scoped source"))
    links.extend(source_to_evidence)
    links.extend(evidence_to_selection)
    decision_weight = max(1, sum(value for _, _, value, _ in selection_to_decision) / max(1, len(selection_to_decision)))
    links.append((selected_label, governance_label, decision_weight, f"{len(evidence_items)} ranked evidence record(s)"))
    links.append((governance_label, decision_label, decision_weight, f"Decision {recommendation}; Risk {risk_level}; Compliance {compliance_status}"))

    node_colors = []
    for label in labels:
        if label.startswith("Customer:"):
            node_colors.append("#0b3a66")
        elif label.startswith("Source:"):
            node_colors.append("#175cd3")
        elif label.startswith("E"):
            node_colors.append("#21a67a")
        elif label == decision_label:
            node_colors.append("#007a5a" if recommendation == "APPROVE" else "#f79009")
        else:
            node_colors.append("#344054")

    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=18,
                    thickness=22,
                    line=dict(color="#d0d5dd", width=1),
                    label=labels,
                    color=node_colors,
                ),
                link=dict(
                    source=[label_index[src] for src, _, _, _ in links],
                    target=[label_index[dst] for _, dst, _, _ in links],
                    value=[max(1, float(value)) for _, _, value, _ in links],
                    color=["rgba(33, 166, 122, 0.22)" if "Evidence" in detail or "rank" in detail else "rgba(23, 92, 211, 0.18)" for _, _, _, detail in links],
                    customdata=[detail for _, _, _, detail in links],
                    hovertemplate="%{source.label} -> %{target.label}<br>Signal: %{customdata}<br>Weight: %{value}<extra></extra>",
                ),
            )
        ]
    )
    fig.update_layout(
        title="Customer Evidence Lineage: Sources -> Selected Evidence -> Decision",
        height=max(620, min(980, 48 * len(labels))),
        font=dict(size=16, color="#1d2939"),
        margin=dict(l=20, r=130, t=58, b=18),
    )
    st.plotly_chart(fig, use_container_width=True)

    unresolved_sources = sum(
        1 for row in lineage_rows
        if row.get("Source") in {"-", "", "Unresolved source"}
    )
    if unresolved_sources:
        st.warning(
            f"{unresolved_sources} selected evidence row(s) do not expose source metadata. "
            "AEGIS inferred sources where possible from chunk IDs and content; unresolved rows should be reviewed in the evidence table."
        )

    render_compact_status_grid([
        ("Customer", customer_id),
        ("Selected Evidence", len(evidence_items)),
        ("Source Files", len(source_nodes)),
        ("Decision", recommendation),
        ("Risk", risk_level),
        ("Compliance", compliance_status),
    ])
    render_table("Lineage Evidence Detail", lineage_rows)


def render_governance_control_ladder(result):
    st.subheader("Governance Control Ladder")
    recommendation = str(result.get("recommendation", "-")).upper()
    risk_level = str(result.get("risk_level") or _safe_get(result, "risk_authority", {}).get("risk_level") or _safe_get(result, "risk_authority", {}).get("level") or "-").upper()
    compliance_status = _canonical_compliance_status(result)
    review_risk_states = {"HIGH", "CRITICAL", "REVIEW", "REVIEW_REQUIRED", "INSUFFICIENT_EVIDENCE", "CUSTOMER_NOT_FOUND", "UNKNOWN", "-"}
    release_assessment = _governance_release_assessment(result)
    review_required = bool(release_assessment["review_required"])
    governance_status = release_assessment["governance_status"]
    release_route = release_assessment["release_route"]
    governance_detail = "HITL sign-off required" if review_required else "Auto-release eligible"
    release_detail = "Awaiting reviewer sign-off" if review_required else "Final governed recommendation"
    render_story_strip([
        {"eyebrow": "Risk Check", "title": risk_level, "detail": "Canonical risk authority", "state": "review" if risk_level in review_risk_states else "pass"},
        {"eyebrow": "Compliance", "title": compliance_status, "detail": "KYC/AML and policy controls", "state": "pass" if compliance_status == "COMPLIANT" else "review"},
        {"eyebrow": "Governance", "title": governance_status, "detail": governance_detail, "state": "pass" if governance_status == "PASS" else "review"},
        {"eyebrow": "Human Review", "title": "Required" if review_required else "Not Required", "detail": "HITL control", "state": "review" if review_required else "pass"},
        {"eyebrow": "Release Route", "title": release_route, "detail": release_detail, "state": "review" if review_required else "pass"},
    ])
    st.subheader("Human Review Decision Path")
    st.caption("Compact view of how governance conditions decide auto-release versus human approval.")
    dot = _build_governance_hitl_graphviz_dot(
        recommendation=recommendation,
        risk_level=risk_level,
        compliance_status=compliance_status,
        governance_status=governance_status,
        review_required=review_required,
    )
    st.graphviz_chart(dot, use_container_width=True)


def _build_governance_hitl_graphviz_dot(
    recommendation,
    risk_level,
    compliance_status,
    governance_status,
    review_required,
):
    release_label = "HITL Review" if review_required else "Auto Release"
    release_detail = "Reviewer sign-off required" if review_required else "Governed output returned"
    release_fill = "#2b2f42" if review_required else "#083b2f"
    release_border = "#98a2b3" if review_required else "#21d4a7"
    decision_label = "Pending HITL" if review_required else str(recommendation)
    decision_detail = "Awaiting sign-off" if review_required else "Released"
    return "\n".join([
        "digraph GovernanceHITL {",
        "rankdir=LR;",
        "graph [bgcolor=\"transparent\", pad=\"0.16\", nodesep=\"0.30\", ranksep=\"0.42\"];",
        "node [shape=box, style=\"rounded,filled\", fontname=\"Segoe UI\", fontsize=12, margin=\"0.12,0.08\", width=1.95, height=0.72, penwidth=1.8, fontcolor=\"white\"];",
        "edge [fontname=\"Segoe UI\", fontsize=10, color=\"#52a8ff\", fontcolor=\"#344054\", arrowsize=0.70, penwidth=1.7];",
        f'risk [label={_graphviz_html_label(["Risk Authority", str(risk_level)])}, fillcolor="#12395f", color="#52a8ff"];',
        f'compliance [label={_graphviz_html_label(["Compliance", str(compliance_status)])}, fillcolor="#12395f", color="#52a8ff"];',
        f'governance [label={_graphviz_html_label(["Governance Gate", str(governance_status)])}, fillcolor="#12395f", color="#52a8ff"];',
        f'hitl [label={_graphviz_html_label([release_label, release_detail])}, fillcolor="{release_fill}", color="{release_border}"];',
        f'decision [label={_graphviz_html_label(["Release Route", decision_label, decision_detail])}, fillcolor="{release_fill}", color="{release_border}"];',
        "risk -> governance [label=\"risk signal\"];",
        "compliance -> governance [label=\"policy signal\"];",
        "governance -> hitl [label=\"release control\"];",
        "hitl -> decision [label=\"sign-off pending\", color=\"#98a2b3\"];" if review_required else "hitl -> decision [label=\"released\"];",
        "}",
    ])


def render_audit_readiness_meter(result):
    st.subheader("Audit Readiness Meter")
    export = _safe_dict(result.get("artifact_export"))
    tests = _safe_dict(export.get("test_results"))
    checks = [
        ("Evidence Linked", _safe_count(result.get("evidence_pack", [])) > 0, f"{_safe_count(result.get('evidence_pack', []))} evidence object(s)"),
        ("Runtime Trace", _safe_count(result.get("agent_trace", [])) > 0, f"{_safe_count(result.get('agent_trace', []))} trace row(s)"),
        ("Compliance Reconciled", _canonical_compliance_status(result) not in {"", "UNKNOWN"}, _canonical_compliance_status(result)),
        ("Package Saved", export.get("status") == "SAVED", export.get("status", "-")),
        ("Invariant Tests", bool(tests.get("passed")), f"{tests.get('passed_count', 0)}/{tests.get('total', 0)} passed"),
    ]
    passed = sum(1 for _, ok, _ in checks if ok)
    readiness = round((passed / len(checks)) * 100, 1) if checks else 0
    st.progress(int(readiness), text=f"Audit readiness: {readiness}%")
    render_story_strip([
        {"eyebrow": "Ready" if ok else "Review", "title": label, "detail": detail, "state": "pass" if ok else "review"}
        for label, ok, detail in checks
    ])


def render_metric_row(metrics):

    cols = st.columns(len(metrics))

    for col, (title, value) in zip(cols, metrics.items()):

        col.metric(title, value)


# ============================================================
# Investigation
# ============================================================

def _runtime_query_pair(result):
    query_rewrite = result.get("query_rewrite", {})
    query_rewrite = query_rewrite if isinstance(query_rewrite, dict) else {}
    original_query = (
        result.get("original_query")
        or result.get("query")
        or query_rewrite.get("original_query")
        or ""
    )
    rewritten_query = (
        query_rewrite.get("rewritten_query")
        or result.get("rewritten_query")
        or result.get("updated_query")
        or result.get("decision_snapshot", {}).get("rewritten_query")
        or ""
    )
    return original_query, rewritten_query


def render_query_overview(result):
    st.header("User Query")
    st.caption("Pillar: Measurable AI | Audit anchor for this run")
    original_query, rewritten_query = _runtime_query_pair(result)
    c1, c2, c3 = st.columns(3)
    c1.metric("Customer", result.get("customer_id", "-"))
    c2.metric("Runtime", result.get("runtime_id", "-"))
    c3.metric(
        "Status",
        result.get("runtime_summary", {}).get("status")
        or result.get("runtime_health_v2", {}).get("execution_status")
        or result.get("runtime_status")
        or result.get("status", "-"),
    )
    q1, q2 = st.columns(2)
    with q1:
        st.text_area("Original User Query", value=original_query, height=110, disabled=True)
    with q2:
        st.text_area("Updated Query", value=rewritten_query, height=110, disabled=True)


def _runtime_cache_payload(result):
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    cache = (
        result.get("cache_lookup")
        or result.get("cache_runtime")
        or telemetry.get("cache_metrics")
        or result.get("cache_metrics")
        or {}
    )
    return cache if isinstance(cache, dict) else {}


def _canonical_display_payload(result):
    return service_canonical_display_payload(result)


def _cache_age_display(cache):
    if not isinstance(cache, dict):
        return "-"
    status = str(cache.get("status", "")).upper()
    if "age_seconds" in cache:
        age_seconds = int(_numeric_score(cache.get("age_seconds"), 0))
        if age_seconds <= 0 and status == "STORED":
            return "Just stored"
        return _format_agent_latency(age_seconds * 1000)
    if status == "STORED":
        return "Just stored"
    if status in {"MISS", "BYPASSED"}:
        return "No cached result"
    return "-"


def _cache_remaining_ttl_display(cache):
    if not isinstance(cache, dict):
        return "-"
    remaining = cache.get("remaining_ttl_seconds")
    ttl = cache.get("ttl_seconds")
    if remaining is not None:
        return _format_agent_latency(int(_numeric_score(remaining, 0)) * 1000)
    if str(cache.get("status", "")).upper() == "STORED" and ttl:
        return _format_agent_latency(int(_numeric_score(ttl, 0)) * 1000)
    return "-"


def _cache_miss_reason(cache, query_cache=None):
    cache = cache if isinstance(cache, dict) else {}
    query_cache = query_cache if isinstance(query_cache, dict) else {}
    status = str(cache.get("status", "")).upper()
    if status == "HIT":
        return "Full runtime result was reused; agent traversal and model calls were avoided."
    if status == "STORED":
        query_status = str(query_cache.get("status", "")).upper()
        if query_status == "HIT":
            return "Full runtime result was not available yet, but the query rewrite was reused from cache. This completed run is now stored for the next exact match."
        return "No completed full-runtime result existed for this exact customer, query, app version, data fingerprint, model version, and policy version; this fresh result was stored for reuse."
    if status == "EXPIRED":
        return "Matching runtime cache entry existed but exceeded its TTL."
    if status == "BYPASSED":
        return cache.get("reason", "Runtime cache was bypassed.")
    if status == "MISS":
        return "No exact full-runtime cache key matched this request. The cache requires the same customer, query, app version, data fingerprint, model version, and policy version."
    return "Cache lookup completed."


def _cache_layer_payload(result):
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    cache_metrics = (
        telemetry.get("cache_metrics")
        or result.get("cache_metrics")
        or {}
    )
    cache_metrics = cache_metrics if isinstance(cache_metrics, dict) else {}
    layers = cache_metrics.get("layers") or result.get("cache_layers") or {}
    return layers if isinstance(layers, dict) else {}


def _runtime_recommendation_and_risk(result):
    canonical = result.get("canonical_display")
    if isinstance(canonical, dict) and canonical:
        recommendation = canonical.get("recommendation")
        risk_level = canonical.get("risk_level")
        if recommendation and risk_level:
            return str(recommendation).upper(), str(risk_level).upper()
    runtime_health = (
        result.get("runtime_health_v2")
        or result.get("runtime_health")
        or _safe_get(result, "runtime_telemetry", {}).get("runtime_health")
        or {}
    )
    runtime_health = runtime_health if isinstance(runtime_health, dict) else {}
    recommendation = (
        result.get("recommendation")
        or _safe_get(result, "recommendation_package", {}).get("recommendation")
        or _safe_get(result, "decision_snapshot", {}).get("recommendation")
        or runtime_health.get("recommendation")
        or "REVIEW"
    )
    risk_level = (
        result.get("risk_level")
        or _safe_get(result, "risk_authority", {}).get("risk_level")
        or _safe_get(result, "recommendation_package", {}).get("risk_level")
        or _safe_get(result, "decision_snapshot", {}).get("risk_level")
        or "REVIEW"
    )
    return str(recommendation).upper(), str(risk_level).upper()


def _canonical_compliance_status(result):
    return service_canonical_compliance_status(result)


def _governance_release_assessment(result):
    """Display authority for whether this run is auto-release eligible and why."""
    return service_governance_release_assessment(result)


def _canonical_compliance_controls(result):
    recommendation, risk_level = _runtime_recommendation_and_risk(result)
    compliance_status = _canonical_compliance_status(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    quality = _canonical_quality_scores(result)
    release_assessment = _governance_release_assessment(result)
    review_required = bool(release_assessment["review_required"])
    rows = [
        {
            "Control": "Input Validation",
            "Status": "PASS",
            "Reason": "Customer ID and analyst query were accepted for runtime processing.",
        },
        {
            "Control": "Prompt Protection",
            "Status": "PASS",
            "Reason": "No prompt injection or blocked instruction was reported.",
        },
        {
            "Control": "Evidence Sufficiency",
            "Status": "REVIEW" if risk_level == "INSUFFICIENT_EVIDENCE" or evidence_count < 3 else "PASS",
            "Reason": f"{evidence_count} customer-scoped evidence object(s) available.",
        },
        {
            "Control": "Risk Authority",
            "Status": "REVIEW" if risk_level in {"INSUFFICIENT_EVIDENCE", "REVIEW_REQUIRED", "CUSTOMER_NOT_FOUND", "UNKNOWN", "HIGH", "CRITICAL"} else "PASS",
            "Reason": f"Canonical risk level is {risk_level}.",
        },
        {
            "Control": "Governance Decision",
            "Status": "REVIEW" if recommendation != "APPROVE" else "PASS",
            "Reason": f"Governed recommendation is {recommendation}.",
        },
        {
            "Control": "Trust Validation",
            "Status": "FAIL" if quality["trust_score"] < 50 else "REVIEW" if review_required else "PASS",
            "Reason": f"Canonical trust score is {quality['trust_score']:.1f}; human review required is {review_required}.",
        },
        {
            "Control": "Human Review",
            "Status": "REVIEW" if review_required else "PASS",
            "Reason": "Required for non-approval or insufficient-evidence decisions." if review_required else "Not required for auto-approval.",
        },
        {
            "Control": "Compliance Outcome",
            "Status": "PASS" if compliance_status == "COMPLIANT" else "REVIEW" if compliance_status == "REVIEW_REQUIRED" else "FAIL",
            "Reason": f"Canonical compliance status is {compliance_status}.",
        },
    ]
    return rows


def _canonical_object_audit_rows(result):
    rows = service_canonical_object_audit_rows(result)
    for row in rows:
        if row.get("Object") == "Total Execution Time Ms":
            row["Object"] = "Total Execution Time"
            row["Canonical Value"] = _format_agent_latency(row.get("Canonical Value"))
    return rows


def _canonical_consistency_audit_rows(result):
    """Detect stale projection values that disagree with the canonical runtime values."""
    return service_canonical_consistency_audit_rows(result)


def _clean_recommendation_key_factors(result, factors):
    cleaned = []
    compliance_status = _canonical_compliance_status(result)
    seen_compliance = False
    for factor in factors or []:
        text = str(factor)
        label = text.split(":", 1)[0].strip().casefold()
        if label in {"trust score", "confidence"}:
            continue
        if label == "compliance status":
            if not seen_compliance:
                cleaned.append(f"Compliance Status: {compliance_status}")
                seen_compliance = True
            continue
        cleaned.append(text)
    if not seen_compliance:
        cleaned.append(f"Compliance Status: {compliance_status}")
    return cleaned


def render_compact_status_grid(items):
    html_parts = ["<div class='compact-status-grid'>"]
    for label, value in items:
        html_parts.append(
            "<div class='compact-status-item'>"
            f"<span>{html.escape(str(label))}</span>"
            f"<strong>{html.escape(str(value))}</strong>"
            "</div>"
        )
    html_parts.append("</div>")
    st.markdown("".join(html_parts), unsafe_allow_html=True)


def render_story_strip(items):
    parts = ["<div class='story-strip'>"]
    for index, item in enumerate(items):
        if index > 0:
            parts.append("<div class='story-arrow' aria-hidden='true'></div>")
        state = str(item.get("state", "neutral")).lower()
        if state not in {"pass", "review", "fail"}:
            state = ""
        parts.append(
            f"<div class='story-card {state}'>"
            f"<span>{html.escape(str(item.get('eyebrow', '')))}</span>"
            f"<strong>{html.escape(str(item.get('title', '-')))}</strong>"
            f"<em>{html.escape(str(item.get('detail', '')))}</em>"
            "</div>"
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def _audit_ledger_table_counts(ledger, runtime_id=None):
    counts = _safe_dict(_safe_get(ledger, "table_counts"))
    if counts:
        return counts
    ledger_path = str(_safe_get(ledger, "path") or "").strip()
    if not ledger_path:
        return {}
    path = Path(ledger_path)
    if not path.is_file():
        return {}
    tables = (
        "audit_run",
        "audit_agent_execution",
        "audit_evidence",
        "audit_decision",
        "audit_consistency_check",
        "audit_cache_event",
        "audit_artifact",
    )
    try:
        with sqlite3.connect(path) as conn:
            for table in tables:
                if runtime_id:
                    counts[table] = conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE runtime_id = ?",
                        (str(runtime_id),),
                    ).fetchone()[0]
                else:
                    counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error:
        return {}
    return counts


def render_agent_brief(node):
    status = _agent_display_status(node)
    execution_time = _format_agent_latency(node.get("duration_ms")) if node.get("observed") else "-"
    order = node.get("execution_order") or "-"
    phase = node.get("phase", "-")
    tool = node.get("tool", "-")
    execution_count = int(_numeric_score(node.get("execution_count"), 1))
    if node.get("observed"):
        narrative = (
            f"{node.get('label', 'This agent')} completed the {phase} stage "
            f"in {execution_time}. It used {tool} and executed {execution_count} time(s)."
        )
    else:
        narrative = (
            f"{node.get('label', 'This agent')} was planned but did not execute. "
            f"Reason: {node.get('skip_reason') or 'Not required for this runtime path'}."
        )
    chips = [
        ("Status", status),
        ("Execution Time", execution_time),
        ("Phase", phase),
        ("Order", order),
    ]
    html_parts = [
        "<div class='agent-brief'>",
        f"<h4>{html.escape(str(node.get('label', 'Selected Agent')))}</h4>",
        f"<p>{html.escape(narrative)}</p>",
        "<div class='agent-brief-strip'>",
    ]
    for label, value in chips:
        html_parts.append(
            "<div class='agent-brief-chip'>"
            f"<span>{html.escape(str(label))}</span>"
            f"<strong>{html.escape(str(value))}</strong>"
            "</div>"
        )
    html_parts.append("</div></div>")
    st.markdown("".join(html_parts), unsafe_allow_html=True)


def render_executive_outcome_banner(result):
    st.header("Executive Outcome")
    cache = _runtime_cache_payload(result)
    canonical = _canonical_display_payload(result)
    recommendation = str(canonical.get("recommendation", "-")).upper()
    risk_level = str(canonical.get("risk_level", "-")).upper()
    evidence_count = canonical.get("evidence_count", 0)
    cache_status = str(cache.get("status", result.get("result_origin", "LIVE"))).upper()
    result_origin = str(result.get("result_origin") or ("RUNTIME_CACHE" if cache_status == "HIT" else "LIVE_EXECUTION")).upper()

    if recommendation in {"ESCALATE", "REJECT", "BLOCK"} or risk_level in {"HIGH", "CRITICAL"}:
        st.error(f"{recommendation} | Risk {risk_level} | Evidence {evidence_count} | {result_origin}")
    elif recommendation in {"MONITOR", "REVIEW"} or risk_level in {"MEDIUM", "REVIEW"}:
        st.warning(f"{recommendation} | Risk {risk_level} | Evidence {evidence_count} | {result_origin}")
    else:
        st.success(f"{recommendation} | Risk {risk_level} | Evidence {evidence_count} | {result_origin}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Board Decision", recommendation)
    c2.metric("Application Risk", risk_level)
    c3.metric("Evidence Strength", f"{evidence_count} sources")


def render_cache_roi_panel(result):
    st.header("Cache ROI")
    cache = _runtime_cache_payload(result)
    agent_counts = _canonical_agent_counts(result)
    total_execution_ms = int(_numeric_score(agent_counts.get("latency_ms"), 0))
    cache_status = str(cache.get("status", "ANALYZED")).upper()
    ttl_seconds = int(_numeric_score(cache.get("ttl_seconds"), 0))
    remaining_ttl = int(_numeric_score(cache.get("remaining_ttl_seconds"), 0))
    age_seconds = int(_numeric_score(cache.get("age_seconds"), 0))
    hit_ratio = _numeric_score(cache.get("cache_hit_ratio"), 0)
    cache_hits = int(_numeric_score(cache.get("cache_hits"), 0))
    cache_misses = int(_numeric_score(cache.get("cache_misses"), 0))

    saved_ms = total_execution_ms if cache_status == "HIT" else 0
    potential_saved_ms = total_execution_ms if cache_status != "HIT" and total_execution_ms else 0
    next_run_value = _format_agent_latency(saved_ms or potential_saved_ms)
    ttl_display = _format_agent_latency((remaining_ttl or ttl_seconds) * 1000) if (remaining_ttl or ttl_seconds) else "-"

    render_compact_status_grid([
        ("Cache Status", cache_status),
        ("Execution Time Avoided" if cache_status == "HIT" else "Next-Run Saving", next_run_value),
        ("Hit Ratio", f"{hit_ratio:.1f}%"),
        ("TTL Remaining", ttl_display),
        ("Hits / Misses", f"{cache_hits} / {cache_misses}"),
        ("Cached Result Age", _cache_age_display(cache)),
        ("Cache Entries", cache.get("entries", 0)),
        ("Result Mode", "Served from cache" if cache_status == "HIT" else "Stored for reuse"),
    ])

    if cache_status == "HIT":
        st.success("This run reused a completed runtime result, avoiding the full agent traversal and model calls.")
    elif cache_status == "STORED":
        st.info("This result has been stored in runtime cache. Re-running the same customer, investigation type, and analyst query should return from cache.")
    elif cache_status == "BYPASSED":
        st.warning(cache.get("reason", "Runtime cache was bypassed for this execution."))
    else:
        st.caption("Cache ROI appears after the runtime cache lookup or store operation completes.")


def render_executive_runtime_snapshot(result):
    st.header("Executive Runtime Snapshot")
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    agent_counts = _canonical_agent_counts(result)
    runtime_health = (
        result.get("runtime_health_v2")
        or result.get("runtime_health")
        or _safe_get(result, "runtime_telemetry", {}).get("runtime_health")
        or {}
    )
    runtime_health = runtime_health if isinstance(runtime_health, dict) else {}
    total_latency_ms = agent_counts["latency_ms"]
    token = (
        result.get("token_metrics")
        or telemetry.get("token_metrics")
        or {}
    )
    token = token if isinstance(token, dict) else {}
    canonical = _canonical_display_payload(result)

    render_compact_status_grid([
        ("Agents Executed", f"{agent_counts['executed']}/{agent_counts['total']}"),
        ("Execution Stages", agent_counts.get("execution_stages", 0)),
        ("Parallel Control Checks", agent_counts.get("parallel_control_checks", 0)),
        ("Observed Agent Handoffs", agent_counts.get("observed_handoffs", agent_counts.get("transitions", 0))),
        ("Total Execution Time", _format_agent_latency(total_latency_ms)),
        ("Avg Agent Time", _format_agent_latency(agent_counts["avg_latency_ms"])),
        ("Execution Checkpoints", f"{len(result.get('execution_timeline', []) or [])} logged"),
        ("Runtime Status", canonical.get("runtime_status") or runtime_health.get("status", result.get("status", "-"))),
        ("Current Phase", result.get("current_phase", "RUNTIME_COMPLETE")),
        ("Estimated Model Cost (USD)", canonical.get("estimated_cost_usd", token.get("estimated_cost_usd", 0))),
        ("Runtime Source", result.get("result_origin", "LIVE_EXECUTION")),
        ("Audit Package", _safe_get(result, "artifact_export", {}).get("status", "-")),
        ("Run ID", result.get("runtime_id", "-")),
    ])

    stage_rows = agent_counts.get("stage_breakdown") or []
    if stage_rows:
        render_table(
            "Stage-Aware Execution Model",
            [
                {
                    "Execution Stage": row.get("stage"),
                    "Executed Agents": row.get("executed"),
                    "Planned Agents": row.get("planned"),
                    "Parallel Interpretation": (
                        "Parallel/co-equal controls" if int(row.get("executed", 0) or 0) > 1
                        else "Sequential or single-control stage"
                    ),
                    "Agents": ", ".join(row.get("agents") or []),
                }
                for row in stage_rows
            ],
        )


def render_executive_positioning_panel(result):
    """Concise boardroom framing for what AEGIS is and why DBS should care."""
    st.header("Executive Positioning")
    st.markdown(
        """
        <div class="aegis-positioning-hero">
            <strong>AEGIS is the enterprise control plane for governing AI applications in production.</strong>
            <span>It does not replace Dify, Claude, OpenAI, Azure AI, LangChain, Bedrock, or custom AI apps. It standardizes their runtime telemetry and turns it into governance, observability, evidence, resilience, economics, and audit control.</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_story_strip([
        {
            "eyebrow": "Without AEGIS",
            "title": "Fragmented AI oversight",
            "detail": "Each app explains execution, evidence, risk, cost, and audit differently.",
            "state": "review",
        },
        {
            "eyebrow": "With AEGIS",
            "title": "Single control plane",
            "detail": "One canonical record for runtime, decision, evidence, cost, controls, and audit.",
            "state": "pass",
        },
        {
            "eyebrow": "DBS Outcome",
            "title": "Board-ready assurance",
            "detail": "Management can see whether AI is trustworthy, governable, measurable, scalable, resilient, and auditable.",
            "state": "pass",
        },
    ])

    render_compact_status_grid([
        ("Control Plane", "Govern AI apps without replacing them"),
        ("DBS Value", "Faster governance and audit readiness"),
        ("Runtime Mode", "Post-run, live monitoring, or pre-decision gate"),
        ("Canonical Output", "One decision record across UI, HTML, PDF, and audit"),
        ("Application Coverage", "LOB AI apps, GRC, audit, risk, technology"),
        ("Current Demo", "Customer 360 is a sample onboarded app"),
    ])


def render_enterprise_ai_control_pillars(result):
    """Boardroom-level framing for trust, governance, measurement, and scale."""
    st.header("Enterprise AI Control Tower Pillars")
    st.caption(
        "AEGIS is positioned as a governable AI runtime, not only a RAG workflow: "
        "it measures trust, enforces controls, observes execution, proves scalable reuse, and demonstrates operational resilience."
    )
    quality = _canonical_quality_scores(result)
    compliance_status = _canonical_compliance_status(result)
    recommendation = str(result.get("recommendation", "-")).upper()
    agent_counts = _canonical_agent_counts(result)
    cache = _runtime_cache_payload(result)
    retrieval_scope = _safe_dict(result.get("retrieval_scope"))
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))
    release_assessment = _governance_release_assessment(result)

    trust_state = "pass" if quality.get("trust_score", 0) >= 70 and str(quality.get("hallucination_risk", "")).upper() != "HIGH" else "review"
    governance_state = "pass" if release_assessment["release_allowed"] else "review"
    measurable_state = "pass" if agent_counts.get("executed", 0) > 0 and agent_counts.get("latency_ms", 0) > 0 else "review"
    scale_state = "pass" if str(cache.get("status", "")).upper() in {"HIT", "STORED"} else "review"
    runtime_status = str(result.get("runtime_status") or result.get("status") or "").upper()
    runtime_errors = result.get("runtime_errors", []) if isinstance(result.get("runtime_errors"), list) else []
    resilience_components = [
        100 if runtime_status == "COMPLETED" else 60,
        100 if _safe_get(result, "artifact_export", {}).get("status") else 65,
        100 if str(cache.get("status", "")).upper() in {"HIT", "STORED"} else 70,
        100 if not runtime_errors else 45,
        100 if release_assessment["release_allowed"] or compliance_status in {"COMPLIANT", "REVIEW_REQUIRED"} else 75,
    ]
    resilience_score = round(sum(resilience_components) / len(resilience_components), 1)
    resilience_state = "pass" if resilience_score >= 85 else "review"
    consistency_rows = _canonical_consistency_audit_rows(result)
    consistency_mismatches = [row for row in consistency_rows if row.get("Status") == "MISMATCH"]
    artifact_status = _safe_get(result, "artifact_export", {}).get("status")
    ledger_status = _safe_get(result, "artifact_export", {}).get("audit_ledger", {}).get("status")
    audit_components = [
        100 if artifact_status else 65,
        100 if ledger_status == "SAVED" else 70,
        100 if not consistency_mismatches else 45,
        100 if evidence_count > 0 else 60,
        100 if agent_counts.get("executed", 0) > 0 else 60,
    ]
    audit_score = round(sum(audit_components) / len(audit_components), 1)
    audit_state = "pass" if audit_score >= 85 else "review"
    trust_score = round(
        (
            _numeric_score(quality.get("trust_score"), 0) * 0.40
            + _numeric_score(quality.get("confidence"), 0) * 0.25
            + _numeric_score(quality.get("groundedness"), 0) * 0.25
            + (100 if str(quality.get("hallucination_risk", "")).upper() == "LOW" else 65) * 0.10
        ),
        1,
    )
    governance_score = round(
        (
            (100 if compliance_status == "COMPLIANT" else 65) * 0.35
            + (100 if recommendation == "APPROVE" else 70) * 0.30
            + (75 if release_assessment["review_required"] else 100) * 0.20
            + _numeric_score(_safe_get(result, "governance", {}).get("governance_score"), 90) * 0.15
        ),
        1,
    )
    measured_components = [
        100 if agent_counts.get("executed", 0) > 0 else 0,
        100 if agent_counts.get("transitions", 0) > 0 else 0,
        100 if evidence_count > 0 else 0,
        100 if _numeric_score(token.get("estimated_cost_usd"), 0) >= 0 else 0,
    ]
    measurement_score = round(sum(measured_components) / len(measured_components), 1)
    scale_score = round(
        (
            (100 if str(cache.get("status", "")).upper() == "HIT" else 80 if str(cache.get("status", "")).upper() == "STORED" else 55) * 0.45
            + (100 if cache.get("entries", 0) else 50) * 0.20
            + (100 if result.get("vector_index_cdc") else 70) * 0.20
            + (100 if _safe_get(result, "artifact_export", {}).get("status") else 65) * 0.15
        ),
        1,
    )

    render_story_strip([
        {
            "eyebrow": "Trustworthy AI",
            "title": f"Trust {quality.get('trust_score', 0):.1f}",
            "detail": f"Grounding {quality.get('groundedness', 0) or 0:.1f} | Hallucination {quality.get('hallucination_risk', '-')}",
            "state": trust_state,
        },
        {
            "eyebrow": "Governable AI",
            "title": compliance_status,
            "detail": f"Decision {recommendation} | Route {release_assessment['release_route']}",
            "state": governance_state,
        },
        {
            "eyebrow": "Measurable AI",
            "title": f"{agent_counts.get('executed', 0)}/{agent_counts.get('total', 0)} Agents",
            "detail": f"{_format_agent_latency(agent_counts.get('latency_ms', 0))} observed | {evidence_count} evidence rows",
            "state": measurable_state,
        },
        {
            "eyebrow": "Scalable AI",
            "title": str(cache.get("status", result.get("result_origin", "-"))).upper(),
            "detail": f"Cache entries {cache.get('entries', 0)} | Cost USD {token.get('estimated_cost_usd', 0)}",
            "state": scale_state,
        },
        {
            "eyebrow": "Resilient AI",
            "title": f"{resilience_score:.1f}",
            "detail": f"Recovery guards | Errors {len(runtime_errors)} | Audit {_safe_get(result, 'artifact_export', {}).get('status', '-')}",
            "state": resilience_state,
        },
        {
            "eyebrow": "Auditable AI",
            "title": f"{audit_score:.1f}",
            "detail": f"Ledger {ledger_status or '-'} | Mismatches {len(consistency_mismatches)}",
            "state": audit_state,
        },
    ])

    radar_labels = ["Trustworthy", "Governable", "Measurable", "Scalable", "Resilient", "Auditable"]
    radar_values = [trust_score, governance_score, measurement_score, scale_score, resilience_score, audit_score]
    radar = go.Figure()
    radar.add_trace(go.Scatterpolar(
        r=radar_values + [radar_values[0]],
        theta=radar_labels + [radar_labels[0]],
        fill="toself",
        name="AEGIS maturity",
        line=dict(color="#e31837", width=3),
        fillcolor="rgba(227, 24, 55, 0.18)",
        hovertemplate="%{theta}: %{r:.1f}<extra></extra>",
    ))
    radar.add_trace(go.Scatterpolar(
        r=[85, 85, 85, 85, 85, 85, 85],
        theta=radar_labels + [radar_labels[0]],
        mode="lines",
        name="Enterprise target",
        line=dict(color="#12395f", width=2, dash="dash"),
        hovertemplate="Enterprise target: %{r:.1f}<extra></extra>",
    ))
    radar.update_layout(
        title="Control Tower Maturity Radar",
        polar=dict(
            domain=dict(x=[0.12, 0.88], y=[0.16, 0.94]),
            radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(size=10)),
            angularaxis=dict(tickfont=dict(size=13)),
        ),
        height=560,
        margin=dict(l=80, r=80, t=78, b=96),
        legend=dict(orientation="h", yanchor="bottom", y=-0.06, xanchor="center", x=0.5),
    )
    st.plotly_chart(radar, use_container_width=True)

    render_reference_architecture_visual(
        title="AEGIS Reference Architecture",
        caption=(
            "Where the Control Tower fits: external AI apps emit standard telemetry; "
            "AEGIS governs, observes, measures, reuses, and audits the run."
        ),
        show_positioning=False,
    )

    render_table("Control Tower Capability Map", [
        {
            "Pillar": "Trustworthy",
            "What It Proves": "The answer is grounded, scored, and checked for hallucination risk.",
            "Runtime Signal": f"Trust {quality.get('trust_score', 0):.1f}; Confidence {quality.get('confidence', 0):.1f}; Coverage {quality.get('coverage', 0) or 0:.1f}",
        },
        {
            "Pillar": "Governable",
            "What It Proves": "AI output passes policy, compliance, risk, and human-review controls before presentation.",
            "Runtime Signal": f"Compliance {compliance_status}; Recommendation {recommendation}; Route {release_assessment['release_route']}",
        },
        {
            "Pillar": "Measurable",
            "What It Proves": "Every agent execution, transition, evidence object, cost, and timing signal is observable.",
            "Runtime Signal": f"{agent_counts.get('execution_stages', 0)} stages; {agent_counts.get('parallel_control_checks', 0)} parallel checks; {_format_agent_latency(agent_counts.get('latency_ms', 0))}; retrieval {retrieval_scope.get('source', '-')}",
        },
        {
            "Pillar": "Scalable",
            "What It Proves": "The platform can reuse runtime results, query/retrieval cache, vector CDC, and audit packages.",
            "Runtime Signal": f"Cache {cache.get('status', '-')}; TTL {cache.get('ttl_seconds', '-')}; entries {cache.get('entries', 0)}",
        },
        {
            "Pillar": "Resilient",
            "What It Proves": "The runtime can complete safely, preserve audit evidence, tolerate misses/skips, and route uncertainty to review instead of failing silently.",
            "Runtime Signal": f"Status {runtime_status}; Runtime errors {len(runtime_errors)}; Audit {_safe_get(result, 'artifact_export', {}).get('status', '-')}",
        },
        {
            "Pillar": "Auditable",
            "What It Proves": "The run is retained as searchable ledger records plus portable PDF/HTML/JSON/CSV evidence artifacts.",
            "Runtime Signal": f"Artifacts {artifact_status or '-'}; Ledger {ledger_status or '-'}; Consistency mismatches {len(consistency_mismatches)}",
        },
    ])


def render_pillar_coverage(pillars, message):
    """Small executive signpost showing which AEGIS pillars a tab proves."""
    chips = "".join(
        f"<span class='pillar-chip'>{html.escape(str(pillar))}</span>"
        for pillar in pillars
    )
    st.markdown(
        f"""
        <div class="pillar-coverage">
            <div>{chips}</div>
            <p>{html.escape(str(message))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _six_pillar_visual_model(result):
    """Return one derived six-pillar model for Streamlit visuals.

    The values are intentionally derived from canonical runtime fields so the
    pillar tab remains an executive lens, not a second source of truth.
    """
    quality = _canonical_quality_scores(result)
    compliance_status = _canonical_compliance_status(result)
    recommendation = str(result.get("recommendation", "-")).upper()
    agent_counts = _canonical_agent_counts(result)
    cache = _runtime_cache_payload(result)
    token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    runtime_status = str(result.get("runtime_status") or result.get("status") or "").upper()
    runtime_errors = result.get("runtime_errors", []) if isinstance(result.get("runtime_errors"), list) else []
    release_assessment = _governance_release_assessment(result)
    consistency_rows = _canonical_consistency_audit_rows(result)
    consistency_mismatches = [row for row in consistency_rows if row.get("Status") == "MISMATCH"]
    artifact_status = _safe_get(result, "artifact_export", {}).get("status")
    ledger_status = _safe_get(result, "artifact_export", {}).get("audit_ledger", {}).get("status")

    trustworthy_components = [
        (_numeric_score(quality.get("trust_score"), 0), 0.40),
        (_numeric_score(quality.get("confidence"), 0), 0.25),
    ]
    if not _is_unknown_value(quality.get("groundedness")):
        trustworthy_components.append((_numeric_score(quality.get("groundedness"), 0), 0.25))
    hallucination_label = str(quality.get("hallucination_risk", "")).upper()
    if hallucination_label not in {"", "-", "UNKNOWN", "N/A", "NONE", "NULL"}:
        trustworthy_components.append(((100 if hallucination_label == "LOW" else 65), 0.10))
    trust_weight = sum(weight for _, weight in trustworthy_components) or 1
    trust_score = round(sum(score * weight for score, weight in trustworthy_components) / trust_weight, 1)
    trustworthy_formula_parts = [
        f"Trust {quality.get('trust_score', 0):.1f} x 40%",
        f"Confidence {quality.get('confidence', 0):.1f} x 25%",
    ]
    missing_trustworthy = []
    if not _is_unknown_value(quality.get("groundedness")):
        trustworthy_formula_parts.append(f"Grounding {_numeric_score(quality.get('groundedness'), 0):.1f} x 25%")
    else:
        missing_trustworthy.append("groundedness")
    if hallucination_label not in {"", "-", "UNKNOWN", "N/A", "NONE", "NULL"}:
        trustworthy_formula_parts.append(f"Hallucination control {(100 if hallucination_label == 'LOW' else 65):.1f} x 10%")
    else:
        missing_trustworthy.append("hallucination_risk")
    trustworthy_calculation = (
        f"Formula: ({' + '.join(trustworthy_formula_parts)}) / {trust_weight:.2f}. "
        f"Missing not scored: {', '.join(missing_trustworthy) if missing_trustworthy else 'none'}."
    )
    governance_score = round(
        (100 if compliance_status == "COMPLIANT" else 65) * 0.35
        + (100 if recommendation == "APPROVE" else 70) * 0.30
        + (75 if release_assessment["review_required"] else 100) * 0.20
        + _numeric_score(_safe_get(result, "governance", {}).get("governance_score"), 90) * 0.15,
        1,
    )
    measured_components = [
        100 if agent_counts.get("executed", 0) > 0 else 0,
        100 if agent_counts.get("transitions", 0) > 0 else 0,
        100 if evidence_count > 0 else 0,
        100 if _numeric_score(token.get("estimated_cost_usd"), 0) >= 0 else 0,
    ]
    measurement_score = round(sum(measured_components) / len(measured_components), 1)
    cache_status = str(cache.get("status", "")).upper()
    cache_component = 100 if cache_status == "HIT" else 80 if cache_status == "STORED" else 55
    cache_entries_component = 100 if cache.get("entries", 0) else 50
    vector_component = 100 if result.get("vector_index_cdc") else 70
    artifact_component = 100 if artifact_status else 65
    scale_score = round(
        cache_component * 0.45
        + cache_entries_component * 0.20
        + vector_component * 0.20
        + artifact_component * 0.15,
        1,
    )
    scalable_calculation = (
        f"Formula: Cache {cache_component} x 45% + Entries {cache_entries_component} x 20% + "
        f"Vector/CDC {vector_component} x 20% + Artifact {artifact_component} x 15%."
    )
    resilience_components = [
        100 if runtime_status == "COMPLETED" else 60,
        100 if artifact_status else 65,
        100 if str(cache.get("status", "")).upper() in {"HIT", "STORED"} else 70,
        100 if not runtime_errors else 45,
        100 if release_assessment["release_allowed"] or compliance_status in {"COMPLIANT", "REVIEW_REQUIRED"} else 75,
    ]
    resilience_score = round(sum(resilience_components) / len(resilience_components), 1)
    audit_components = [
        100 if artifact_status else 65,
        100 if ledger_status == "SAVED" else 70,
        100 if not consistency_mismatches else 45,
        100 if evidence_count > 0 else 60,
        100 if agent_counts.get("executed", 0) > 0 else 60,
    ]
    audit_score = round(sum(audit_components) / len(audit_components), 1)
    auditable_calculation = (
        f"Formula: Artifact {audit_components[0]}, Ledger {audit_components[1]}, "
        f"Consistency {audit_components[2]}, Evidence {audit_components[3]}, Agents {audit_components[4]} average. "
        f"Mismatch source: canonical_consistency_audit has {len(consistency_mismatches)} mismatch row(s)."
    )

    return [
        {
            "Pillar": "Trustworthy AI",
            "Short Label": "Trustworthy",
            "Score": trust_score,
            "Signal": (
                f"Trust {quality.get('trust_score', 0):.1f}; Confidence {quality.get('confidence', 0):.1f}; "
                f"Hallucination {quality.get('hallucination_risk', '-')}. {trustworthy_calculation}"
            ),
            "State": "pass" if trust_score >= 80 else "review",
            "Tabs": "Evidence, Retrieval, OWASP AI, LLM Judge",
        },
        {
            "Pillar": "Governable AI",
            "Short Label": "Governable",
            "Score": governance_score,
            "Signal": f"Compliance {compliance_status}; Decision {recommendation}; Route {release_assessment['release_route']}",
            "State": "pass" if governance_score >= 80 else "review",
            "Tabs": "Risk/Governance, OWASP AI, Auditability",
        },
        {
            "Pillar": "Measurable AI",
            "Short Label": "Measurable",
            "Score": measurement_score,
            "Signal": f"{agent_counts.get('executed', 0)}/{agent_counts.get('total', 0)} agents; {evidence_count} evidence; cost USD {token.get('estimated_cost_usd', 0)}",
            "State": "pass" if measurement_score >= 80 else "review",
            "Tabs": "Runtime Observability, Agents, Cost",
        },
        {
            "Pillar": "Scalable AI",
            "Short Label": "Scalable",
            "Score": scale_score,
            "Signal": f"Cache {cache.get('status', '-')}; entries {cache.get('entries', 0)}; onboarding contract. {scalable_calculation}",
            "State": "pass" if scale_score >= 80 else "review",
            "Tabs": "Cache, Asset Registry, Onboarding",
        },
        {
            "Pillar": "Resilient AI",
            "Short Label": "Resilient",
            "Score": resilience_score,
            "Signal": f"Runtime {runtime_status}; errors {len(runtime_errors)}; fallback/alerts",
            "State": "pass" if resilience_score >= 80 else "review",
            "Tabs": "Alerts, Runtime Observability, Agents",
        },
        {
            "Pillar": "Auditable AI",
            "Short Label": "Auditable",
            "Score": audit_score,
            "Signal": f"Artifacts {artifact_status or '-'}; ledger {ledger_status or '-'}; mismatches {len(consistency_mismatches)}. {auditable_calculation}",
            "State": "pass" if audit_score >= 80 else "review",
            "Tabs": "Auditability, Audit Package, Evidence",
        },
    ]


def render_six_pillar_visuals(result):
    """Render board-friendly visuals for the six-pillar control model."""
    rows = _six_pillar_visual_model(result)
    render_story_strip([
        {
            "eyebrow": row["Pillar"],
            "title": f"{row['Score']:.1f}",
            "detail": row["Signal"],
            "state": row["State"],
        }
        for row in rows
    ])

    labels = [row["Short Label"] for row in rows]
    values = [row["Score"] for row in rows]
    radar = go.Figure()
    radar.add_trace(go.Scatterpolar(
        r=values + [values[0]],
        theta=labels + [labels[0]],
        fill="toself",
        name="AEGIS maturity",
        line=dict(color="#e31837", width=3),
        fillcolor="rgba(227, 24, 55, 0.18)",
        hovertemplate="%{theta}: %{r:.1f}<extra></extra>",
    ))
    radar.add_trace(go.Scatterpolar(
        r=[85] * 7,
        theta=labels + [labels[0]],
        mode="lines",
        name="Enterprise target",
        line=dict(color="#12395f", width=2, dash="dash"),
        hovertemplate="Enterprise target: %{r:.1f}<extra></extra>",
    ))
    radar.update_layout(
        title="Six Pillar Maturity Radar",
        polar=dict(
            domain=dict(x=[0.12, 0.88], y=[0.16, 0.94]),
            radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(size=10)),
            angularaxis=dict(tickfont=dict(size=13)),
        ),
        height=540,
        margin=dict(l=80, r=80, t=78, b=96),
        legend=dict(orientation="h", yanchor="bottom", y=-0.06, xanchor="center", x=0.5),
    )
    st.plotly_chart(radar, use_container_width=True)

    render_story_strip([
        {"eyebrow": "1. AI App Runtime", "title": "Signals emitted", "detail": "Agents, tools, prompts, evidence, tokens, errors", "state": "pass"},
        {"eyebrow": "2. Canonical Record", "title": "Normalized", "detail": "One source for trust, risk, decision, cost, evidence", "state": "pass"},
        {"eyebrow": "3. Six Pillar Scoring", "title": "Assessed", "detail": "Trust, governance, measurement, scale, resilience, audit", "state": "pass"},
        {"eyebrow": "4. Governed Output", "title": str(result.get("recommendation", "-")).upper(), "detail": "Decision, rationale, HITL, audit package", "state": "pass"},
    ])

    coverage_columns = ["Runtime", "Evidence", "OWASP", "LLM Judge", "Cache", "Cost", "Alerts", "Audit"]
    coverage = {
        "Trustworthy AI": [1, 1, 1, 1, 0, 0, 0, 1],
        "Governable AI": [1, 1, 1, 1, 0, 0, 1, 1],
        "Measurable AI": [1, 1, 0, 0, 1, 1, 0, 1],
        "Scalable AI": [1, 0, 0, 0, 1, 1, 0, 1],
        "Resilient AI": [1, 0, 1, 1, 1, 0, 1, 1],
        "Auditable AI": [1, 1, 1, 1, 1, 1, 1, 1],
    }
    heatmap = go.Figure(data=go.Heatmap(
        z=list(coverage.values()),
        x=coverage_columns,
        y=list(coverage.keys()),
        colorscale=[[0, "#f2f4f7"], [1, "#11845b"]],
        showscale=False,
        text=[["Covered" if value else "N/A" for value in row] for row in coverage.values()],
        texttemplate="%{text}",
        hovertemplate="Pillar=%{y}<br>Control=%{x}<br>Status=%{text}<extra></extra>",
    ))
    heatmap.update_layout(
        title="Control Coverage Heatmap",
        height=380,
        margin=dict(l=20, r=20, t=60, b=30),
        xaxis=dict(tickfont=dict(size=12)),
        yaxis=dict(tickfont=dict(size=12)),
    )
    st.plotly_chart(heatmap, use_container_width=True)
    st.info(
        "This heatmap shows which AEGIS control capabilities contribute to each enterprise AI governance pillar. "
        "N/A means the control is not directly applicable to that pillar, not a missing feature."
    )

    render_table("Pillar Score Formula Summary", [
        {
            "Pillar": row["Pillar"],
            "Score": f"{row['Score']:.1f}",
            "Derived From": row["Signal"],
            "Primary UI Evidence": row["Tabs"],
        }
        for row in rows
    ])


def render_six_pillar_control_view(result):
    """Executive crosswalk from functional tabs to the six AEGIS control pillars."""
    st.header("Six Pillar Control View")
    st.caption(
        "This view maps every functional dashboard area to the six AEGIS enterprise AI control pillars."
    )
    quality = _canonical_quality_scores(result)
    compliance_status = _canonical_compliance_status(result)
    agent_counts = _canonical_agent_counts(result)
    cache = _runtime_cache_payload(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))
    artifact_status = _safe_get(result, "artifact_export", {}).get("status", "-")
    runtime_errors = result.get("runtime_errors", []) if isinstance(result.get("runtime_errors"), list) else []

    render_six_pillar_visuals(result)

    render_table("Pillar To Dashboard Coverage", [
        {
            "AEGIS Pillar": "Trustworthy AI",
            "Primary Tabs": "Evidence, Retrieval, OWASP AI, Risk/Governance",
            "What It Proves": "Outputs are grounded, evidence-backed, checked for hallucination risk, and supported by traceable evidence.",
        },
        {
            "AEGIS Pillar": "Governable AI",
            "Primary Tabs": "Risk, Governance & Decisioning, OWASP AI, Auditability",
            "What It Proves": "Policy, compliance, human-review, risk, and security controls are applied before a decision is accepted.",
        },
        {
            "AEGIS Pillar": "Measurable AI",
            "Primary Tabs": "Runtime Observability, Agents, Model Cost & Token Economics",
            "What It Proves": "Execution time, agent status, observed handoffs, execution stages, parallel controls, model cost, tokens, and runtime health are observable.",
        },
        {
            "AEGIS Pillar": "Scalable AI",
            "Primary Tabs": "Cache Acceleration, AI Asset Registry, Application Onboarding Contract",
            "What It Proves": "Repeated workloads can reuse cache, onboard consistently, and be governed through reusable platform assets.",
        },
        {
            "AEGIS Pillar": "Resilient AI",
            "Primary Tabs": "Alerts & Notifications, Runtime Observability, Agents",
            "What It Proves": "Failures, latency spikes, skipped branches, fallback needs, and alert conditions are visible.",
        },
        {
            "AEGIS Pillar": "Auditable AI",
            "Primary Tabs": "Auditability, Audit & Evidence Package, Evidence",
            "What It Proves": "The run produces portable audit records, evidence lineage, consistency checks, and artifact history.",
        },
    ])


def render_dbs_value_add(result):
    """DBS-specific executive value view for leadership demos."""
    st.header("DBS Value Add")
    st.caption(
        "How AEGIS translates runtime telemetry, governance, evidence, resilience, cost, and audit records "
        "into practical enterprise value for DBS."
    )
    quality = _canonical_quality_scores(result)
    agent_counts = _canonical_agent_counts(result)
    cache = _runtime_cache_payload(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))

    render_story_strip([
        {
            "eyebrow": "Governance",
            "title": "One control plane",
            "detail": "Standardizes controls across AI apps built in Dify, Claude, OpenAI, Azure, Bedrock, LangChain, or custom stacks.",
            "state": "pass",
        },
        {
            "eyebrow": "Observability",
            "title": f"{agent_counts.get('executed', 0)} agents observed",
            "detail": "Shows execution path, skipped branches, slow stages, runtime events, and control-plane validation.",
            "state": "pass",
        },
        {
            "eyebrow": "Evidence",
            "title": f"{evidence_count} evidence rows",
            "detail": "Links retrieved and reranked evidence to the governed recommendation and audit package.",
            "state": "pass",
        },
        {
            "eyebrow": "Economics",
            "title": f"USD {token.get('estimated_cost_usd', 0)}",
            "detail": f"Cost visibility plus cache status {str(cache.get('status', '-')).upper()} for repeatable workloads.",
            "state": "pass" if str(cache.get("status", "")).upper() in {"HIT", "STORED"} else "review",
        },
    ])

    render_table("DBS Value Add", [
        {
            "Value Lever": "Single AI governance control tower",
            "What DBS Gets": "One board-ready view across app runtime, controls, evidence, economics, resilience, and audit.",
            "AEGIS Capability": "Six-pillar control model, canonical runtime state, governance center.",
            "Executive Outcome": "Fewer fragmented AI dashboards and clearer ownership.",
        },
        {
            "Value Lever": "Faster risk and governance review",
            "What DBS Gets": "Risk, compliance, HITL, OWASP AI, and evidence checks visible in one run package.",
            "AEGIS Capability": "Risk, Governance & Decisioning, OWASP AI, Score Explainability, Evidence Lineage.",
            "Executive Outcome": "Shorter review cycles with stronger traceability.",
        },
        {
            "Value Lever": "Operational resilience",
            "What DBS Gets": "Slow agents, failed controls, retries, skipped paths, and notification triggers become visible.",
            "AEGIS Capability": "Runtime Observability, Alerts & Notifications, Agent Trace, Execution Graph.",
            "Executive Outcome": "Issues can be detected before they become leadership escalations.",
        },
        {
            "Value Lever": "Auditability and regulatory traceability",
            "What DBS Gets": "HTML, PDF, JSON, CSV, evidence pack, runtime checks, and artifact manifest.",
            "AEGIS Capability": "Auditability and Audit & Evidence Package.",
            "Executive Outcome": "A portable evidence pack for risk, audit, and technology review.",
        },
        {
            "Value Lever": "Reusable onboarding pattern",
            "What DBS Gets": "Any AI app can onboard by emitting standard runtime events and a final canonical decision record.",
            "AEGIS Capability": "Application Onboarding Contract, AI Asset Registry, canonical data enforcement.",
            "Executive Outcome": "Control tower scales beyond this Customer 360 demo.",
        },
    ])


def _build_llm_judge_graphviz_dot(result, assurance):
    """Graph view for the AEGIS LLM-as-Judge assurance layer."""
    verdict = str(assurance.get("final_verdict", "-")).upper()
    provider = "-"
    engine = "-"
    verdicts = assurance.get("judge_verdicts", []) if isinstance(assurance.get("judge_verdicts"), list) else []
    if verdicts:
        final_row = next(
            (
                row for row in verdicts
                if isinstance(row, dict) and str(row.get("judge_name", "")).casefold().startswith("final")
            ),
            verdicts[-1] if isinstance(verdicts[-1], dict) else {},
        )
        provider = final_row.get("provider") or assurance.get("provider") or "-"
        engine = final_row.get("engine") or assurance.get("engine") or "-"
    release_assessment = _governance_release_assessment(result)
    hitl = "YES" if release_assessment["review_required"] else "NO"
    recommendation = str(result.get("recommendation", "-")).upper()
    risk_level = str(result.get("risk_level") or _safe_get(result, "risk_authority", {}).get("risk_level") or "-").upper()

    nodes = [
        ("app_output", ["App Output", "Decision + evidence"], "#063d32", "#21d4a7"),
        ("rubrics", ["Rubrics", "Grounding | OWASP | Evidence"], "#12395f", "#52a8ff"),
        ("provider", ["Provider", f"{provider}", f"{engine}"], "#12395f", "#52a8ff"),
        ("committee", ["Judge Committee", "Security | Risk | Quality"], "#12395f", "#52a8ff"),
        ("gate", ["Control Gate", f"{verdict} | HITL {hitl}", release_assessment["release_route"]], "#12395f", "#52a8ff"),
        ("audit", ["Audit", "Verdict ledger"], "#083b2f", "#21d4a7"),
    ]
    lines = [
        "digraph LLMJudge {",
        "rankdir=LR;",
        "graph [bgcolor=\"transparent\", pad=\"0.15\", nodesep=\"0.28\", ranksep=\"0.38\"];",
        "node [shape=box, style=\"rounded,filled\", fontname=\"Segoe UI\", fontsize=13, margin=\"0.10,0.07\", width=1.75, height=0.62, penwidth=1.8, fontcolor=\"white\"];",
        "edge [fontname=\"Segoe UI\", fontsize=10, color=\"#52a8ff\", fontcolor=\"#344054\", arrowsize=0.65, penwidth=1.6];",
    ]
    for node_id, label_lines, fill, border in nodes:
        lines.append(
            f'{node_id} [label={_graphviz_html_label(label_lines)}, fillcolor="{fill}", color="{border}"];'
        )
    edges = [
        ("app_output", "rubrics", "canonical"),
        ("rubrics", "provider", "select"),
        ("provider", "committee", "judge"),
        ("committee", "gate", "verdict"),
        ("gate", "audit", "persist"),
    ]
    for source, target, label in edges:
        lines.append(f'{source} -> {target} [label="{_graphviz_escape(label)}"];')
    lines.append("}")
    return "\n".join(lines)


def render_llm_judge_assurance(result):
    """LLM-as-judge and assurance roadmap view for enterprise demos."""
    st.header("LLM Judge & Assurance")
    st.caption(
        "Production assurance layer for AI output validation: independent judge contract, deterministic fallback, "
        "rubrics, adversarial checks, human review, model risk, resilience controls, and persisted audit records."
    )
    assurance = get_llm_judge_assurance(result)
    verdicts = assurance.get("judge_verdicts", []) if isinstance(assurance.get("judge_verdicts"), list) else []
    rubrics = assurance.get("rubric_registry", []) if isinstance(assurance.get("rubric_registry"), list) else []
    committee = assurance.get("committee_roles", []) if isinstance(assurance.get("committee_roles"), list) else []
    adversarial = assurance.get("adversarial_tests", []) if isinstance(assurance.get("adversarial_tests"), list) else []
    model_risk = assurance.get("model_risk_management", []) if isinstance(assurance.get("model_risk_management"), list) else []
    resilience = assurance.get("resilience_controls", []) if isinstance(assurance.get("resilience_controls"), list) else []
    runtime_errors = result.get("runtime_errors", []) if isinstance(result.get("runtime_errors"), list) else []
    release_assessment = _governance_release_assessment(result)
    hitl_required = bool(release_assessment["review_required"])
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
    final_judge = next(
        (
            row for row in judge_rows
            if str(row.get("Judge") or "").casefold().startswith("final")
        ),
        judge_rows[-1] if judge_rows else {},
    )
    final_provider = final_judge.get("Provider") or assurance.get("provider") or "-"
    final_engine = final_judge.get("Engine") or assurance.get("engine") or "-"

    render_story_strip([
        {
            "eyebrow": "Current Build",
            "title": assurance.get("judge_mode", "Judge assurance"),
            "detail": f"Trace {assurance.get('trace_id', '-')}; verdict {assurance.get('final_verdict', '-')}.",
            "state": "pass",
        },
        {
            "eyebrow": "Provider Chain",
            "title": f"{final_provider}",
            "detail": f"Priority is Groq online judge, then local Qwen, then deterministic fallback. Current engine: {final_engine}.",
            "state": "pass",
        },
        {
            "eyebrow": "Audit",
            "title": _safe_get(result, "llm_judge_audit", {}).get("status", "Audit-ready"),
            "detail": _safe_get(result, "llm_judge_audit", {}).get("db_path", "Persisted when runtime completes."),
            "state": "pass" if _safe_get(result, "llm_judge_audit", {}).get("status") == "PERSISTED" else "review",
        },
        {
            "eyebrow": "Control Gate",
            "title": release_assessment["release_route"],
            "detail": release_assessment["rationale"],
            "state": "review" if hitl_required else "pass",
        },
    ])

    st.subheader("LLM Judge Control-Plane Diagram")
    st.caption(
        "LLM Judge is an AEGIS control-plane validation capability. It is not part of the external application's "
        "application workflow; it validates the app's canonical output, evidence, risk, and final response before the output is trusted."
    )
    st.graphviz_chart(_build_llm_judge_graphviz_dot(result, assurance), use_container_width=True)

    render_table("LLM Judge Agent Ownership", [
        {
            "Question": "Which agent owns LLM Judge?",
            "Answer": "AEGIS Control Agent / Assurance Layer",
            "Explanation": "It sits after or alongside the app workflow and validates the app output using judge rubrics.",
        },
        {
            "Question": "Is it an application agent?",
            "Answer": "No",
            "Explanation": "Application agents create the proposed answer. AEGIS judge agents validate trust, evidence, security, governance, and release readiness.",
        },
        {
            "Question": "Can it run during runtime?",
            "Answer": "Yes",
            "Explanation": "It can judge partial runtime signals while the app runs, and can also judge the final canonical decision before it is returned.",
        },
    ])

    render_table("Judge Provider Chain", [
        {
            "Priority": 1,
            "Provider": "Groq",
            "When Used": "GROQ_API_KEY is available, SDK/network call succeeds, and judge mode requests LLM judging.",
            "Purpose": "Fast online independent judge for executive demo and arbitration.",
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
            "Purpose": "Guarantees the demo and audit package continue with rule-based verdicts.",
        },
    ])

    render_table("LLM-as-Judge Implementation Matrix", judge_rows)

    render_table("Judge Rubric Registry", rubrics)

    render_table("Multi-Judge / Committee Mode", committee)

    render_table("Adversarial Testing Coverage", adversarial)

    render_table("Human Review Workflow", [
        {"Step": "Trigger", "Description": "High OWASP risk, low trust, low confidence, missing evidence, policy breach, or model disagreement.", "Current Build": "HITL flag and alert evidence", "Production Upgrade": "Workflow queue / GRC case creation"},
        {"Step": "Reviewer Packet", "Description": "Shows query, proposed decision, evidence pack, judge verdicts, risk, and rationale.", "Current Build": "Offline HTML/PDF audit package", "Production Upgrade": "Reviewer UI with approve/reject/comment"},
        {"Step": "Decision Recording", "Description": "Reviewer decision, reason, timestamp, and artifact hashes are retained.", "Current Build": "Audit package and runtime state", "Production Upgrade": "Immutable audit table / enterprise ledger"},
    ])

    render_table("Model Risk Management View", model_risk)

    render_table("Resilience Controls", resilience)

    if runtime_errors:
        st.warning("Runtime errors were captured for this run. Review Runtime Observability and Auditability before external presentation.")


def render_human_review_release_gate(result):
    """Human-in-the-loop release gate for governed publication."""
    st.header("Human Review & Release Gate")
    st.caption(
        "AEGIS can validate the onboarded app during runtime and before final publication. "
        "If quality, grounding, OWASP, policy, or execution checks fail after the retry policy, "
        "the final output is routed to human review instead of being auto-released."
    )

    workflow = _safe_dict(result.get("hitl_workflow"))
    gate = _safe_dict(result.get("publication_gate"))
    reviewer_packet = _safe_dict(workflow.get("reviewer_packet"))
    release_assessment = _governance_release_assessment(result)
    required = bool(release_assessment["review_required"])
    release_allowed = bool(release_assessment["release_allowed"])
    retry_count = gate.get("retry_count", 0)
    max_retries = gate.get("max_retries", 3)
    gate_status = "PASSED" if release_allowed else gate.get("status") or "REVIEW"
    workflow_status = "PENDING_REVIEW" if required else "NOT_REQUIRED"
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

    render_story_strip([
        {
            "eyebrow": "1. App Output",
            "title": "Proposed answer",
            "detail": "The application emits canonical runtime events and a final canonical decision record.",
            "state": "pass",
        },
        {
            "eyebrow": "2. AEGIS Checks",
            "title": "Trust, grounding, OWASP",
            "detail": "AEGIS validates evidence, hallucination risk, security, policy, runtime health, and cost signals.",
            "state": "pass" if gate_status == "PASSED" else "review",
        },
        {
            "eyebrow": "3. Retry Policy",
            "title": f"{retry_count}/{max_retries} attempts",
            "detail": "If the output is not publication-ready, AEGIS can ask the app to repair and retry up to the configured limit.",
            "state": "review" if retry_count else "pass",
        },
        {
            "eyebrow": "4. Review Queue",
            "title": workflow_status,
            "detail": workflow.get("queue") or "No reviewer queue required for this run.",
            "state": "review" if required else "pass",
        },
        {
            "eyebrow": "5. Release",
            "title": "ALLOWED" if release_allowed else "BLOCKED",
            "detail": release_assessment["rationale"] if required else "Governed output can be returned to the application.",
            "state": "pass" if release_allowed else "risk",
        },
    ])

    st.subheader("Release-Gate Decision Diagram")
    st.caption("Shows how runtime signals, judge verdicts, retry policy, and HITL combine before final publication.")
    dot = "\n".join([
        "digraph HITLGate {",
        "rankdir=LR;",
        "graph [bgcolor=\"transparent\", pad=\"0.18\", nodesep=\"0.32\", ranksep=\"0.45\"];",
        "node [shape=box, style=\"rounded,filled\", fontname=\"Segoe UI\", fontsize=12, margin=\"0.12,0.08\", width=1.95, height=0.72, penwidth=1.8, fontcolor=\"white\"];",
        "edge [fontname=\"Segoe UI\", fontsize=10, color=\"#52a8ff\", fontcolor=\"#344054\", arrowsize=0.7, penwidth=1.7];",
        f'app [label={_graphviz_html_label(["Onboarded App", "Canonical output + runtime signals"])}, fillcolor="#063d32", color="#21d4a7"];',
        f'checks [label={_graphviz_html_label(["AEGIS Validation", "OWASP | grounding | evidence | policy"])}, fillcolor="#12395f", color="#52a8ff"];',
        f'pass [label={_graphviz_html_label(["All controls pass", "Release governed output"])}, fillcolor="#083b2f", color="#21d4a7"];',
        f'retry [label={_graphviz_html_label(["Repair / retry", f"Up to {max_retries} attempts"])}, fillcolor="#7a4b00", color="#ffb020"];',
        f'hitl [label={_graphviz_html_label(["Human Review", workflow_status, workflow.get("queue") or "Reviewer queue"])}, fillcolor="#2b2f42", color="#98a2b3"];',
        f'audit [label={_graphviz_html_label(["Audit Evidence", "decision + reviewer packet"])}, fillcolor="#12395f", color="#52a8ff"];',
        'app -> checks [label="submit"];',
        'checks -> pass [label="pass"];',
        'checks -> retry [label="repairable issue"];',
        'retry -> checks [label="re-validate"];',
        'retry -> hitl [label="still failing"];',
        'checks -> hitl [label="critical risk"];',
        'pass -> audit [label="persist"];',
        'hitl -> audit [label="review decision"];',
        "}",
    ])
    st.graphviz_chart(dot, use_container_width=True)

    render_table("Release-Gate Conditions", condition_rows)

    policy_as_code = _safe_dict(result.get("policy_as_code"))
    if policy_as_code:
        render_table("Policy-as-Code Decision Gate", [{
            "Policy Version": policy_as_code.get("policy_version", "-"),
            "Gate Status": policy_as_code.get("status", "-"),
            "Effective Release Allowed": "YES" if release_allowed else "NO",
            "Effective Human Review": "YES" if required else "NO",
            "Failed Checks": policy_as_code.get("failed_count", 0),
            "Critical Failed": policy_as_code.get("critical_failed_count", 0),
        }])
        checks = [
            {
                "Policy ID": row.get("policy_id"),
                "Result": "PASS" if row.get("passed") else "REVIEW",
                "Severity": row.get("severity"),
                "Actual": row.get("actual"),
                "Expected": row.get("expected"),
                "Action": row.get("action"),
            }
            for row in policy_as_code.get("checks", []) or []
            if isinstance(row, dict)
        ]
        render_table("Policy Checks", checks)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("HITL Required", "YES" if required else "NO")
    c2.metric("Workflow Status", workflow_status)
    c3.metric("Release Gate", gate_status)
    c4.metric("Retry Policy", f"{retry_count}/{max_retries}")

    render_table("Human Review Workflow", [
        {"Field": "Workflow ID", "Value": workflow.get("workflow_id", "-")},
        {"Field": "Runtime ID", "Value": workflow.get("runtime_id") or result.get("runtime_id", "-")},
        {"Field": "Customer ID", "Value": workflow.get("customer_id") or result.get("customer_id", "-")},
        {"Field": "Required", "Value": "Yes" if required else "No"},
        {"Field": "Status", "Value": workflow_status},
        {"Field": "Trigger", "Value": workflow.get("trigger") or gate.get("block_reason") or "-"},
        {"Field": "Queue", "Value": workflow.get("queue", "-")},
        {"Field": "Priority", "Value": workflow.get("priority", "-")},
        {"Field": "Allowed Actions", "Value": ", ".join(workflow.get("allowed_actions", []) or []) or "-"},
        {"Field": "SLA", "Value": workflow.get("sla", "-")},
    ])

    render_table("Reviewer Packet", [
        {"Review Item": "Recommendation", "Canonical Value": reviewer_packet.get("recommendation") or result.get("recommendation", "-")},
        {"Review Item": "Risk Level", "Canonical Value": reviewer_packet.get("risk_level") or result.get("risk_level", "-")},
        {"Review Item": "Trust Score", "Canonical Value": reviewer_packet.get("trust_score") or result.get("trust_score", "-")},
        {"Review Item": "Confidence", "Canonical Value": reviewer_packet.get("confidence") or result.get("confidence", "-")},
        {"Review Item": "Evidence Count", "Canonical Value": reviewer_packet.get("evidence_count") or _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks") or [])},
        {"Review Item": "Publication Gate", "Canonical Value": gate_status},
        {"Review Item": "Release Allowed", "Canonical Value": "Yes" if release_allowed else "No"},
        {"Review Item": "Release Route", "Canonical Value": release_assessment["release_route"]},
    ])

    attempts = gate.get("attempts", []) if isinstance(gate.get("attempts"), list) else []
    if attempts:
        render_table("Publication Retry Attempts", attempts)


def render_ai_release_policy_gate(result):
    """Policy-as-code release decision with executive and technical visuals."""
    st.header("AI Release Policy Gate")
    st.caption(
        "This tab shows the governed release rules AEGIS applies before an onboarded app output is returned, "
        "retried, blocked, or routed to human review."
    )

    policy_as_code = _safe_dict(result.get("policy_as_code"))
    checks = [
        row for row in policy_as_code.get("checks", []) or []
        if isinstance(row, dict)
    ]
    passed = sum(1 for row in checks if row.get("passed"))
    review = len(checks) - passed
    critical_failed = int(policy_as_code.get("critical_failed_count") or 0)
    release_assessment = _governance_release_assessment(result)
    release_allowed = bool(release_assessment["release_allowed"])
    hitl_required = bool(release_assessment["review_required"])
    gate_status = "PASS" if release_allowed else policy_as_code.get("status") or "REVIEW"

    render_metric_row({
        "Gate Status": gate_status,
        "Release Allowed": "YES" if release_allowed else "NO",
        "Human Review": "YES" if hitl_required else "NO",
        "Policy Version": policy_as_code.get("policy_version", "-"),
    })

    st.subheader("Release Policy Flow")
    dot = "\n".join([
        "digraph ReleasePolicyGate {",
        "rankdir=LR;",
        "graph [bgcolor=\"transparent\", pad=\"0.18\", nodesep=\"0.32\", ranksep=\"0.45\"];",
        "node [shape=box, style=\"rounded,filled\", fontname=\"Segoe UI\", fontsize=12, margin=\"0.12,0.08\", width=2.05, height=0.74, penwidth=1.8, fontcolor=\"white\"];",
        "edge [fontname=\"Segoe UI\", fontsize=10, color=\"#52a8ff\", fontcolor=\"#344054\", arrowsize=0.72, penwidth=1.7];",
        f'input [label={_graphviz_html_label(["App proposed output", "decision + evidence + runtime signals"])}, fillcolor="#063d32", color="#21d4a7"];',
        f'policy [label={_graphviz_html_label(["Policy-as-Code", "thresholds + security + retries"])}, fillcolor="#12395f", color="#52a8ff"];',
        f'pass [label={_graphviz_html_label(["Pass", "release governed output"])}, fillcolor="#083b2f", color="#21d4a7"];',
        f'retry [label={_graphviz_html_label(["Repair / Retry", "up to configured limit"])}, fillcolor="#7a4b00", color="#ffb020"];',
        f'hitl [label={_graphviz_html_label(["Human Review", "required when unresolved"])}, fillcolor="#2b2f42", color="#98a2b3"];',
        f'audit [label={_graphviz_html_label(["Audit Ledger", "policy result persisted"])}, fillcolor="#12395f", color="#52a8ff"];',
        "input -> policy [label=\"evaluate\"];",
        "policy -> pass [label=\"all required checks pass\"];",
        "policy -> retry [label=\"repairable issue\"];",
        "retry -> policy [label=\"re-check\"];",
        "policy -> hitl [label=\"critical / unresolved\"];",
        "pass -> audit [label=\"record\"];",
        "hitl -> audit [label=\"review packet\"];",
        "}",
    ])
    st.graphviz_chart(dot, use_container_width=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        if checks:
            fig = go.Figure(go.Bar(
                x=["Pass", "Review / Block"],
                y=[passed, review],
                marker_color=["#11845b", "#f79009" if critical_failed == 0 else "#e31837"],
                text=[passed, review],
                textposition="auto",
            ))
            fig.update_layout(
                title="Policy Check Outcome",
                height=300,
                margin=dict(l=20, r=20, t=50, b=35),
                yaxis_title="Checks",
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No policy checks were emitted for this run.")
    with col2:
        severity_counts = {}
        for row in checks:
            severity = str(row.get("severity") or "INFO").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + (0 if row.get("passed") else 1)
        if severity_counts:
            fig = go.Figure(go.Pie(
                labels=list(severity_counts.keys()),
                values=list(severity_counts.values()),
                hole=0.55,
                marker_colors=["#e31837", "#f79009", "#175cd3", "#11845b"],
            ))
            fig.update_layout(title="Open Policy Findings by Severity", height=300, margin=dict(l=10, r=10, t=50, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("No open policy findings.")

    render_table("Policy Gate Summary", [{
        "Policy Version": policy_as_code.get("policy_version", "-"),
        "Gate Status": gate_status,
        "Passed Checks": passed,
        "Review / Block Checks": review,
        "Critical Failed": critical_failed,
        "Release Allowed": "YES" if release_allowed else "NO",
        "HITL Required": "YES" if hitl_required else "NO",
        "Release Route": release_assessment["release_route"],
    }])
    render_table("Release Rule Details", _policy_rule_display_rows(checks))


def _policy_rule_display_rows(checks):
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

    def clean(value):
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


def render_canonical_runtime_audit(result):
    st.subheader("Canonical Runtime Audit")
    st.caption("Single source of truth used to reconcile values across every tab.")
    render_table("Canonical Runtime Values", _canonical_object_audit_rows(result))
    audit_rows = _canonical_consistency_audit_rows(result)
    mismatch_rows = [row for row in audit_rows if row.get("Status") == "MISMATCH"]
    if mismatch_rows:
        st.warning("Canonical consistency mismatches detected. Review these projection values before presenting.")
        render_table("Canonical Consistency Mismatches", mismatch_rows)
    else:
        st.success("Canonical consistency check passed across executive projections.")


def render_investigation(result):

    st.header("Investigation Context")
    st.caption("Pillar: Measurable AI | Audit anchor for this run")

    render_metric_row({

        "Customer":
            result.get("customer_id", "-"),

        "Runtime":
            result.get("runtime_id", "-"),

        "Status": (
            result.get("runtime_summary", {}).get("status")
            or result.get("runtime_health_v2", {}).get("execution_status")
            or result.get("runtime_status")
            or result.get("status", "-")
        )

    })



    # -------------------------------------------------------
    # Original & Rewritten Query
    # -------------------------------------------------------

    original_query, rewritten_query = _runtime_query_pair(result)

    st.text_area(
        "Original Query",
        value=original_query,
        height=90,
        disabled=True
    )

    st.text_area(
        "Updated Query",
        value=rewritten_query,
        height=90,
        disabled=True
    )

    st.divider()


# ============================================================
# Planner
# ============================================================

def render_planner(result):

    st.header("Planner Intelligence")

    planner = result.get(
        "execution_plan",
        result.get(
            "planner",
            {}
        ).get(
            "execution_plan",
            {}
        )
    )

    render_metric_row({

        "Intent":
            planner.get("intent", "-"),

        "Strategy":
            planner.get("strategy", "-"),

        "Plan Status":
            planner.get("status", "READY")

    })

    goals = planner.get("goals", [])

    if goals:

        with st.expander(
            "Planner Goals",
            expanded=True
        ):

            for goal in goals:

                st.write("-", goal)

    planner_llm = result.get(
        "planner_llm",
        {}
    )

    reasoning = (

        planner_llm
        .get(
            "parsed_output",
            {}
        )
        .get(
            "planning_reasoning",
            ""
        )

    )

    if reasoning:

        st.subheader(
            "Planning Reasoning"
        )

        st.info(reasoning)

    telemetry = planner_llm.get(
        "telemetry",
        {}
    )

    render_metric_row({

        "Execution Time (ms)":
            telemetry.get(
                "latency_ms",
                0
            ),

        "LLM Status":
            planner_llm.get("status", "COMPLETED")

    })

    st.divider()


# ============================================================
# Tool Selection
# ============================================================

def render_tools(result):

    st.header("Tool Selection")

    selected = result.get(
        "selected_tools",
        []
    )

    if not selected:

        selected = (

            result
            .get(
                "agent",
                {}
            )
            .get(
                "selected_tools",
                []
            )

        )

    render_table(

        "Selected Tools",

        [{"Tool": tool} for tool in selected]

    )

    router = result.get(
        "router",
        {}
    )

    if router:

        with st.expander(
            "Router Output",
            expanded=False
        ):

            st.write(router)

    st.divider()


# ============================================================
# Customer Intelligence
# ============================================================

def render_customer(result):

    st.header("Customer 360 Intelligence")

    tabs = st.tabs([

        "Customer",

        "Accounts",

        "Transactions",

        "Alerts",

        "Risk"

    ])

    with tabs[0]:

        profile = result.get(
            "customer_profile",
            {}
        )

        if _customer_not_found(result):

            st.error(
                f"Customer {profile.get('customer_id', result.get('customer_id', ''))} is not present in the source database/CSV. "
                "Risk, health and approval classification are blocked and human review is required."
            )

        if profile:

            render_table(
                "Customer Profile",
                _customer_profile_display(profile, result)
            )

        else:

            st.info(
                "Customer profile not available."
            )

    with tabs[1]:

        render_table(

            "Accounts",

            result.get(
                "accounts"
            )

        )

    with tabs[2]:

        render_table(

            "Transactions",

            result.get(
                "transactions"
            )

        )

    with tabs[3]:

        render_table(

            "Alerts",

            result.get(
                "alerts"
            )

        )

    with tabs[4]:

        render_table(

            "Risk Profile",

            result.get(
                "risk_profile",
                {}
            )

        )

    st.divider()
# ============================================================
# Retrieval Intelligence
# ============================================================


def _retrieval_chunk_value(chunk, *keys, default="-"):
    if not isinstance(chunk, dict):
        return default
    for key in keys:
        value = chunk.get(key)
        if value not in (None, "", [], {}):
            return value
    metadata = chunk.get("metadata")
    if isinstance(metadata, dict):
        for key in keys:
            value = metadata.get(key)
            if value not in (None, "", [], {}):
                return value
    return default


def _infer_retrieval_mode(retrieval, knowledge, chunks):
    explicit = "-"
    if isinstance(retrieval, dict):
        explicit = retrieval.get("mode") or retrieval.get("retrieval_mode") or retrieval.get("method") or "-"
    if explicit == "-" and isinstance(knowledge, dict):
        explicit = knowledge.get("mode") or knowledge.get("retrieval_mode") or knowledge.get("method") or "-"
    if explicit != "-":
        return explicit

    methods = []
    for chunk in chunks or []:
        method = _retrieval_chunk_value(chunk, "retrieval_method", "method", "retrieval_mode", "fusion_method")
        if method != "-":
            methods.append(str(method).upper())
        signals = _retrieval_chunk_value(chunk, "retrieval_signals", "signals", default=[])
        if isinstance(signals, list):
            for signal in signals:
                if isinstance(signal, dict) and signal.get("method"):
                    methods.append(str(signal.get("method")).upper())

    joined = " ".join(methods)
    if "HYBRID" in joined or ("BM25" in joined and ("VECTOR" in joined or "SEMANTIC" in joined)):
        return "Hybrid BM25 + Semantic"
    if "BM25" in joined:
        return "BM25 lexical"
    if "VECTOR" in joined or "SEMANTIC" in joined:
        return "Semantic vector"
    return "Hybrid retrieval"


def _infer_evidence_source(retrieval, knowledge, chunks):
    explicit = "-"
    if isinstance(knowledge, dict):
        explicit = knowledge.get("source") or knowledge.get("evidence_source") or "-"
    if explicit == "-" and isinstance(retrieval, dict):
        explicit = retrieval.get("source") or retrieval.get("evidence_source") or "-"
    if explicit != "-":
        return explicit
    sources = []
    for chunk in chunks or []:
        source = _retrieval_chunk_value(chunk, "source", "source_file", "file_name")
        if source != "-":
            sources.append(str(source))
    unique_sources = sorted(set(sources))
    if not unique_sources:
        return "-"
    if len(unique_sources) <= 2:
        return ", ".join(unique_sources)
    return f"{len(unique_sources)} sources"


def _retrieval_chunk_display_rows(chunks):
    rows = []
    for rank, chunk in enumerate(chunks or [], start=1):
        chunk_id = _retrieval_chunk_value(chunk, "chunk_id", "id", "document_id")
        source = _retrieval_chunk_value(chunk, "source", "source_file", "file_name")
        method = _retrieval_chunk_value(chunk, "retrieval_method", "method", "retrieval_mode", "fusion_method")
        if method == "-":
            signals = _retrieval_chunk_value(chunk, "retrieval_signals", "signals", default=[])
            if isinstance(signals, list) and signals:
                method_names = [
                    str(signal.get("method")).upper()
                    for signal in signals
                    if isinstance(signal, dict) and signal.get("method")
                ]
                if method_names:
                    method = " + ".join(sorted(set(method_names)))
        score = _retrieval_chunk_value(chunk, "score", "retrieval_score", "similarity_score", "distance")
        rerank = _retrieval_chunk_value(chunk, "rerank_score", "reranked_score", "final_score")
        text = _retrieval_chunk_value(chunk, "content", "document", "text", "page_content")
        if isinstance(text, dict):
            text = json.dumps(text, ensure_ascii=False)
        text = str(text or "-").replace("\n", " ")
        if len(text) > 260:
            text = text[:257] + "..."
        rows.append({
            "Rank": rank,
            "Chunk ID": chunk_id,
            "Source": source,
            "Retrieval Method": method,
            "Score": score,
            "Rerank Score": rerank,
            "Evidence Preview": text,
        })
    return rows


def render_retrieval(result):

    st.header("Retrieval Intelligence")

    retrieval = result.get("retrieval", {})

    knowledge = result.get(
        "knowledge_intelligence",
        {}
    )

    tabs = st.tabs(
        [
            "Retrieved Chunks",
            "Statistics",
            "Knowledge",
            "Vector Inventory"
        ]
    )

    # ==========================================================
    # Retrieved Chunks
    # ==========================================================

    with tabs[0]:

        retrieval_documents = retrieval.get("documents", []) if isinstance(retrieval, dict) else []
        reranked_documents = _safe_get(result, "reranking", {}).get("reranked_chunks", [])
        chunks = (
            reranked_documents
            or result.get("retrieved_chunks", [])
            or retrieval_documents
            or []
        )
        if len(retrieval_documents or []) > len(chunks):
            chunks = retrieval_documents
        chunks = _filter_customer_scoped_records(chunks, result.get("customer_id"))
        cache = result.get("cache_lookup") or result.get("cache_metrics") or {}
        scope = result.get("retrieval_scope", {})
        if isinstance(cache, dict) and cache.get("status") == "HIT":
            st.success(f"Retrieved evidence restored from runtime cache ({len(chunks)} chunks).")
        elif isinstance(scope, dict) and scope.get("source") == "AUTHORITATIVE_CSV_FALLBACK":
            st.info("Entity-scoped index had no valid matches; evidence was loaded from authoritative customer CSV records.")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Retrieved Chunks",
            len(chunks)
        )

        c2.metric(
            "Evidence",
            len(result.get("evidence_pack", []) or [])
        )

        retrieval_mode = _infer_retrieval_mode(retrieval, knowledge, chunks)
        evidence_source = _infer_evidence_source(retrieval, knowledge, chunks)

        c3.metric("Retrieval Mode", retrieval_mode)

        c4.metric("Evidence Source", evidence_source)

        st.divider()

        if chunks:

            render_table(
                "Retrieved Chunks",
                _retrieval_chunk_display_rows(chunks)
            )
            _render_retrieval_score_explanation()

        else:

            st.info(
                "No retrieved chunks available."
            )

    # ==========================================================
    # Retrieval Statistics
    # ==========================================================

    with tabs[1]:

        stats = retrieval.get(
            "retrieval_statistics",
            result.get(
                "retrieval_statistics",
                knowledge.get(
                    "retrieval_statistics",
                    {}
                )
            )
        )

        if stats:

            render_table(
                "Retrieval Statistics",
                stats
            )

        summary = retrieval.get(
            "retrieval_summary",
            result.get(
                "retrieval_summary",
                None
            )
        )

        if summary:

            st.success(summary)

        st.divider()



        telemetry = result.get("runtime_telemetry", {})

        graph = (
            result.get("graph_metrics")
            or telemetry.get("graph_metrics")
            or {}
        )

        if graph:

            st.subheader(
                "Graph Metrics"
            )

            render_table(
                "Graph Metrics",
                graph
            )

    # ==========================================================
    # Knowledge Intelligence
    # ==========================================================

    with tabs[2]:

        if knowledge:

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Retrieved",
                knowledge.get(
                    "retrieved_chunks",
                    "-"
                )
            )

            c2.metric(
                "Evidence",
                knowledge.get(
                    "evidence_count",
                    "-"
                )
            )

            c3.metric(
                "Graph Health",
                knowledge.get(
                    "graph_health",
                    "-"
                )
            )

            c4.metric(
                "Memory Objects",
                knowledge.get(
                    "memory_objects",
                    "-"
                )
            )

            st.divider()

            render_table(
                "Knowledge Intelligence",
                knowledge
            )

        else:

            st.info(
                "Knowledge Intelligence not available."
            )

        memory = result.get(
            "memory_dashboard",
            {}
        )

        if memory:

            st.divider()

            st.subheader(
                "Memory Dashboard"
            )

            render_table(
                "Memory Dashboard",
                memory
            )

    # ==========================================================
    # Vector Inventory
    # ==========================================================

    with tabs[3]:

        vector = result.get(
            "vector_inventory",
            retrieval.get(
                "vector_inventory",
                {}
            )
        )

        if vector:

            render_table(
                "Vector Inventory",
                vector
            )

        else:

            st.info(
                "Vector Inventory not available."
            )

        document = result.get(
            "document_analysis",
            {}
        )

        if document:

            st.divider()

            st.subheader(
                "Document Inventory"
            )

            render_table(
                "Document Analysis",
                document
            )

    st.divider()
# ============================================================
# Evidence Intelligence
# ============================================================


def render_evidence(result):

    st.header("Evidence Intelligence")

    evidence = result.get(
        "evidence_analysis",
        result.get(
            "evidence",
            {}
        )
    )

    def _evidence_source(item):
        if not isinstance(item, dict):
            return "-"
        metadata = item.get("metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        return (
            item.get("source")
            or item.get("file")
            or item.get("document")
            or metadata.get("source")
            or metadata.get("file")
            or "-"
        )

    render_evidence_coverage_map(result, evidence)

    tabs = st.tabs(
        [
            "Lineage Graph",
            "Evidence Flow",
            "Evidence Pack",
            "Retrieved Evidence",
            "Reranked Evidence",
            "Analysis",
            "Metrics",
            "Sources"
        ]
    )

    # ==========================================================
    # Evidence Lineage Graph
    # ==========================================================

    with tabs[0]:
        render_evidence_lineage_graph(result, evidence)

    with tabs[1]:
        render_evidence_flow_explainer(result, evidence)

    # ==========================================================
    # Evidence Pack
    # ==========================================================

    with tabs[2]:

        evidence_pack = result.get(
            "evidence_pack",
            evidence.get(
                "evidence_pack",
                []
            )
        )
        evidence_pack = _filter_customer_scoped_records(
            evidence_pack,
            result.get("customer_id"),
        )

        metrics = _canonical_evidence_metrics(result, evidence)

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Evidence",
            len(evidence_pack)
        )

        c2.metric(
            "Avg Evidence Trust",
            metrics.get("average_trust", "-")
        )

        c3.metric(
            "Highest Evidence Trust",
            metrics.get("highest_trust", "-")
        )

        c4.metric(
            "Sources",
            metrics.get("sources", "-")
        )

        st.info(
            "Evidence Trust measures source authority, not search relevance. 100 = canonical/authoritative evidence; "
            "70 = customer-scoped CSV evidence without an explicit trust field. Retrieval and rerank scores are tracked separately."
        )

        st.divider()

        if evidence_pack:

            render_table(
                "Evidence Pack",
                _evidence_display_rows(evidence_pack)
            )
            with st.expander("Technical evidence payload", expanded=False):
                render_table(
                    "Raw Evidence Payload",
                    _raw_evidence_detail_rows(evidence_pack)
                )

        else:

            st.info(
                "No evidence pack available."
            )

    # ==========================================================
    # Retrieved Evidence
    # ==========================================================

    with tabs[3]:
        retrieved_chunks = result.get("retrieved_chunks", []) or []
        retrieved_chunks = _filter_customer_scoped_records(
            retrieved_chunks,
            result.get("customer_id"),
        )
        st.subheader("Retrieved Evidence")
        retrieval_scope = result.get("retrieval_scope", {})
        retrieval_scope = retrieval_scope if isinstance(retrieval_scope, dict) else {}
        retrieval_stats = result.get("retrieval_statistics", {})
        retrieval_stats = retrieval_stats if isinstance(retrieval_stats, dict) else {}
        strategy_rows = [{
            "Retrieval Strategy": retrieval_scope.get("source", "HYBRID_INDEX"),
            "BM25 Keyword Hits": retrieval_stats.get("bm25_hits", "-"),
            "Semantic Vector Hits": retrieval_stats.get("vector_hits", "-"),
            "Customer Scope Enforced": "YES" if retrieval_scope.get("enforced", True) else "NO",
            "Matched Candidates": retrieval_scope.get("matched_candidates", len(retrieved_chunks)),
        }]
        render_table("Retrieval Method Summary", strategy_rows)
        st.caption(
            "Retrieved evidence shows the pre-packaging chunks. Method explains whether the row came from BM25 keyword search, "
            "semantic/vector search, hybrid fusion, or an authoritative customer-scoped CSV match."
        )
        render_table(
            "Retrieval Score Guide",
            [
                {
                    "Score Family": "Authoritative CSV match",
                    "Displayed Value": "1",
                    "Meaning": "Exact customer-scoped source-of-record row injected before hybrid ranking.",
                    "How to Read It": "It is a match marker, not a relevance score and not a trust score.",
                },
                {
                    "Score Family": "Hybrid BM25 + Semantic Vector",
                    "Displayed Value": "Example: 21.3955",
                    "Meaning": "Combined retrieval relevance from keyword/BM25 and semantic vector ranking.",
                    "How to Read It": "Higher means the candidate was more relevant during retrieval; it is separate from Evidence Trust.",
                },
                {
                    "Score Family": "Rerank Score",
                    "Displayed Value": "Example: 7.8958 or 100",
                    "Meaning": "Final read-priority after source authority, fusion, and reranker signals.",
                    "How to Read It": "Used to order evidence after retrieval; shown only in retrieval/reranking views.",
                },
                {
                    "Score Family": "Evidence Trust",
                    "Displayed Value": "70 or 100",
                    "Meaning": "Source-authority score for audit confidence.",
                    "How to Read It": "100 means explicit authoritative runtime/source-of-record evidence; 70 is the conservative CSV authority floor.",
                },
            ],
        )
        if retrieved_chunks:
            retrieved_rows = []
            for index, chunk in enumerate(retrieved_chunks, start=1):
                if isinstance(chunk, dict):
                    retrieved_rows.append({
                        "Rank": index,
                        "Source": _evidence_source(chunk),
                        "Evidence Trust": _evidence_trust_value(chunk),
                        "Trust Basis": _evidence_trust_basis(chunk),
                        "Retrieval Method": _retrieval_method_label(chunk),
                        "Retrieval Contribution": _retrieval_contribution_label(chunk),
                        "Score": chunk.get("score", chunk.get("similarity_score", chunk.get("retrieval_score", "-"))),
                        "Rerank Score": chunk.get("rerank_score", chunk.get("cross_encoder_score", "-")),
                        "Text": chunk.get("text") or chunk.get("content") or chunk.get("chunk") or chunk.get("summary") or str(chunk)[:500],
                    })
                else:
                    retrieved_rows.append({"Rank": index, "Source": "-", "Score": "-", "Rerank Score": "-", "Text": str(chunk)})
            if retrieved_rows and all(row.get("Rerank Score") in (None, "", "-") for row in retrieved_rows):
                for row in retrieved_rows:
                    row.pop("Rerank Score", None)
            render_table("Retrieved Evidence", retrieved_rows)
        else:
            st.info("No retrieved evidence chunks were captured for this runtime.")

    # ==========================================================
    # Reranked Evidence
    # ==========================================================

    with tabs[4]:
        reranking = result.get("reranking", {})
        reranking = reranking if isinstance(reranking, dict) else {}
        retrieved_chunks = reranking.get("reranked_chunks") or result.get("retrieved_chunks", []) or []
        retrieved_chunks = _filter_customer_scoped_records(
            retrieved_chunks,
            result.get("customer_id"),
        )
        st.subheader("Reranked Evidence")
        st.caption(_rerank_score_explanation())
        if reranking:
            summary = dict(reranking)
            if "reranked_chunks" in summary:
                summary["reranked_chunks"] = f"{_safe_count(summary.get('reranked_chunks'))} prioritized evidence row(s)"
            summary.setdefault("score_meaning", "Higher score means higher read priority after source authority, hybrid relevance, and reranker signals.")
            render_table("Reranking Summary", summary)
            st.divider()
        if retrieved_chunks:
            def _rerank_value(chunk):
                if not isinstance(chunk, dict):
                    return 0
                return max(
                    _numeric_score(chunk.get("rerank_score"), 0),
                    _numeric_score(chunk.get("cross_encoder_score"), 0),
                    _numeric_score(chunk.get("relevance_score"), 0),
                    _numeric_score(chunk.get("score"), 0),
                )

            reranked_chunks = sorted(
                retrieved_chunks,
                key=_rerank_value,
                reverse=True,
            )
            reranked_rows = []
            for index, chunk in enumerate(reranked_chunks, start=1):
                if isinstance(chunk, dict):
                    reranked_rows.append({
                        "Rerank": index,
                        "Source": _evidence_source(chunk),
                        "Evidence Trust": _evidence_trust_value(chunk),
                        "Trust Basis": _evidence_trust_basis(chunk),
                        "Retrieval Method": _retrieval_method_label(chunk),
                        "Rerank Score": chunk.get("rerank_score", chunk.get("cross_encoder_score", chunk.get("relevance_score", chunk.get("score", "-")))),
                        "Score Meaning": "Read priority after reranking; not evidence trust",
                        "Original Rank": chunk.get("rank", chunk.get("retrieval_rank", "-")),
                        "Evidence Text": chunk.get("text") or chunk.get("content") or chunk.get("chunk") or chunk.get("summary") or str(chunk)[:500],
                    })
                else:
                    reranked_rows.append({"Rerank": index, "Source": "-", "Rerank Score": "-", "Original Rank": "-", "Evidence Text": str(chunk)})
            render_table("Reranked Evidence", reranked_rows)
        else:
            st.info("No retrieved chunks are available for reranking display.")

    # ==========================================================
    # Evidence Analysis
    # ==========================================================

    with tabs[5]:

        if evidence:
            evidence_display = dict(evidence) if isinstance(evidence, dict) else evidence
            if isinstance(evidence_display, dict):
                evidence_display.pop("health", None)

            render_table(
                "Evidence Analysis",
                evidence_display
            )

            summary = evidence.get(
                "summary"
            )

            if summary:

                st.success(summary)

            generated = evidence.get(
                "generated_at"
            )

            if generated:

                st.caption(
                    f"Generated : {generated}"
                )

        else:

            st.info(
                "Evidence analysis not available."
            )

    # ==========================================================
    # Evidence Metrics
    # ==========================================================

    with tabs[6]:

        metrics = _canonical_evidence_metrics(result, evidence)

        if metrics:

            render_table(
                "Evidence Metrics",
                [
                    {
                        "Metric": "Evidence Count",
                        "Value": metrics.get("evidence_count", "-"),
                        "Explanation": "Customer-scoped evidence rows included in the governed evidence pack.",
                    },
                    {
                        "Metric": "Average Evidence Trust",
                        "Value": metrics.get("average_trust", "-"),
                        "Explanation": "Average of evidence-authority scores only; retrieval/rerank scores are excluded.",
                    },
                    {
                        "Metric": "Highest Evidence Trust",
                        "Value": metrics.get("highest_trust", "-"),
                        "Explanation": "Highest authority score among the selected evidence rows.",
                    },
                    {
                        "Metric": "Lowest Evidence Trust",
                        "Value": metrics.get("lowest_trust", "-"),
                        "Explanation": "Lowest authority score among the selected evidence rows.",
                    },
                    {
                        "Metric": "Sources",
                        "Value": metrics.get("sources", "-"),
                        "Explanation": "Distinct source systems/files contributing evidence.",
                    },
                    {
                        "Metric": "Metric Source",
                        "Value": metrics.get("metric_source", "-"),
                        "Explanation": "Primary object used to calculate evidence metrics.",
                    },
                ]
            )
            st.info(
                "Why 70 vs 100: 100 is reserved for canonical runtime evidence or explicitly authoritative source records. "
                "70 is used as a conservative floor for customer-scoped CSV evidence when no explicit evidence_trust/source_trust "
                "field is available. Low retrieval scores are not treated as low evidence trust."
            )
            render_table(
                "Evidence Trust Calculation",
                [
                    {
                        "Signal": "Explicit evidence trust",
                        "When Used": "evidence_trust, evidence_authority, source_trust, or trust is populated",
                        "Meaning": "Direct evidence authority/validation score",
                    },
                    {
                        "Signal": "Authoritative customer-scoped source",
                        "When Used": "Runtime canonical records or AUTHORITATIVE_CSV provenance",
                        "Meaning": "Trusted source record emitted by the application/runtime contract",
                    },
                    {
                        "Signal": "Validated trust_score field",
                        "When Used": "trust_score is 50 or above and therefore behaves like trust, not low retrieval confidence",
                        "Meaning": "Accepted as evidence trust",
                    },
                    {
                        "Signal": "Customer-scoped CSV authority floor",
                        "When Used": "CSV evidence matches the investigated customer but only low retrieval-style scores exist",
                        "Meaning": "Uses 70 as source-authority floor; retrieval/rerank scores stay separate",
                    },
                ]
            )

        dataframe = evidence.get(
            "dataframe"
        )
        dataframe = _filter_customer_scoped_records(
            dataframe,
            result.get("customer_id"),
        )

        if dataframe is not None:

            st.divider()

            st.subheader(
                "Evidence Data"
            )

            try:

                st.dataframe(
                    dataframe,
                    use_container_width=True,
                    hide_index=True
                )

            except Exception:

                pass

    # ==========================================================
    # Source Distribution
    # ==========================================================

    with tabs[7]:

        distribution = evidence.get(
            "source_distribution",
            {}
        )

        if distribution:
            source_df = pd.DataFrame(
                [{"Source": str(source), "Evidence Objects": _numeric_score(count, 0)} for source, count in distribution.items()]
            )
            if not source_df.empty:
                fig = px.bar(
                    source_df,
                    x="Source",
                    y="Evidence Objects",
                    text="Evidence Objects",
                    title="Evidence Source Distribution",
                )
                fig.update_layout(height=330, margin=dict(l=10, r=10, t=45, b=10), xaxis_tickangle=-20)
                st.plotly_chart(fig, use_container_width=True)

            render_table(
                "Source Distribution",
                distribution
            )

        else:

            st.info(
                "No source distribution available."
            )

        query = evidence.get(
            "query"
        )

        if query:

            st.divider()

            st.caption(
                "Customer 360 retrieval query was generated from the original user request and investigation type."
            )
            with st.expander("Retrieval Query Used", expanded=False):
                st.code(
                    query,
                    language="text"
                )

    st.divider()


# ============================================================
# Agent Runtime Intelligence
# ============================================================

def _graphviz_escape(value):
    text = str(value or "-").replace("\\n", "\n")
    return text.replace("\\", "/").replace('"', '\\"').replace("\n", "\\n")


def _graphviz_html_label(lines):
    """Build a Graphviz HTML-like label so literal \\n never appears in rendered nodes."""
    safe_lines = [html.escape(str(line or "-")).replace("\\n", " ") for line in lines]
    return "<" + "<BR/>".join(safe_lines) + ">"


def _format_agent_latency(value):
    latency_ms = int(_numeric_score(value, 0))
    if latency_ms >= 1000:
        return f"{latency_ms / 1000:.2f} s"
    return f"{latency_ms} ms"


def _agent_display_status(node):
    status = str(node.get("status", "UNKNOWN")).upper()
    if not node.get("observed"):
        return "NOT EXECUTED"
    if status in {"SUCCESS", "SUCCEEDED"}:
        return "COMPLETED"
    return status


def _get_agent_graph_query_selection():
    try:
        value = st.query_params.get("agent_node")
        if isinstance(value, list):
            return value[0] if value else None
        return value
    except Exception:
        try:
            value = st.experimental_get_query_params().get("agent_node")
            return value[0] if isinstance(value, list) and value else value
        except Exception:
            return None


def _set_agent_graph_query_selection(node_id):
    try:
        st.query_params["agent_node"] = str(node_id)
    except Exception:
        try:
            st.experimental_set_query_params(agent_node=str(node_id))
        except Exception:
            pass


def _select_agent_graph_node(node_id):
    st.session_state["selected_agent_execution_node"] = str(node_id)
    _set_agent_graph_query_selection(node_id)


def _short_skip_reason(node):
    reason = str(node.get("skip_reason") or "")
    if not reason:
        return ""
    return reason if len(reason) <= 72 else f"{reason[:69]}..."


def _short_graph_label(value, limit=30):
    text = " ".join(str(value or "-").split())
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def _agent_selector_label(node):
    status = _agent_display_status(node)
    latency = _format_agent_latency(node.get("duration_ms")) if node.get("observed") else "-"
    return f"{node.get('label', 'Agent')} | {status} | {latency}"


def _agent_parallel_stage(node):
    label = str(node.get("label") or node.get("id") or "").casefold()
    phase = str(node.get("phase") or "").casefold()
    text = f"{label} {phase}"
    if text.startswith("app ") or any(token in text for token in ("query", "planner", "router", "retrieval", "evidence packager", "response generator", "proposed decision")):
        return "External App Workflow"
    if any(token in text for token in ("owasp", "security", "governance", "compliance", "trust")):
        return "AEGIS Governance & Trust Controls"
    if any(token in text for token in ("reflection", "evaluation", "ragas", "hallucination", "grounding")):
        return "AEGIS Quality & Grounding Controls"
    if any(token in text for token in ("cache", "runtime", "builder", "packager", "monitor")):
        return "AEGIS Observability, Cache & Audit"
    return str(node.get("phase") or "Runtime")


def _group_agents_by_stage(nodes):
    stage_order = [
        "External App Workflow",
        "AEGIS Governance & Trust Controls",
        "AEGIS Quality & Grounding Controls",
        "AEGIS Observability, Cache & Audit",
    ]
    grouped = {}
    for node in nodes:
        stage = _agent_parallel_stage(node)
        grouped.setdefault(stage, []).append(node)
    for stage_nodes in grouped.values():
        stage_nodes.sort(key=lambda item: int(_numeric_score(item.get("execution_order"), 9999)))
    ordered = [(stage, grouped.pop(stage)) for stage in stage_order if stage in grouped]
    ordered.extend(sorted(grouped.items(), key=lambda item: min(int(_numeric_score(node.get("execution_order"), 9999)) for node in item[1])))
    return ordered


def _agent_stage_is_parallel(stage):
    return str(stage) in {"AEGIS Governance & Trust Controls", "AEGIS Quality & Grounding Controls", "AEGIS Observability, Cache & Audit"}


def _agent_graph_zone(node):
    label = str(node.get("label") or "").casefold()
    if label.startswith("app "):
        return "app"
    if "packager" in label or label.startswith("aegis "):
        return "aegis"
    return "aegis"


def _agent_is_executed_node(node):
    if not isinstance(node, dict):
        return False
    status = str(node.get("status") or "").upper().replace(" ", "_")
    if status in {"NOT_EXECUTED", "PLANNED", "PENDING", "SKIPPED", "NOT_SELECTED"}:
        return False
    if node.get("observed") is False:
        return False
    return True


def _agent_graph_node_line(node):
    status = _agent_display_status(node)
    observed = bool(node.get("observed"))
    order = node.get("execution_order") or "-"
    execution_time = _format_agent_latency(node.get("duration_ms")) if observed else "-"
    repeat = int(_numeric_score(node.get("execution_count"), 1))
    repeat_text = f" | x{repeat}" if repeat > 1 else ""
    title = f"Step {order}" if observed else "Planned Branch"
    parts = [
        title,
        _short_graph_label(node.get("label", "Agent"), 32),
        f"{status} | {execution_time}{repeat_text}",
    ]
    return "\n".join(parts)


def _agent_graph_node_label_lines(node):
    observed = bool(node.get("observed"))
    order = node.get("execution_order") or "-"
    execution_time = _format_agent_latency(node.get("duration_ms")) if observed else "-"
    repeat = int(_numeric_score(node.get("execution_count"), 1))
    repeat_text = f" | x{repeat}" if repeat > 1 else ""
    agent_label = _short_graph_label(node.get("label", "Agent"), 28)
    if observed:
        return [f"Step {order}: {agent_label}", f"{execution_time}{repeat_text}"]
    return ["Planned Branch", agent_label]


def _summarize_graph_group(title, nodes, subtitle=None, max_items=6):
    labels = [str(node.get("label") or "Agent") for node in nodes]
    visible = labels[:max_items]
    extra = len(labels) - len(visible)
    lines = [title]
    if subtitle:
        lines.append(subtitle)
    lines.extend(visible)
    if extra > 0:
        lines.append(f"+ {extra} more")
    return "\n".join(lines)


def _build_agent_graphviz_dot(nodes, edges, selected_id=None):
    node_by_id = {str(node.get("id")): node for node in nodes}
    observed_nodes = sorted(
        [
            node for node in nodes
            if _agent_is_executed_node(node) and str(node.get("id")) in node_by_id
        ],
        key=lambda item: int(_numeric_score(item.get("execution_order"), 9999)),
    )
    skipped_nodes = sorted(
        [
            node for node in nodes
            if not _agent_is_executed_node(node) and str(node.get("id")) in node_by_id
        ],
        key=lambda item: str(item.get("label") or item.get("id") or ""),
    )
    dot = [
        "digraph AEGISRuntime {",
        "  graph [rankdir=TB, bgcolor=\"transparent\", splines=ortho, nodesep=\"0.18\", ranksep=\"0.36\", pad=\"0.08\", margin=\"0.04\", concentrate=false];",
        "  node [shape=box, style=\"rounded,filled\", fontname=\"Arial Bold\", fontsize=32, margin=\"0.18,0.08\", width=4.8, height=0.92, penwidth=2.8, fixedsize=false];",
        "  edge [fontname=\"Arial\", fontsize=17, color=\"#21d4a7\", penwidth=2.8, arrowsize=0.9];",
    ]

    for node in observed_nodes:
        node_id = str(node.get("id"))
        status = _agent_display_status(node)
        label = _agent_graph_node_line(node)
        zone = _agent_graph_zone(node)
        fill = "#063d32" if zone == "app" else "#0d2f57"
        color = "#21d4a7" if zone == "app" else "#52a8ff"
        font_color = "#f8fafc"
        if status in {"FAILED", "ERROR"}:
            fill = "#471b25"
            color = "#ff5c7a"
        elif status in {"RUNNING", "IN_PROGRESS"}:
            fill = "#102f52"
            color = "#52a8ff"
        if str(selected_id) == node_id:
            color = "#f6c343"
        label_lines = _agent_graph_node_label_lines(node)
        dot.append(
            f"  \"{_graphviz_escape(node_id)}\" "
            f"[label={_graphviz_html_label(label_lines)}, fillcolor=\"{fill}\", color=\"{color}\", fontcolor=\"{font_color}\", width=4.8, height=0.92, fixedsize=false];"
        )

    if observed_nodes:
        dot.append(
            "  governed_decision_returned "
            "[label=<Governed Decision<BR/>route package>, "
            "fillcolor=\"#fff6e5\", color=\"#f59e0b\", fontcolor=\"#182230\", fontsize=30, width=4.8, height=0.92, fixedsize=false];"
        )
        dot.append(
            "  canonical_parameters "
            "[label=<Canonical Runtime Capture<BR/>agent | status | time | retry | audit>, "
            "fillcolor=\"#e0f2fe\", color=\"#0284c7\", fontcolor=\"#182230\", fontsize=28, width=5.4, height=0.96, fixedsize=false];"
        )
        dot.append(
            "  post_draft_review "
            "[label=<AEGIS Review<BR/>validates draft>, "
            "fillcolor=\"#0d2f57\", color=\"#52a8ff\", fontcolor=\"#f8fafc\", fontsize=30, width=4.8, height=0.92, fixedsize=false];"
        )
        dot.append(
            "  decision_route "
            "[shape=box, style=\"rounded,filled,bold\", label=<Decision Route<BR/>release / exception>, "
            "fillcolor=\"#ffffff\", color=\"#f59e0b\", fontcolor=\"#182230\", fontsize=30, width=4.8, height=0.92, fixedsize=false];"
        )
        dot.append(
            "  business_channel "
            "[label=<External Channel<BR/>outcome + audit ref>, "
            "fillcolor=\"#eef2f7\", color=\"#334155\", fontcolor=\"#182230\", fontsize=30, width=4.8, height=0.92, fixedsize=false];"
        )
        dot.append(
            "  exception_route "
            "[label=<Exception Route<BR/>retry | review | block>, "
            "fillcolor=\"#fff7ed\", color=\"#f97316\", fontcolor=\"#182230\", fontsize=28, width=5.0, height=0.92, fixedsize=false];"
        )
        dot.append(
            "  feedback_note "
            "[label=<Feedback To App<BR/>review fail / retry>, "
            "fillcolor=\"#fff7ed\", color=\"#f97316\", fontcolor=\"#182230\", fontsize=28, width=5.0, height=0.92, fixedsize=false];"
        )

    app_signal_nodes = [node for node in observed_nodes if _agent_graph_zone(node) == "app"]
    first_app_node = app_signal_nodes[0] if app_signal_nodes else (observed_nodes[0] if observed_nodes else None)
    telemetry_anchor = app_signal_nodes[min(2, len(app_signal_nodes) - 1)] if app_signal_nodes else first_app_node
    if telemetry_anchor:
        dot.append(
            f"  {{ rank=same; \"{_graphviz_escape(telemetry_anchor.get('id'))}\"; canonical_parameters; }}"
        )
    canonical_draft_node = next(
        (
            node for node in observed_nodes
            if "canonical decision draft" in str(node.get("label") or "").casefold()
        ),
        app_signal_nodes[-1] if app_signal_nodes else None,
    )
    post_draft_target = None
    if canonical_draft_node:
        for index, node in enumerate(observed_nodes[:-1]):
            if str(node.get("id")) == str(canonical_draft_node.get("id")):
                post_draft_target = observed_nodes[index + 1]
                break
    if observed_nodes and app_signal_nodes:
        for index, signal_node in enumerate(app_signal_nodes):
            edge_label = "emits canonical params" if index == 0 else ""
            dot.append(
                f"  \"{_graphviz_escape(signal_node.get('id'))}\" -> canonical_parameters "
                f"[label=\"{edge_label}\", color=\"#0284c7\", fontcolor=\"#0369a1\", "
                "style=dotted, penwidth=1.6, arrowsize=0.55, constraint=false];"
            )

    for source, target in zip(observed_nodes, observed_nodes[1:]):
        if (
            canonical_draft_node
            and post_draft_target
            and str(source.get("id")) == str(canonical_draft_node.get("id"))
            and str(target.get("id")) == str(post_draft_target.get("id"))
        ):
            continue
        source_zone = _agent_graph_zone(source)
        target_zone = _agent_graph_zone(target)
        if source_zone == "app" and target_zone == "aegis":
            edge_label = "canonical objects"
            edge_color = "#52a8ff"
        elif source_zone == "app" and target_zone == "app":
            edge_label = "app step"
            edge_color = "#21d4a7"
        elif source_zone == "aegis" and target_zone == "aegis":
            edge_label = "AEGIS validation"
            edge_color = "#52a8ff"
        else:
            edge_label = "handoff"
            edge_color = "#f59e0b"
        dot.append(
            f"  \"{_graphviz_escape(source.get('id'))}\" -> \"{_graphviz_escape(target.get('id'))}\" "
            f"[label=\"{edge_label}\", color=\"{edge_color}\", style=solid, penwidth=3.2, weight=20];"
        )

    if observed_nodes:
        last_observed = observed_nodes[-1]
        if canonical_draft_node and post_draft_target:
            dot.append(
                f"  \"{_graphviz_escape(canonical_draft_node.get('id'))}\" -> post_draft_review "
                "[label=\"submitted for AEGIS review\", color=\"#52a8ff\", style=solid, penwidth=2.8, weight=24];"
            )
            dot.append(
                "  post_draft_review -> "
                f"\"{_graphviz_escape(post_draft_target.get('id'))}\" "
                "[label=\"review passed\", color=\"#52a8ff\", style=solid, penwidth=2.8, weight=24];"
            )
        if first_app_node and canonical_draft_node and post_draft_target:
            dot.append(
                "  post_draft_review -> feedback_note "
                "[label=\"review failed\", color=\"#f97316\", style=dashed, penwidth=2.2, constraint=false, minlen=1];"
            )
        dot.append(
            f"  \"{_graphviz_escape(last_observed.get('id'))}\" -> governed_decision_returned "
            "[label=\"review complete\", color=\"#f59e0b\", style=solid, penwidth=3.0, weight=20];"
        )
        dot.append(
            "  governed_decision_returned -> decision_route "
            "[label=\"route outcome\", color=\"#f59e0b\", style=solid, penwidth=3.0, weight=20];"
        )
        dot.append(
            "  decision_route -> business_channel "
            "[label=\"release\", color=\"#21d4a7\", style=solid, penwidth=3.0, weight=20];"
        )
        dot.append(
            "  decision_route -> exception_route "
            "[label=\"if not releasable\", color=\"#f97316\", style=dashed, penwidth=2.4, constraint=false];"
        )
        dot.append(
            "  exception_route -> feedback_note "
            "[label=\"feedback route\", color=\"#f97316\", style=dotted, penwidth=2.0, constraint=false, minlen=1];"
        )
        dot.append(
            "  { rank=same; canonical_parameters; feedback_note; }"
        )

    dot.append("}")
    return "\n".join(dot)


def _render_agent_stage_map(nodes, selected_id=None):
    observed_nodes = sorted(
        [node for node in nodes if node.get("observed")],
        key=lambda item: int(_numeric_score(item.get("execution_order"), 9999)),
    )
    skipped_nodes = [node for node in nodes if not node.get("observed")]
    stage_groups = _group_agents_by_stage(observed_nodes)

    html_parts = [
        textwrap.dedent("""
        <style>
        .aegis-stage-map {
            width: 100%;
            overflow: visible;
            padding: 8px 2px 18px 2px;
        }
        .aegis-stage-row {
            display: grid;
            grid-template-columns: 190px minmax(0, 1fr);
            gap: 18px;
            align-items: stretch;
            margin: 0 0 14px 0;
        }
        .aegis-stage-label {
            background: #f7f9fc;
            border: 1px solid #d8dee9;
            border-left: 5px solid #e31837;
            border-radius: 8px;
            padding: 14px 16px;
            color: #263241;
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 18px;
            font-weight: 800;
            min-height: 92px;
            display: flex;
            align-items: center;
        }
        .aegis-stage-agents {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            align-items: stretch;
            background: #ffffff;
            border: 1px solid #d8dee9;
            border-radius: 10px;
            padding: 12px;
            min-width: 0;
        }
        .aegis-agent-card {
            background: #063d32;
            color: #f8fafc;
            border: 3px solid #21d4a7;
            border-radius: 10px;
            padding: 14px 16px;
            min-height: 104px;
            box-shadow: 0 6px 16px rgba(15, 23, 42, 0.10);
            font-family: "Segoe UI", Arial, sans-serif;
        }
        .aegis-agent-card.selected {
            border-color: #f6c343;
            box-shadow: 0 0 0 3px rgba(246, 195, 67, 0.22);
        }
        .aegis-agent-card.skipped {
            background: #242938;
            border-color: #8a94a8;
        }
        .aegis-agent-step {
            font-size: 13px;
            font-weight: 800;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            opacity: 0.86;
            margin-bottom: 8px;
        }
        .aegis-agent-title {
            font-size: 20px;
            line-height: 1.18;
            font-weight: 800;
            margin-bottom: 10px;
            word-break: break-word;
        }
        .aegis-agent-meta {
            font-size: 15px;
            line-height: 1.35;
            color: #d9f7ef;
        }
        .aegis-stage-arrow {
            width: 190px;
            text-align: center;
            color: #21d4a7;
            font-size: 28px;
            line-height: 20px;
            font-weight: 900;
            margin: -2px 0 10px 0;
        }
        .aegis-branch-box {
            margin-top: 16px;
            background: #fff7ed;
            border: 1px solid #f59e0b;
            border-radius: 10px;
            padding: 14px;
        }
        .aegis-branch-title {
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 18px;
            font-weight: 800;
            color: #263241;
            margin-bottom: 10px;
        }
        @media (max-width: 900px) {
            .aegis-stage-row {
                grid-template-columns: 1fr;
            }
            .aegis-stage-label {
                min-height: auto;
            }
            .aegis-stage-arrow {
                width: 100%;
            }
        }
        </style>
        <div class="aegis-stage-map">
        """)
    ]

    for index, (stage, stage_nodes) in enumerate(stage_groups, start=1):
        html_parts.append(
            f"""
            <div class="aegis-stage-row">
                <div class="aegis-stage-label">{html.escape(stage)}</div>
                <div class="aegis-stage-agents">
            """
        )
        for node in stage_nodes:
            node_id = str(node.get("id"))
            selected_class = " selected" if str(selected_id) == node_id else ""
            order = html.escape(str(node.get("execution_order") or "-"))
            title = html.escape(str(node.get("label") or "Agent"))
            status = html.escape(_agent_display_status(node))
            execution_time = html.escape(_format_agent_latency(node.get("duration_ms")))
            repeat = int(_numeric_score(node.get("execution_count"), 1))
            repeat_text = f" | repeated x{repeat}" if repeat > 1 else ""
            html_parts.append(
                f"""
                <div class="aegis-agent-card{selected_class}">
                    <div class="aegis-agent-step">Step {order}</div>
                    <div class="aegis-agent-title">{title}</div>
                    <div class="aegis-agent-meta">{status} | {execution_time}{html.escape(repeat_text)}</div>
                </div>
                """
            )
        html_parts.append("</div></div>")
        if index < len(stage_groups):
            html_parts.append('<div class="aegis-stage-arrow">&darr;</div>')

    if skipped_nodes:
        html_parts.append(
            """
            <div class="aegis-branch-box">
                <div class="aegis-branch-title">Planned Branches Not Taken</div>
                <div class="aegis-stage-agents">
            """
        )
        for node in skipped_nodes:
            title = html.escape(str(node.get("label") or "Agent"))
            reason = html.escape(_short_skip_reason(node) or "Not selected by the intent router for this investigation.")
            html_parts.append(
                f"""
                <div class="aegis-agent-card skipped">
                    <div class="aegis-agent-step">Not executed</div>
                    <div class="aegis-agent-title">{title}</div>
                    <div class="aegis-agent-meta">{reason}</div>
                </div>
                """
            )
        html_parts.append("</div></div>")

    html_parts.append("</div>")
    st.markdown(textwrap.dedent("".join(html_parts)).strip(), unsafe_allow_html=True)


def render_agent_execution_graph(result):
    """Render the planned and observed AEGIS execution pattern."""
    graph = build_agent_execution_graph(result) if result.get("agent_trace") else (result.get("agent_execution_graph") or build_agent_execution_graph(result))
    result["agent_execution_graph"] = graph
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    nodes = [
        node for node in nodes
        if isinstance(node, dict)
        and _is_countable_agent_label(node.get("label") or node.get("id"))
    ]
    node_id_set = {str(node.get("id")) for node in nodes}
    edges = [
        edge for edge in edges
        if isinstance(edge, dict)
        and str(edge.get("source")) in node_id_set
        and str(edge.get("target")) in node_id_set
    ]

    st.header("App-to-AEGIS Execution Graph")
    st.caption(
        "Opening runtime story: external AI application workflow emits canonical objects into AEGIS, "
        "then AEGIS applies governance, trust, quality, observability, cache, and audit controls."
    )
    if not nodes:
        st.info("Run an AEGIS investigation to populate the live agent graph.")
        return

    agent_counts = _canonical_agent_counts(result)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Agents", agent_counts["total"])
    c2.metric("Executed", agent_counts["executed"])
    c3.metric("Not Executed", agent_counts["not_executed"])
    c4.metric("Avg Execution Time", _format_agent_latency(agent_counts["avg_latency_ms"]))
    repeated_nodes = [
        node for node in nodes
        if int(_numeric_score(node.get("execution_count"), 1)) > 1
    ]
    if repeated_nodes:
        st.warning(
            "Repeated agent executions detected: "
            + ", ".join(
                f"{node.get('label')} x{int(_numeric_score(node.get('execution_count'), 1))}"
                for node in repeated_nodes
            )
        )

    legend = st.columns(4)
    legend[0].success("Main path executed")
    legend[1].warning("Path not taken")
    legend[2].info("Feedback / quality loop")
    legend[3].caption("Yellow border = selected agent")

    selected_key = "selected_agent_execution_node"
    node_by_id = {str(node.get("id")): node for node in nodes}
    node_ids = list(node_by_id.keys())
    query_selection = _get_agent_graph_query_selection()
    if query_selection in node_by_id:
        st.session_state[selected_key] = query_selection
    if st.session_state.get(selected_key) not in node_by_id and node_ids:
        st.session_state[selected_key] = node_ids[0]
    selected_id = st.session_state.get(selected_key, node_ids[0] if node_ids else None)

    with st.container(border=True):
        observed_nodes = sorted(
            [node for node in nodes if _agent_is_executed_node(node)],
            key=lambda item: int(_numeric_score(item.get("execution_order"), 9999)),
        )
        skipped_nodes = [node for node in nodes if not _agent_is_executed_node(node)]
        feedback_nodes = [
            node for node in observed_nodes
            if int(_numeric_score(node.get("execution_count"), 1)) > 1
            or str(node.get("id", "")).lower() in {"reflection", "evaluation", "hallucination", "grounding"}
            or any(token in str(node.get("label", "")).lower() for token in ("reflection", "evaluation", "hallucination", "grounding"))
        ]
        st.subheader("App-to-AEGIS Execution Graph")
        st.caption(
            "Graphviz topology view: solid arrows show the execution handoff path; dotted arrows show runtime canonical events emitted "
            "by each onboarded app agent into the AEGIS telemetry/control plane."
        )
        st.markdown(
            """
            <div style="display:flex; gap:14px; flex-wrap:wrap; margin: 6px 0 12px 0; font-size:14px;">
              <div><span style="display:inline-block;width:14px;height:14px;background:#063d32;border:2px solid #21d4a7;border-radius:3px;vertical-align:-2px;"></span> External app workflow</div>
              <div><span style="display:inline-block;width:14px;height:14px;background:#0d2f57;border:2px solid #52a8ff;border-radius:3px;vertical-align:-2px;"></span> AEGIS control tower</div>
              <div><span style="display:inline-block;width:14px;height:14px;background:#e0f2fe;border:2px solid #0284c7;border-radius:3px;vertical-align:-2px;"></span> Runtime signal bus</div>
              <div><span style="display:inline-block;width:14px;height:14px;background:#fff6e5;border:2px solid #f59e0b;border-radius:3px;vertical-align:-2px;"></span> Governed decision returned</div>
              <div><span style="display:inline-block;width:14px;height:14px;background:#242938;border:2px dashed #8a94a8;border-radius:3px;vertical-align:-2px;"></span> Branch not taken</div>
              <div><span style="display:inline-block;width:24px;height:0;border-top:3px solid #21d4a7;vertical-align:4px;"></span> Executed path</div>
              <div><span style="display:inline-block;width:24px;height:0;border-top:3px dotted #0284c7;vertical-align:4px;"></span> Runtime signal emitted</div>
              <div><span style="display:inline-block;width:24px;height:0;border-top:3px solid #f59e0b;vertical-align:4px;"></span> Return / governed output</div>
              <div><span style="display:inline-block;width:24px;height:0;border-top:3px dashed #8a94a8;vertical-align:4px;"></span> Planned but skipped</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <style>
            div[data-testid="stGraphVizChart"] {
                display: flex;
                justify-content: center;
                overflow-x: auto;
            }
            div[data-testid="stGraphVizChart"] svg {
                width: min(980px, 100%) !important;
                max-width: 980px;
                height: auto !important;
                margin-left: auto;
                margin-right: auto;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        st.graphviz_chart(_build_agent_graphviz_dot(nodes, edges, selected_id), use_container_width=True)
        st.markdown("#### AEGIS Decision Outcomes")
        st.caption(
            "These routes are policy-configurable controls. Release, retry, HITL review, block rules, retry count, and retry thresholds can be tuned per onboarded application."
        )
        st.markdown(
            """
            <div style="display:grid; grid-template-columns: repeat(4, minmax(170px, 1fr)); gap:12px; margin: 8px 0 16px 0;">
              <div style="border:1px solid #bbf7d0; border-top:4px solid #16a34a; border-radius:8px; background:#f0fdf4; padding:14px;">
                <div style="font-weight:800; color:#166534; font-size:16px;">Publish / Release</div>
                <div style="color:#334155; font-size:13px; margin-top:6px;">Return governed outcome to app or channel with audit reference.</div>
                <div style="color:#166534; font-size:12px; font-weight:700; margin-top:10px;">Configurable release policy</div>
              </div>
              <div style="border:1px solid #fed7aa; border-top:4px solid #f97316; border-radius:8px; background:#fff7ed; padding:14px;">
                <div style="font-weight:800; color:#9a3412; font-size:16px;">Retry / Enrich</div>
                <div style="color:#334155; font-size:13px; margin-top:6px;">Send feedback to the app when evidence, grounding, or quality is not sufficient.</div>
                <div style="color:#9a3412; font-size:12px; font-weight:700; margin-top:10px;">Configurable retry count</div>
              </div>
              <div style="border:1px solid #c7d2fe; border-top:4px solid #6366f1; border-radius:8px; background:#eef2ff; padding:14px;">
                <div style="font-weight:800; color:#3730a3; font-size:16px;">HITL Review</div>
                <div style="color:#334155; font-size:13px; margin-top:6px;">Route to reviewer queue when human approval or escalation is required.</div>
                <div style="color:#3730a3; font-size:12px; font-weight:700; margin-top:10px;">Configurable review trigger</div>
              </div>
              <div style="border:1px solid #fecdd3; border-top:4px solid #e11d48; border-radius:8px; background:#fff1f2; padding:14px;">
                <div style="font-weight:800; color:#9f1239; font-size:16px;">Block / No Release</div>
                <div style="color:#334155; font-size:13px; margin-top:6px;">Stop release when policy, safety, compliance, or trust checks fail.</div>
                <div style="color:#9f1239; font-size:12px; font-weight:700; margin-top:10px;">Configurable stop rule</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if skipped_nodes or feedback_nodes:
            branch_col, loop_col = st.columns(2)
            with branch_col:
                st.markdown("#### Path Not Taken")
                if skipped_nodes:
                    branch_rows = [
                        {
                            "Agent": node.get("label", "Agent"),
                            "Reason": _short_skip_reason(node) or "Planned branch was not required for this query path.",
                        }
                        for node in skipped_nodes
                    ]
                    render_table("Skipped branches", branch_rows)
                else:
                    st.success("All planned countable agents executed.")
            with loop_col:
                st.markdown("#### Feedback Loop")
                if feedback_nodes:
                    loop_rows = []
                    for node in feedback_nodes:
                        repeat = int(_numeric_score(node.get("execution_count"), 1))
                        loop_rows.append({
                            "Agent": node.get("label", "Agent"),
                            "Signal": "Repeated execution" if repeat > 1 else "Quality/reflection validation",
                            "Execution Time": _format_agent_latency(node.get("duration_ms")),
                        })
                    render_table("Loop signals", loop_rows)
                else:
                    st.info("No repeated agent execution or quality loop was observed.")

    st.markdown("#### Clickable Agent Inspector")
    st.caption("Use these compact tiles to select an agent and update the Agent Brief.")
    selector_col, detail_col = st.columns([1.15, 1])
    with selector_col:
        for row_start in range(0, len(nodes), 3):
            button_columns = st.columns(3)
            for column, node in zip(button_columns, nodes[row_start:row_start + 3]):
                status = _agent_display_status(node)
                latency = _format_agent_latency(node.get("duration_ms")) if node.get("observed") else "-"
                button_label = f"{node.get('label', 'Agent')}\n{status} | {latency}"
                column.button(
                    button_label,
                    key=f"agent_graph_select_{node.get('id')}",
                    use_container_width=True,
                    type="primary" if str(st.session_state.get(selected_key)) == str(node.get("id")) else "secondary",
                    on_click=_select_agent_graph_node,
                    args=(node.get("id"),),
                )

    selected_node = next(
        (node for node in nodes if node.get("id") == st.session_state.get(selected_key)),
        nodes[0],
    )
    with detail_col:
        st.markdown("#### Agent Brief")
        render_agent_brief(selected_node)
        with st.expander("Technical agent fields"):
            detail_rows = [
                {"Field": "Agent ID", "Value": selected_node.get("id", "-")},
                {"Field": "Observed", "Value": "Yes" if selected_node.get("observed") else "No"},
                {"Field": "Execution Count", "Value": int(_numeric_score(selected_node.get("execution_count"), 1))},
                {"Field": "Execution Orders", "Value": ", ".join(str(item) for item in (selected_node.get("execution_orders") or [])) or "-"},
                {"Field": "Tool", "Value": selected_node.get("tool", "-")},
                {"Field": "Skip Reason", "Value": selected_node.get("skip_reason", "-") if not selected_node.get("observed") else "-"},
            ]
            render_table("Selected Agent Runtime Details", detail_rows)

    with st.expander("Graph details"):
        graph_rows = []
        for node in nodes:
            graph_rows.append({
                "Agent": node.get("label"),
                "Phase": node.get("phase"),
                "Execution Status": _agent_display_status(node),
                "Execution Count": int(_numeric_score(node.get("execution_count"), 1)),
                "Execution Time": _format_agent_latency(node.get("duration_ms")) if node.get("observed") else "-",
                "Executed": "Yes" if node.get("observed") else "No",
                "Tool": node.get("tool", "-"),
                "Reason": node.get("skip_reason", "-") if not node.get("observed") else "-",
            })
        render_table("Agent nodes", graph_rows)
        render_table("Agent transitions", edges)


def render_decision_lineage_graph(result):
    """Show the executive-facing path from query to final decision."""
    st.header("Decision Lineage Graph")
    st.caption("Technical view of how the investigation moved from user intent to evidence, controls, and final recommendation.")

    recommendation = (
        result.get("recommendation")
        or _safe_get(result, "recommendation_package", {}).get("recommendation")
        or _safe_get(result, "decision_snapshot", {}).get("recommendation")
        or "PENDING"
    )
    risk_level = (
        result.get("risk_level")
        or _safe_get(result, "risk_authority", {}).get("risk_level")
        or _safe_get(result, "recommendation_package", {}).get("risk_level")
        or "REVIEW"
    )
    governance_decision = recommendation
    evidence_count = len(result.get("evidence_pack", []) or result.get("retrieved_chunks", []) or [])

    lineage_nodes = [
        ("query", "User Query", "Intent captured"),
        ("rewrite", "Updated Query", "Banking-normalized objective"),
        ("retrieval", "Evidence Retrieval", f"{evidence_count} evidence objects"),
        ("risk", "Risk Scoring", str(risk_level).upper()),
        ("governance", "Governance Controls", str(governance_decision).upper()),
        ("recommendation", "Final Recommendation", str(recommendation).upper()),
    ]
    with st.container(border=True):
        flow = ["<div class='decision-lineage-flow'>"]
        for index, (node_id, title, detail) in enumerate(lineage_nodes, start=1):
            if index > 1:
                flow.append("<div class='decision-lineage-arrow'>-&gt;</div>")
            final_class = " final" if node_id == "recommendation" else ""
            flow.append(
                f"<div class='decision-lineage-card{final_class}'>"
                f"<span>Step {index}</span>"
                f"<strong>{html.escape(str(title))}</strong>"
                f"<em>{html.escape(str(detail))}</em>"
                "</div>"
            )
        flow.append("</div>")
        st.markdown("".join(flow), unsafe_allow_html=True)


def _agent_slowness_reason(row, result=None):
    """Explain why an agent appears slow using runtime context and phase heuristics."""
    duration_ms = int(_numeric_score(row.get("duration_ms"), 0))
    if duration_ms < 30000:
        return "Normal execution time; no bottleneck detected."

    agent = str(row.get("agent") or row.get("agent_name") or "").lower()
    phase = str(row.get("phase") or "").lower()
    remarks = str(row.get("remarks") or row.get("reason") or row.get("tool") or "").strip()
    result = result if isinstance(result, dict) else {}
    vector_cdc = _safe_dict(result.get("vector_index_cdc"))
    cache = _runtime_cache_payload(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))

    if "runtime builder" in agent or "runtime" in phase:
        if vector_cdc.get("rebuilt"):
            return "Vector index CDC rebuilt after CSV changes; embedding/index synchronization increased runtime."
        if str(cache.get("status", "")).upper() in {"MISS", "STORED", "ANALYZED"}:
            return "Fresh runtime build executed because cache did not serve a completed result."
        return "Runtime assembly step aggregated traces, evidence, governance, cache, and audit package objects."
    if "recommendation" in agent or "recommendation" in phase:
        return "Recommendation synthesis reconciled evidence, risk, governance, compliance, and executive narrative."
    if "query rewriter" in agent or "query intelligence" in phase:
        return "LLM-backed query normalization and banking intent expansion added model latency."
    if "planner" in agent or "planning" in phase:
        return "Planner selected agent path and tool strategy before execution."
    if "reflection" in agent or "evaluation" in agent or "ragas" in agent:
        return "Quality/reflection validation compared the response against evidence and decision controls."
    if "retrieval" in agent or "rag" in agent:
        return f"Hybrid retrieval and customer-scoped evidence ranking processed {evidence_count} evidence object(s)."
    if "compliance" in agent or "governance" in agent:
        return "Control reconciliation evaluated policy, review, approval, and audit constraints."
    if remarks and remarks != "-":
        return remarks
    return "Slow band triggered by execution time threshold; no deeper runtime reason was captured."


def render_latency_waterfall(result):
    """Show agent execution-time and performance ranking for technical executives."""
    st.header("Agent Execution Time / Performance")
    st.caption("Runtime observability view showing where execution time was spent across agents.")
    trace = _agent_trace_with_lineage(result)
    rows = []
    for row in trace:
        if not isinstance(row, dict):
            continue
        duration_ms = int(_numeric_score(row.get("duration_ms"), 0))
        rows.append({
            "Agent": row.get("agent") or row.get("agent_name") or "-",
            "Agent Type": row.get("Agent Type", "-"),
            "Receives From": row.get("Receives From", "-"),
            "Passes To": row.get("Passes To", "-"),
            "Phase": row.get("phase", "-"),
            "Status": row.get("status", "-"),
            "Execution Time (s)": round(duration_ms / 1000, 2),
            "Execution Time (ms)": duration_ms,
            "Performance Band": "Slow" if duration_ms >= 120000 else "Watch" if duration_ms >= 30000 else "Normal",
            "Likely Slowness Reason": _agent_slowness_reason(row, result),
        })
    if not rows:
        st.info("Agent execution-time data unavailable.")
        return

    df = pd.DataFrame(rows).sort_values("Execution Time (ms)", ascending=False)
    agent_counts = _canonical_agent_counts(result)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Agents Observed", f"{agent_counts['executed']}/{agent_counts['total']}")
    c2.metric("Total Execution Time", _format_agent_latency(agent_counts["latency_ms"]))
    c3.metric("Slowest Agent", df.iloc[0]["Agent"])
    c4.metric("Slowest Execution Time", _format_agent_latency(df.iloc[0]["Execution Time (ms)"]))

    fig = px.bar(
        df,
        x="Execution Time (s)",
        y="Agent",
        color="Performance Band",
        color_discrete_map={"Slow": "#e31837", "Watch": "#f79009", "Normal": "#21a67a"},
        orientation="h",
        hover_data=["Phase", "Status", "Execution Time (ms)", "Likely Slowness Reason"],
        title="Agent Bottleneck Heatmap",
    )
    fig.update_layout(
        yaxis={"categoryorder": "total ascending"},
        height=max(420, min(900, 34 * len(df))),
        margin=dict(l=12, r=12, t=48, b=12),
        legend_title_text="Performance Band",
    )
    st.plotly_chart(fig, use_container_width=True)
    render_table("Agent Performance Ranking", df.to_dict("records"))


def render_runtime_observability_summary(result):
    """Compact runtime view without repeating cache, cost, security, or agent inventory tabs."""
    st.header("Runtime Observability")
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    runtime_health = (
        result.get("runtime_health_v2")
        or result.get("runtime_health")
        or telemetry.get("runtime_health")
        or {}
    )
    runtime_health = runtime_health if isinstance(runtime_health, dict) else {}
    agent_counts = _canonical_agent_counts(result)
    timeline = _normalized_execution_timeline(result)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Health Score", runtime_health.get("health_score", "-"))
    c2.metric("Status", runtime_health.get("status", result.get("status", "-")))
    c3.metric("Agents", f"{agent_counts['executed']}/{agent_counts['total']}")
    c4.metric("Avg Execution Time", _format_agent_latency(agent_counts["avg_latency_ms"]))

    render_table(
        "Runtime Health Summary",
        [
            {"Metric": "Execution Status", "Value": runtime_health.get("execution_status", result.get("runtime_status", result.get("status", "-")))},
            {"Metric": "Health Level", "Value": runtime_health.get("health_level", "-")},
            {"Metric": "Recommendation", "Value": _runtime_recommendation_and_risk(result)[0]},
            {"Metric": "Total Execution Time", "Value": _format_agent_latency(agent_counts["latency_ms"])},
            {"Metric": "Telemetry Events", "Value": len(result.get("live_runtime", []) or [])},
        ],
    )

    if timeline:
        render_table(
            "Execution Timeline",
            timeline[:12],
        )


def render_monitoring_alerts(result):
    st.header("Alerts & Notifications")
    st.caption(
        "Operational response layer for AEGIS monitoring. This tab explains which runtime events should trigger alerts, "
        "how mail is configured, and whether the current execution produced any notification-worthy findings."
    )
    alerts = build_runtime_alerts(result)
    mail_status = email_config_status()
    dispatch = result.get("notification_dispatch") or result.get("alert_notifications") or {}
    dispatch = dispatch if isinstance(dispatch, dict) else {}
    dispatch_status = dispatch.get("dispatch_status") or dispatch.get("mode") or "Not dispatched"
    auto_send = bool(dispatch.get("auto_send_enabled") or dispatch.get("automatic_dispatch"))
    critical_count = sum(1 for row in alerts if str(row.get("Severity")).upper() == "CRITICAL")
    high_count = sum(1 for row in alerts if str(row.get("Severity")).upper() == "HIGH")

    render_compact_status_grid([
        ("Monitoring Mode", "Per-run event evaluation"),
        ("Real-time Status", "Near real-time target"),
        ("Active Alerts", len(alerts)),
        ("Critical / High", f"{critical_count} / {high_count}"),
        ("Mail Channel", "Configured" if mail_status.get("configured") else "Not configured"),
        ("Trigger Mode", "Auto-send enabled" if auto_send else "Controlled / manual send"),
        ("Dispatch Status", dispatch_status),
    ])

    st.info(
        "AEGIS detects alert conditions per execution. Email dispatch is environment-gated: manual send is available when SMTP variables are configured, "
        "and automatic send is enabled only when AEGIS_ALERT_AUTO_SEND=true."
    )

    render_table("Alert Routing Policy", [
        {
            "Severity": "Critical",
            "Trigger Examples": "OWASP failure, hallucination high, governance block, runtime error",
            "Recommended Frequency": "Immediate per execution",
            "Notification": "Email + incident channel",
        },
        {
            "Severity": "High",
            "Trigger Examples": "Trust below threshold, customer/source data missing, evidence failure",
            "Recommended Frequency": "Immediate per execution",
            "Notification": "Email + GRC queue",
        },
        {
            "Severity": "Medium",
            "Trigger Examples": "Confidence below threshold, runtime warning, execution time breach",
            "Recommended Frequency": "Near real-time or 1-5 minute batch",
            "Notification": "Email digest or dashboard alert",
        },
    ])

    render_table("Notification Trigger Events", [
        {
            "Trigger Event": "OWASP AI vulnerability",
            "Condition": "OWASP finding marked REVIEW, FAIL, HIGH, or CRITICAL",
            "Severity": "Critical / High",
            "Action": "Block presentation until reviewed; notify risk and technology owners",
        },
        {
            "Trigger Event": "Customer or source-data error",
            "Condition": "Customer not found, missing canonical records, or explicit runtime error",
            "Severity": "High",
            "Action": "Notify application owner and data owner",
        },
        {
            "Trigger Event": "Trust or confidence breach",
            "Condition": "Trust score or confidence falls below threshold",
            "Severity": "High / Medium",
            "Action": "Route to human review queue",
        },
        {
            "Trigger Event": "Hallucination or grounding risk",
            "Condition": "Hallucination risk HIGH/CRITICAL or grounding below threshold",
            "Severity": "Critical / High",
            "Action": "Suppress auto-consumption and notify governance owner",
        },
        {
            "Trigger Event": "Runtime health degradation",
            "Condition": "Runtime warnings, failed controls, slow agent, or execution error",
            "Severity": "Medium / High",
            "Action": "Notify platform team; include run id and agent bottleneck details",
        },
        {
            "Trigger Event": "Audit/package failure",
            "Condition": "Audit artifact or evidence package not saved",
            "Severity": "High",
            "Action": "Notify audit owner; mark run not externally presentable",
        },
    ])

    if alerts:
        render_table("Current Alert Findings", alerts)
    else:
        st.success("No active alert threshold breach detected for this run.")

    with st.expander("Mail Notification Setup"):
        render_table("SMTP Configuration Status", [
            {"Setting": "SMTP Host", "Value": mail_status.get("host", "-")},
            {"Setting": "Sender", "Value": mail_status.get("sender", "-")},
            {"Setting": "Recipients", "Value": mail_status.get("recipients", "-")},
            {"Setting": "Status", "Value": "Configured" if mail_status.get("configured") else "Missing: " + ", ".join(mail_status.get("missing", []))},
            {"Setting": "Auto Send", "Value": "Enabled" if auto_send else "Disabled"},
            {"Setting": "Last Dispatch Status", "Value": dispatch_status},
        ])
        st.code(
            "AEGIS_SMTP_HOST=smtp.example.com\n"
            "AEGIS_SMTP_PORT=587\n"
            "AEGIS_SMTP_USERNAME=your-user\n"
            "AEGIS_SMTP_PASSWORD=your-password-or-app-token\n"
            "AEGIS_ALERT_FROM=aegis-alerts@example.com\n"
            "AEGIS_ALERT_TO=risk@example.com,technology@example.com\n"
            "AEGIS_SMTP_USE_TLS=true",
            language="bash",
        )
        subject, body = build_alert_email(result, alerts)
        st.text_input("Email Subject", value=subject, key="aegis_alert_email_subject")
        st.text_area("Email Body Preview", value=body, height=220, key="aegis_alert_email_body")
        if st.button("Send Mail Notification", key="send_aegis_mail_notification", use_container_width=True):
            send_result = send_alert_email(
                st.session_state.get("aegis_alert_email_subject", subject),
                st.session_state.get("aegis_alert_email_body", body),
            )
            if send_result.get("sent"):
                st.success("Mail notification sent.")
            else:
                st.error(f"Mail notification not sent: {send_result.get('error', 'Unknown error')}")


def render_ai_quality_summary(result):
    """AI quality view kept separate from OWASP, cache, and raw runtime telemetry."""
    st.header("AI Quality & Trust")
    quality = _canonical_quality_scores(result)
    reflection = _safe_dict(result.get("reflection"))
    trust = _safe_dict(result.get("enterprise_trust"))
    hallucination_risk = str(quality["hallucination_risk"]).upper()
    groundedness = quality["groundedness"]
    coverage = quality["coverage"]
    if hallucination_risk in {"LOW", "NONE"} and (groundedness or 0) >= 90 and (coverage or 0) >= 90:
        response_quality = "EXCELLENT"
    elif hallucination_risk in {"HIGH", "CRITICAL"} or (groundedness or 0) < 50 or (coverage or 0) < 50:
        response_quality = "REVIEW REQUIRED"
    else:
        response_quality = "GOOD"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Trust Score", f"{quality['trust_score']:.1f}")
    c2.metric("Confidence", f"{quality['confidence']:.1f}")
    c3.metric("Groundedness", "-" if quality["groundedness"] is None else f"{quality['groundedness']:.1f}")
    c4.metric("Coverage", "-" if quality["coverage"] is None else f"{quality['coverage']:.1f}")

    c5, c6, c7 = st.columns(3)
    c5.metric("Hallucination Risk", hallucination_risk)
    c6.metric("Reflection Score", reflection.get("reflection_score", "-"))
    c7.metric("Response Quality", response_quality)

    st.info(
        "Canonical AI quality assessment: "
        f"groundedness is {'-' if groundedness is None else f'{groundedness:.1f}'}, "
        f"coverage is {'-' if coverage is None else f'{coverage:.1f}'}, "
        f"hallucination risk is {hallucination_risk}, and response quality is {response_quality}. "
        "Stale pre-reconciliation reflection text is not used for this executive summary."
    )

    component_rows = []
    for label, key in [
        ("Evidence", "evidence"),
        ("Retrieval", "retrieval"),
        ("Grounding", "grounding"),
        ("Governance", "governance"),
        ("Validation", "validation"),
        ("Evaluation", "evaluation"),
    ]:
        value = trust.get(key)
        if value not in (None, ""):
            component_rows.append({"Component": label, "Score": value})
    if component_rows:
        render_table("Trust Components", component_rows)

def render_agent_runtime(result):

    st.header("Agent Runtime Intelligence")

    trace = _agent_trace_with_lineage(result)

    agent_counts = _canonical_agent_counts(result)
    completed = agent_counts["completed"]
    failed = agent_counts["failed"]
    running = agent_counts["running"]

    if isinstance(trace, list):

        for row in trace:

            if not isinstance(row, dict):
                continue

            status = str(
                row.get("status", "")
            ).upper()

            if status in ("COMPLETED", "SUCCESS"):
                completed += 1

            elif status == "FAILED":
                failed += 1

            elif status in (
                "RUNNING",
                "IN_PROGRESS"
            ):
                running += 1

    completed = agent_counts["completed"]
    failed = agent_counts["failed"]
    running = agent_counts["running"]

    render_metric_row({

        "Completed": completed,

        "Failed": failed,

        "Running": running,

        "Total": agent_counts["total"],

        "Executed": agent_counts["executed"],

        "Not Executed": agent_counts["not_executed"]

    })


    security_rows = _security_findings_rows(result)
    if security_rows:
        st.warning(
            "OWASP/security findings were detected for this investigation. "
            "Review these before relying on the customer decision."
        )
        render_table("Customer Investigation Security Findings", security_rows)

    tabs = st.tabs([

        "Live Runtime",

        "Agent Trace",

        "Runtime Contract",

        "Execution",

        "Customer 360 Investigation",

        "Dashboard"



    ])

    # --------------------------------------------------------
    # Live Runtime
    # --------------------------------------------------------

    with tabs[0]:

        render_table(

            "Live Runtime",

            result.get(
                "live_runtime",
                []
            )

        )

    # --------------------------------------------------------
    # Agent Trace
    # --------------------------------------------------------

    with tabs[1]:
        app_trace = [row for row in trace if row.get("Agent Type") == "Application Workflow Agent"]
        aegis_trace = [row for row in trace if row.get("Agent Type") == "AEGIS Control Agent"]
        app_trace_display = _agent_trace_display_rows(app_trace)
        aegis_trace_display = _agent_trace_display_rows(aegis_trace)
        retry_total = sum(int(_numeric_score(row.get("retry_count"), 0)) for row in trace if isinstance(row, dict))
        retry_configured = sum(1 for row in trace if isinstance(row, dict) and int(_numeric_score(row.get("max_retries"), 0)) > 0)
        retry_events = sum(1 for row in trace if isinstance(row, dict) and int(_numeric_score(row.get("retry_count"), 0)) > 0)
        render_metric_row({
            "Retry Attempts": retry_total,
            "Agents With Retry Policy": retry_configured,
            "Agents Retried": retry_events,
        })
        st.caption(
            "Retries are part of the canonical agent telemetry contract. retry_count shows attempts actually used; "
            "max_retries shows the configured resilience policy."
        )
        render_table(
            "Application Workflow Agents",
            app_trace_display
        )
        render_table(
            "AEGIS Control Agents",
            aegis_trace_display
        )
        with st.expander("Complete Agent Trace"):
            render_table(
                "Agent Trace",
                trace
            )


    # --------------------------------------------------------
    # Runtime Contract
    # --------------------------------------------------------

    with tabs[2]:

        st.caption(
            "This is the canonical telemetry contract each onboarded application or AEGIS agent should emit. "
            "AEGIS uses these fields for observability, lineage, cost, retries, resilience, and auditability."
        )
        render_table(
            "Per-Agent Runtime Contract",
            _agent_runtime_contract_rows(trace)
        )
        render_table(
            "Runtime Contract Field Guide",
            [
                {
                    "Field": "agent_id / agent_name",
                    "Mandatory": "Yes",
                    "Purpose": "Identifies which application or AEGIS control emitted the signal.",
                },
                {
                    "Field": "status",
                    "Mandatory": "Yes",
                    "Purpose": "Shows COMPLETED, RUNNING, FAILED, SKIPPED, or NOT EXECUTED.",
                },
                {
                    "Field": "execution_time_ms",
                    "Mandatory": "Yes",
                    "Purpose": "Supports bottleneck detection and runtime observability.",
                },
                {
                    "Field": "receives_from / passes_to",
                    "Mandatory": "Yes",
                    "Purpose": "Explains previous and next agent lineage.",
                },
                {
                    "Field": "retry_count / max_retries",
                    "Mandatory": "Recommended",
                    "Purpose": "Shows resilience behavior and retry policy.",
                },
                {
                    "Field": "evidence_ids / tokens / cost_usd / audit_id",
                    "Mandatory": "Optional but enterprise-critical",
                    "Purpose": "Links execution to evidence, economics, and audit records.",
                },
            ]
        )
        render_table(
            "Runtime Canonical Objects",
            [
                {
                    "Canonical Object": "Runtime Canonical Event",
                    "Emitter": "Every app agent and every AEGIS control agent",
                    "When Emitted": "During execution: agent start, completion, tool call, evidence retrieval, retry, failure, or skip.",
                    "Mandatory Fields": "runtime_id, agent_id, agent_name, event_type, status, timestamp, execution_time_ms, receives_from, passes_to",
                    "Optional Enterprise Fields": "retry_count, max_retries, tokens, cost_usd, evidence_ids, error_code, policy_ids, audit_id",
                    "Used By AEGIS For": "Live traversal, observability, bottleneck analysis, resilience, cost monitoring, lineage, audit ledger.",
                },
                {
                    "Canonical Object": "Final Canonical Decision",
                    "Emitter": "AI application or response generator",
                    "When Emitted": "After the app completes its application workflow or streams a proposed decision to AEGIS.",
                    "Mandatory Fields": "runtime_id, customer_id, original_query, updated_query, recommendation, risk_level, confidence, evidence_pack",
                    "Optional Enterprise Fields": "trust_score, grounding_score, compliance_status, policy_outcomes, model_version, data_fingerprint, artifact_ids",
                    "Used By AEGIS For": "Governance validation, OWASP checks, grounding, decision consistency, executive summary, audit package.",
                },
                {
                    "Canonical Object": "Governed Decision Record",
                    "Emitter": "AEGIS control plane",
                    "When Emitted": "After AEGIS validates the final decision against trust, risk, evidence, policy, and audit controls.",
                    "Mandatory Fields": "runtime_id, canonical_decision_id, governed_recommendation, governed_risk, governance_status, audit_id",
                    "Optional Enterprise Fields": "human_review_required, approval_reason, blocked_reason, notification_status, package_path",
                    "Used By AEGIS For": "Returning the governed outcome to the app, audit evidence, executive reporting, notification triggers.",
                },
            ],
        )
        st.info(
            "Technical positioning: runtime canonical events can stream while the AI application is still running. "
            "The final canonical decision can arrive at the end or as a proposed decision for AEGIS to govern before return."
        )

    # --------------------------------------------------------
    # Execution Timeline
    # --------------------------------------------------------

    with tabs[3]:

        render_table(

            "Execution Timeline",

            _normalized_execution_timeline(result)

        )

    # --------------------------------------------------------
    # Investigation Timeline
    # --------------------------------------------------------

    with tabs[4]:

        render_table(

            "Investigation Timeline",

            result.get(
                "investigation_timeline",
                []
            )

        )

    # --------------------------------------------------------
    # Dashboard Metrics
    # --------------------------------------------------------

# ========================================================
# Dashboard Metrics
# ========================================================

    with tabs[5]:

        dashboard = result.get(
            "dashboard_metrics",
            {}
        )


        telemetry = result.get("runtime_telemetry", {})

        runtime_health = (
            result.get("runtime_health_v2")
            or result.get("runtime_health")
            or telemetry.get("runtime_health")
            or {}
        )


        runtime_summary = (
            result.get("runtime_summary")
            or {}
        )

        graph = result.get(
            "graph_metrics",
            {}
        )

        # ====================================================
        # Executive Runtime KPI
        # ====================================================

        quality = _canonical_quality_scores(result)
        c1, c2, c3, c4 = st.columns(4)

        c1.metric(

            "Runtime Status",

            runtime_summary.get(
                "status",
                runtime_health.get(
                    "status",
                    "-"
                )
            )

        )

        c2.metric(

            "Recommendation",

            runtime_summary.get(
                "recommendation",
                "-"
            )

        )

        c3.metric(

            "Trust Score",

            f"{quality['trust_score']:.1f}"

        )

        c4.metric(

            "Confidence",

            f"{quality['confidence']:.1f}"

        )

        st.divider()

        # ====================================================
        # Dashboard Metrics
        # ====================================================

        if dashboard:

            st.subheader(
                "Dashboard Metrics"
            )

            render_table(

                "Dashboard Metrics",

                dashboard

            )

        # ====================================================
        # Runtime Health
        # ====================================================

        if runtime_health:

            st.divider()

            st.subheader(
                "Runtime Health"
            )

            render_table(

                "Runtime Health",

                runtime_health

            )

        # ====================================================
        # Graph Metrics
        # ====================================================

        if graph:

            st.divider()

            st.subheader(
                "Graph Metrics"
            )

            render_table(

                "Graph Metrics",

                graph

            )

        # ====================================================
        # Runtime Summary
        # ====================================================

        if runtime_summary:

            st.divider()

            st.subheader(
                "Runtime Summary"
            )

            summary_rows = []

            for k, v in runtime_summary.items():

                if isinstance(
                    v,
                    (
                        dict,
                        list
                    )
                ):
                    continue

                summary_rows.append(

                    {

                        "Metric": k.replace(
                            "_",
                            " "
                        ).title(),

                        "Value": v

                    }

                )

            if summary_rows:

                st.dataframe(

                    pd.DataFrame(
                        summary_rows
                    ),

                    use_container_width=True,

                    hide_index=True

                )






    st.divider()

# ============================================================
# AI Intelligence
# ============================================================

def render_ai_intelligence(result):

    st.header("AI Intelligence inside")

    tabs = st.tabs([

        "Reflection",

        "Enterprise Trust",

        "Security",

        "Telemetry"

    ])

#-----------------------------------------------
# Reflection
# --------------------------------------------------------

    with tabs[0]:

        reflection = result.get("reflection", {})

        if not reflection:
            st.info("Reflection not available.")
        else:

            st.subheader("Executive Reflection")

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.metric(
                    "Reflection Score",
                    reflection.get("reflection_score", "-")
                )

            with c2:
                st.metric(
                    "Groundedness",
                    reflection.get("groundedness_score", "-")
                )

            with c3:
                st.metric(
                    "Evidence",
                    reflection.get("evidence_count", "-")
                )

            with c4:
                st.metric(
                    "Coverage",
                    reflection.get("coverage_score", "-")
                )

            st.divider()

            c1, c2, c3 = st.columns(3)

            with c1:

                st.markdown("#### Hallucination")

                st.write(
                    reflection.get(
                        "hallucination_risk",
                        "-"
                    )
                )

            with c2:

                st.markdown("#### Quality")

                st.write(
                    reflection.get(
                        "quality",
                        "-"
                    )
                )

            with c3:

                st.markdown("#### Grounded")

                st.write(
                    reflection.get(
                        "grounded",
                        "-"
                    )
                )

            st.divider()

            narrative = reflection.get("narrative")

            if narrative:

                st.subheader("Reflection Narrative")

                st.info(narrative)

            evolution = reflection.get(
                "reflection_evolution",
                []
            )

            if evolution:

                st.subheader("Reflection Evolution")

                df = pd.DataFrame(evolution)

                st.dataframe(
                    df,
                    use_container_width=True,
                    hide_index=True
                )

                if (
                    "Agent" in df.columns
                    and
                    "Reflection" in df.columns
                ):

                    fig = px.line(
                        df,
                        x="Agent",
                        y="Reflection",
                        markers=True,
                        title="Reflection Score by Agent"
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True
                    )
            llm = reflection.get(
                "llm_reflection",
                {}
            )

            if llm:

                st.divider()

                st.subheader("LLM Reflection")

                summary = llm.get(
                    "reflection_summary",
                    ""
                )

                if summary:
                    st.success(summary)

                strengths = llm.get(
                    "strengths",
                    []
                )

                if strengths:

                    st.markdown("### Strengths")

                    for item in strengths:
                        st.markdown(f"- {item}")

                weaknesses = llm.get(
                    "weaknesses",
                    []
                )

                if weaknesses:

                    st.markdown("### Weaknesses")

                    for item in weaknesses:
                        st.markdown(f"- {item}")

                actions = llm.get(
                    "recommended_actions",
                    []
                )

                if actions:

                    st.markdown("### Recommended Actions")

                    action_df = pd.DataFrame(
                        {
                            "Priority": range(
                                1,
                                len(actions)+1
                            ),
                            "Action": actions
                        }
                    )

                    st.dataframe(
                        action_df,
                        use_container_width=True,
                        hide_index=True
                    )

            generated = reflection.get(
                "generated_at"
            )

            if generated:

                st.caption(
                    f"Generated : {generated}"
                )
    # --------------------------------------------------------
    # Enterprise Trust
    # --------------------------------------------------------


    with tabs[1]:

        trust = result.get("enterprise_trust", {})
        quality = _canonical_quality_scores(result)

        if not trust:
            st.info("Enterprise Trust information not available.")
        else:

            st.subheader("Enterprise Trust")

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Overall Trust",
                f"{quality['trust_score']:.1f}"
            )

            c2.metric(
                "Retrieval",
                trust.get("retrieval", 0)
            )

            c3.metric(
                "Grounding",
                "-" if quality["groundedness"] is None else f"{quality['groundedness']:.1f}"
            )

            c4.metric(
                "Confidence",
                f"{quality['confidence']:.1f}"
            )

            st.divider()

            left, right = st.columns(2)

            with left:

                st.markdown("### Trust Components")
                st.caption("Diagnostic component scores. The headline trust and confidence values above are the canonical executive scores.")

                component_df = pd.DataFrame(
                    [
                        {
                            "Component": "Evidence",
                            "Score": trust.get("evidence", 0)
                        },
                        {
                            "Component": "Grounding",
                            "Score": trust.get("grounding", 0)
                        },
                        {
                            "Component": "Retrieval",
                            "Score": trust.get("retrieval", 0)
                        },
                        {
                            "Component": "Hallucination",
                            "Score": trust.get("hallucination", 0)
                        },
                        {
                            "Component": "Governance",
                            "Score": trust.get("governance", 0)
                        },
                        {
                            "Component": "Security",
                            "Score": trust.get("security", 0)
                        },
                        {
                            "Component": "RAGAS",
                            "Score": trust.get("ragas", 0)
                        },
                        {
                            "Component": "Validation",
                            "Score": trust.get("validation", 0)
                        },
                        {
                            "Component": "Evaluation",
                            "Score": trust.get("evaluation", 0)
                        }
                    ]
                )

                st.dataframe(
                    component_df,
                    use_container_width=True,
                    hide_index=True
                )

            with right:

                st.markdown("### Trust Summary")

                st.info(
                    f"""
    Overall Trust Score : **{quality['trust_score']:.1f}**

    Retrieval Quality : **{trust.get('retrieval',0)}**

    Grounding : **{'-' if quality['groundedness'] is None else f"{quality['groundedness']:.1f}"}**

    Security : **{trust.get('security',0)}**

    Governance : **{trust.get('governance',0)}**

    Confidence : **{quality['confidence']:.1f}**
    """
                )
            evolution = trust.get("trust_evolution", {})

            journey = []

            if isinstance(evolution, dict):
                journey = evolution.get("trust_journey", [])

            if journey:

                st.divider()

                st.subheader("Trust Journey")

                evo_df = pd.DataFrame(journey)

                st.dataframe(
                    evo_df,
                    use_container_width=True,
                    hide_index=True
                )

                if "stage" in evo_df.columns and "score" in evo_df.columns:

                    fig = px.line(
                        evo_df,
                        x="stage",
                        y="score",
                        markers=True,
                        title="Trust Journey"
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True
                    )

            st.divider()

            with st.expander(
                "Enterprise Trust Runtime Object",
                expanded=False
            ):
                st.json(trust)



    # --------------------------------------------------------
    # Security
    # --------------------------------------------------------


    with tabs[2]:

        security = result.get("security_analysis", {})

        if not security:

            st.info("Security analysis not available.")

        else:

            st.subheader("Enterprise Security")

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Security Score",
                security.get("security_score", 0)
            )

            c2.metric(
                "Risk Level",
                security.get("risk_level", "-")
            )

            c3.metric(
                "Overall Status",
                security.get("status", "-")
            )

            c4.metric(
                "Generated",
                "YES"
            )

            st.divider()

            rows = [

                {
                    "Security Control": "Prompt Injection",
                    "Status": security.get(
                        "prompt_injection",
                        {}
                    ).get(
                        "status",
                        "-"
                    ),
                    "Detected": security.get(
                        "prompt_injection",
                        {}
                    ).get(
                        "detected",
                        "-"
                    )
                },

                {
                    "Security Control": "Jailbreak Detection",
                    "Status": security.get(
                        "jailbreak_detection",
                        {}
                    ).get(
                        "status",
                        "-"
                    ),
                    "Detected": security.get(
                        "jailbreak_detection",
                        {}
                    ).get(
                        "detected",
                        "-"
                    )
                },

                {
                    "Security Control": "PII Exposure",
                    "Status": security.get(
                        "pii_exposure",
                        {}
                    ).get(
                        "status",
                        "-"
                    ),
                    "Detected": len(
                        security.get(
                            "pii_exposure",
                            {}
                        ).get(
                            "sensitive_fields",
                            []
                        )
                    )
                },

                {
                    "Security Control": "Data Leakage",
                    "Status": security.get(
                        "data_leakage",
                        {}
                    ).get(
                        "status",
                        "-"
                    ),
                    "Detected": security.get(
                        "data_leakage",
                        {}
                    ).get(
                        "detected",
                        "-"
                    )
                },

                {
                    "Security Control": "Tool Security",
                    "Status": security.get(
                        "tool_security",
                        {}
                    ).get(
                        "status",
                        "-"
                    ),
                    "Detected": len(
                        security.get(
                            "tool_security",
                            {}
                        ).get(
                            "unauthorized_tools",
                            []
                        )
                    )
                }

            ]

            st.subheader("Security Controls")

            st.dataframe(

                pd.DataFrame(rows),

                use_container_width=True,

                hide_index=True

            )

            llm = security.get(
                "security_llm",
                {}
            )

            if llm:

                parsed = llm.get(
                    "parsed_output",
                    {}
                )

                st.divider()

                st.subheader("Executive Security Summary")

                st.success(

                    parsed.get(
                        "executive_summary",
                        "-"
                    )

                )

                risks = parsed.get(
                    "identified_risks",
                    []
                )

                if risks:

                    st.markdown(
                        "### Identified Risks"
                    )

                    risk_df = pd.DataFrame(

                        {

                            "Risk": risks

                        }

                    )

                    st.dataframe(

                        risk_df,

                        use_container_width=True,

                        hide_index=True

                    )

                actions = parsed.get(
                    "recommended_actions",
                    []
                )

                if actions:

                    st.markdown(
                        "### Recommended Actions"
                    )

                    action_df = pd.DataFrame(

                        {

                            "Action": actions

                        }

                    )

                    st.dataframe(

                        action_df,

                        use_container_width=True,

                        hide_index=True

                    )


            telemetry = result.get("runtime_telemetry", {})
            snapshot = (
                result.get("executive_snapshot")
                or telemetry.get("executive_snapshot")
                or {}
            )

            if snapshot:
                st.subheader("Executive Snapshot")
                render_table("Executive Snapshot", snapshot)


            agent_trace = result.get(
                "agent_trace",
                []
            )

            completed = sum(

                1

                for a in agent_trace

                if isinstance(a, dict)

                and str(
                    a.get(
                        "status",
                        ""
                    )
                ).upper() == "COMPLETED"

            )

            failed = sum(

                1

                for a in agent_trace

                if isinstance(a, dict)

                and str(
                    a.get(
                        "status",
                        ""
                    )
                ).upper() == "FAILED"

            )

            running = sum(

                1

                for a in agent_trace

                if isinstance(a, dict)

                and str(
                    a.get(
                        "status",
                        ""
                    )
                ).upper() in (
                    "RUNNING",
                    "IN_PROGRESS"
                )

            )

            total = len(agent_trace)
            agents = (
                result.get("agents")
                or result.get("selected_agents")
                or result.get("agent", {})
            )

            if not isinstance(agents, dict):
                agents = {}
            if agents:

                st.divider()

                st.subheader(
                    "Security Agents"
                )

                rows = []

                for name, info in agents.items():
                    if isinstance(info, dict):
                        agent_status = info.get(
                            "status",
                            "-"
                        )
                        agent_confidence = info.get(
                            "confidence",
                            "-"
                        )
                    else:
                        agent_status = str(info) if info is not None else "-"
                        agent_confidence = "-"

                    rows.append({

                        "Agent": name,

                        "Status": agent_status,

                        "Agent Confidence": agent_confidence

                    })

                st.dataframe(

                    pd.DataFrame(rows),

                    use_container_width=True,

                    hide_index=True

                )
    # --------------------------------------------------------
    # Runtime Telemetry
    # --------------------------------------------------------


    with tabs[3]:

        st.subheader("Runtime Telemetry")

        #runtime_health = result.get("runtime_health_v2", {})
        telemetry = result.get("runtime_telemetry", {})

        runtime_health = (
            result.get("runtime_health_v2")
            or result.get("runtime_health")
            or telemetry.get("runtime_health")
            or {}
        )

        telemetry = result.get("runtime_telemetry", {})

        token = (
            result.get("token_metrics")
            or telemetry.get("token_metrics")
            or {}
        )
        live_runtime = result.get("live_runtime", [])

        # ==========================================================
        # Runtime KPI
        # ==========================================================

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Health Score",
            runtime_health.get("health_score", "-")
        )

        c2.metric(
            "Execution",
            runtime_health.get("execution_status", "-")
        )

        c3.metric(
            "Success Rate",
            f"{runtime_health.get('agent_success_rate',0)}%"
        )

        c4.metric(
            "Avg Latency",
            f"{runtime_health.get('avg_latency_ms',0)} ms"
        )

        st.divider()

        # ==========================================================
        # Runtime Health
        # ==========================================================

        st.subheader("Runtime Health")

        runtime_df = pd.DataFrame([

            {
                "Metric": "Status",
                "Value": runtime_health.get("status", "-")
            },

            {
                "Metric": "Health Level",
                "Value": runtime_health.get("health_level", "-")
            },

            {
                "Metric": "Recommendation",
                "Value": _runtime_recommendation_and_risk(result)[0]
            },

            {
                "Metric": "Total Agents",
                "Value": agent_counts["total"]
            },

            {
                "Metric": "Successful Agents",
                "Value": agent_counts["completed"]
            },

            {
                "Metric": "Failed Agents",
                "Value": agent_counts["failed"]
            }

        ])

        engine_checks = security.get("checks", [])
        if isinstance(engine_checks, list) and engine_checks:
            controls = []
            for check in engine_checks:
                if not isinstance(check, dict):
                    continue
                findings = check.get("findings", [])
                if isinstance(findings, list):
                    findings = "; ".join(str(item) for item in findings)
                controls.append({
                    "OWASP Control": check.get("category", check.get("owasp_control", "Control")),
                    "Status": check.get("status"),
                    "Score": check.get("score"),
                    "Reason / Findings": findings or check.get("reason") or "No issue detected",
                })

        st.dataframe(

            runtime_df,

            use_container_width=True,

            hide_index=True

        )

    # ==========================================================
    # Token Consumption
    # ==========================================================

        if token:

            st.divider()

            st.subheader("Token Consumption")

            t1, t2, t3, t4 = st.columns(4)

            t1.metric(
                "Prompt",
                token.get("prompt_tokens", 0)
            )

            t2.metric(
                "Completion",
                token.get("completion_tokens", 0)
            )

            t3.metric(
                "Embedding",
                token.get("embedding_tokens", 0)
            )

            t4.metric(
                "Total",
                token.get("total_tokens", 0)
            )

            observed_provider, observed_model = _observed_llm_identity(result, token)

            token_df = pd.DataFrame([

                {
                    "Metric":"Provider",
                    "Value":observed_provider
                },

                {
                    "Metric":"Model",
                    "Value":observed_model
                },

                {
                    "Metric":"Estimated Cost (USD)",
                    "Value":token.get("estimated_cost_usd",0)
                },

                {
                    "Metric":"Efficiency",
                    "Value":token.get("token_efficiency",0)
                },

                {
                    "Metric":"Agents",
                    "Value":token.get("agents",0)
                },

                {
                    "Metric":"Average Tokens / Agent",
                    "Value":token.get("avg_tokens_per_agent",0)
                }

            ])

            st.dataframe(

                token_df,

                use_container_width=True,

                hide_index=True

            )

    # ==========================================================
    # Live Runtime
    # ==========================================================

        if live_runtime:

            st.divider()

            st.subheader("Live Runtime")

            runtime_rows = []

            for row in live_runtime:

                trust = row.get("trust_score")

                if isinstance(trust, dict):

                    trust = trust.get("overall", 0)

                runtime_rows.append({

                    "Agent": row.get("agent"),

                    "Phase": row.get("phase"),

                    "Status": row.get("status"),

                    "Duration": _format_agent_latency(row.get("duration_ms")),

                    "Agent Trust": "-" if _is_unknown_value(trust) else trust,

                    "Agent Confidence": "-" if _is_unknown_value(row.get("confidence")) else row.get("confidence")

                })

            st.dataframe(

                _arrow_safe_dataframe(runtime_rows),

                use_container_width=True,

                hide_index=True

            )

        # ==========================================================
        # Runtime Warnings
        # ==========================================================

        warnings = runtime_health.get("warnings", [])

        if warnings:

            st.divider()

            st.subheader("Runtime Warnings")

            warning_df = pd.DataFrame(

                {

                    "Warning": warnings

                }

            )

            st.dataframe(

                warning_df,

                use_container_width=True,

                hide_index=True

            )

    st.divider()

# ============================================================
# EXECUTIVE SUMMARY V3
# ============================================================

def render_executive_summary(result):

    st.header("Executive Summary")

    executive = result.get("executive_narrative", {})

    if not executive:

        st.info("Executive Summary not available.")

        return

    health = _safe_dict(executive.get("customer_health", {}))
    profile = _safe_dict(result.get("customer_profile", {}))
    risk_authority = _safe_dict(result.get("risk_authority", {}))
    recommendation_authority = _safe_dict(result.get("recommendation_authority", {}))
    recommendation_package = _safe_dict(result.get("recommendation_package", {}))
    customer_name = (
        profile.get("customer_name")
        or result.get("customer_name")
        or result.get("customer_id")
        or "Customer"
    )
    recommendation = (
        result.get("recommendation")
        or recommendation_authority.get("recommendation")
        or recommendation_package.get("recommendation")
        or "UNKNOWN"
    )
    risk_level = (
        risk_authority.get("level")
        or risk_authority.get("risk_level")
        or profile.get("risk_rating")
        or "LOW"
    )
    risk_score = (
        risk_authority.get("score")
        if risk_authority.get("score") is not None
        else health.get("risk_score", 0)
    )
    health_score = health.get("health_score", health.get("score", 0))
    retrieval_scope = _safe_dict(result.get("retrieval_scope", {}))
    customer_missing = _customer_not_found(result)
    missing_customer_retrieval = (
        customer_missing
        or
        str(risk_level).upper() in {"INSUFFICIENT_EVIDENCE", "REVIEW_REQUIRED"}
        or str(retrieval_scope.get("coverage_status", "")).upper() == "NO_CUSTOMER_CHUNK_RETRIEVED"
        or str(health.get("retrieval_coverage_status", "")).upper() == "NO_CUSTOMER_CHUNK_RETRIEVED"
    )
    if customer_missing:
        risk_band = "CUSTOMER_NOT_FOUND"
        risk_band_reason = (
            "Customer is not present in the source database/CSV, so AEGIS blocks risk classification."
        )
        health_band = "CUSTOMER_NOT_FOUND"
        health_band_reason = (
            "Customer health is not classified because the customer master record is missing."
        )
    elif missing_customer_retrieval:
        risk_band = "INSUFFICIENT_EVIDENCE"
        risk_band_reason = (
            "No customer-specific retrieved chunk/evidence object is available, so AEGIS blocks LOW-risk classification."
        )
        health_band = "REVIEW_REQUIRED"
        health_band_reason = (
            "Customer health is not classified as HEALTHY until customer-specific evidence is retrieved."
        )
    else:
        risk_band, risk_band_reason = _score_band(
            risk_score,
            [
                (24.99, "LOW", "No material adverse risk indicators are present in the available evidence."),
                (59.99, "MODERATE", "Some monitoring indicators are present, but they do not meet escalation threshold."),
                (100.0, "HIGH", "Risk indicators meet or exceed the escalation threshold and require senior review."),
            ],
            "HIGH"
        )
        health_band, health_band_reason = _score_band(
            health_score,
            [
                (49.99, "AT_RISK", "Composite customer health is below the acceptable operating threshold."),
                (69.99, "WATCHLIST", "Composite customer health is acceptable but requires monitoring."),
                (100.0, "HEALTHY", "Composite customer health is in the acceptable range."),
            ],
            "UNKNOWN"
        )
    kyc_status = profile.get("kyc_status") or result.get("kyc_status") or "UNKNOWN"
    aml_status = profile.get("aml_status") or result.get("aml_status") or "UNKNOWN"
    alert_count = _safe_count(result.get("alerts", []))
    case_count = _safe_count(result.get("cases", []))
    account_count = profile.get("account_count", result.get("account_count", 0))
    fallback_risk = (
        f"{customer_name} is classified as {risk_band} risk because the risk score is {risk_score}. "
        f"{risk_band_reason} KYC is {kyc_status}, AML is {aml_status}, "
        f"alerts={alert_count}, cases={case_count}, accounts={account_count}. "
        f"Customer health is {health_band} with health score {health_score}: {health_band_reason}"
    )
    fallback_recommendation = (
        f"Recommendation is {str(recommendation).upper()}. This follows the score policy: "
        f"LOW risk supports APPROVE when KYC/AML are clear and no alerts or cases are present; "
        f"MODERATE risk supports MONITOR; HIGH risk supports ESCALATE. "
        f"Current evidence places {customer_name} in {risk_band} risk and {health_band} health."
    )
    fallback_management = (
        f"Management summary: {customer_name} has risk score {risk_score} ({risk_band}) and "
        f"health score {health_score} ({health_band}). Follow the {str(recommendation).upper()} decision "
        f"and retain the evidence trail for audit review."
    )
    fallback_next_action = (
        recommendation_authority.get("next_best_action")
        or recommendation_package.get("next_best_action")
        or recommendation_package.get("business_impact")
        or {
            "APPROVE": (
                f"Approve standard servicing. Reason: risk score {risk_score} maps to {risk_band}, "
                f"health score {health_score} maps to {health_band}, and no adverse alert/case trigger is present."
            ),
            "MONITOR": (
                f"Place customer under monitoring. Reason: score profile maps to {risk_band}/{health_band}; "
                f"review transaction behaviour and refresh controls at the next cycle."
            ),
            "ESCALATE": (
                f"Escalate for senior compliance review. Reason: risk score {risk_score} maps to {risk_band}; "
                f"attach KYC, AML, alert, case, and retrieval evidence."
            ),
        }.get(str(recommendation).upper(), "Route to manual review with supporting evidence.")
    )
    quality = _canonical_quality_scores(result)
    evidence_count = _safe_count(
        result.get("evidence")
        or result.get("evidence_objects")
        or result.get("retrieved_chunks")
        or _safe_get(result, "evidence_package", {}).get("evidence")
    )
    canonical_executive_summary = (
        f"{customer_name} received a {str(recommendation).upper()} recommendation. "
        f"Risk is {risk_band}; evidence strength is {evidence_count} source(s). "
        f"Trust score is {quality['trust_score']:.1f} and confidence is {quality['confidence']:.1f}."
    )

    # =====================================================
    # Executive KPI
    # =====================================================

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Relationship",
        health.get("relationship_score", "-")
    )

    c2.metric(
        "Engagement",
        health.get("engagement_score", "-")
    )

    c3.metric(
        "Portfolio",
        health.get("portfolio_score", "-")
    )

    c4.metric(
        "Risk",
        health.get("risk_score", "-")
    )

    st.divider()

    c1, c2 = st.columns([2,1])

    with c1:

        st.subheader("Executive Summary")

        st.success(canonical_executive_summary)

    with c2:

        st.subheader("Customer Health")

        st.caption(
            f"Score: {health.get('health_score', '-')} | "
            f"{health.get('classification_reason', 'Classification reason unavailable')}"
        )
        with st.expander("Health calculation"):
            st.code(health.get("formula", "Formula unavailable"))
            st.json({
                "weights": health.get("weights", {}),
                "component_contributions": health.get("component_contributions", {}),
                "thresholds": health.get("thresholds", {}),
            })

        st.metric(

            "Overall Health",

            health.get(

                "health",

                "-"

            )

        )

    st.divider()

    tabs = st.tabs(

        [

            "Risk",

            "Recommendation",

            "Management",

            "Next Action",

            "Score Calculations"

        ]

    )

    # =====================================================
    # Risk Narrative
    # =====================================================

    with tabs[0]:

        st.subheader("Risk Assessment")

        st.info(
            _narrative_text(
                executive.get("risk_narrative", "-"),
                fallback_risk
            )
        )

    # =====================================================
    # Recommendation Narrative
    # =====================================================

    with tabs[1]:

        st.subheader("Recommendation")

        st.success(
            _narrative_text(
                executive.get("recommendation_narrative", "-"),
                fallback_recommendation
            )
        )

    # =====================================================
    # Management Commentary
    # =====================================================

    with tabs[2]:

        st.subheader("Management Commentary")

        st.info(
            _narrative_text(
                executive.get("management_commentary", "-"),
                fallback_management
            )
        )

    # =====================================================
    # Next Best Action
    # =====================================================

    with tabs[3]:

        st.subheader("Next Best Action")

        action = executive.get(

            "next_best_action",

            "-"

        )

        st.warning(_narrative_text(action, fallback_next_action))

    with tabs[4]:

        render_score_explainability(result)

    st.divider()

    st.subheader("Customer Health Breakdown")

    health_df = pd.DataFrame(

        [

            {

                "Metric":"Relationship Score",

                "Value":health.get(

                    "relationship_score"

                )

            },

            {

                "Metric":"Engagement Score",

                "Value":health.get(

                    "engagement_score"

                )

            },

            {

                "Metric":"Portfolio Score",

                "Value":health.get(

                    "portfolio_score"

                )

            },

            {

                "Metric":"Risk Score",

                "Value":health.get(

                    "risk_score"

                )

            },

            {

                "Metric":"Overall Health",

                "Value":health.get(

                    "health"

                )

            }

        ]

    )

    st.dataframe(

        health_df,

        use_container_width=True,

        hide_index=True

    )

    generated = executive.get("generated_at")

    if generated:

        st.caption(

            f"Generated : {generated}"

        )
# ============================================================
# Governance
# ============================================================
# ============================================================
# GOVERNANCE CENTER V3
# ============================================================

def render_governance(result):

    st.header("Governance Controls Center")

    governance = result.get("governance", {})
    compliance = result.get("compliance", {})
    audit = result.get("audit_package", result.get("audit", {}))
    risk_level = str(result.get("risk_level") or _safe_get(result, "risk_authority", {}).get("risk_level") or _safe_get(result, "risk_authority", {}).get("level") or "-").upper()
    recommendation, risk_level = _runtime_recommendation_and_risk(result)
    release_assessment = _governance_release_assessment(result)
    review_required = bool(release_assessment["review_required"])
    approved = recommendation == "APPROVE" and not review_required
    governance_reason = release_assessment["rationale"]
    if isinstance(governance, dict):
        governance["decision"] = recommendation
        governance["review_required"] = review_required
        governance["approved"] = approved
        governance["status"] = release_assessment["governance_status"]
        governance["release_route"] = release_assessment["release_route"]
        governance["reason"] = governance_reason
    render_governance_control_ladder(result)

    reason = governance_reason

    if reason:

        st.info(reason)
        if release_assessment["review_required"]:
            trigger_rows = [
                {"Trigger": label, "Why It Requires HITL": detail}
                for label, detail in release_assessment["reasons"]
            ] or [{"Trigger": "Configured HITL", "Why It Requires HITL": "A governance or human-review flag is active, but no lower-level blocker was emitted."}]
            render_table("Why HITL Is Required", trigger_rows)
        else:
            render_table("Why This Case Can Be Approved", [
                {"Control": "Recommendation", "Result": recommendation, "Reason": "The proposed recommendation is approve."},
                {"Control": "Risk Authority", "Result": risk_level, "Reason": "Risk is within the auto-release band."},
                {"Control": "Compliance", "Result": _canonical_compliance_status(result), "Reason": "KYC/AML and policy controls are compliant."},
                {"Control": "Evidence", "Result": f"{_safe_count(result.get('evidence_pack') or result.get('retrieved_chunks'))} objects", "Reason": "Customer-scoped evidence is available."},
                {"Control": "Release Route", "Result": release_assessment["release_route"], "Reason": "No concrete HITL blocker was emitted."},
            ])

    st.divider()


    tab1, tab2, tab3, tab4 = st.tabs(

        [

            "Governance",

            "Compliance",

            "Audit Trail",

            "Human Approval"

        ]

    )

    # ==========================================================
    # Governance
    # ==========================================================

    with tab1:

        gov_df = pd.DataFrame(

            [

                {

                    "Property": "Risk Authority",
                    "Value": risk_level
                },
                {
                    "Property": "Compliance Status",
                    "Value": _canonical_compliance_status(result)
                },
                {
                    "Property": "Governance Gate Status",
                    "Value": governance.get("status")
                },
                {
                    "Property": "HITL Control",
                    "Value": "Required" if review_required else "Not Required"
                },
                {
                    "Property": "Release Route",
                    "Value": governance.get("release_route")
                },
                {
                    "Property": "Release Decision",
                    "Value": "Not released until HITL sign-off" if review_required else "Auto-release eligible"
                },
                {
                    "Property": "Control Rationale",
                    "Value": governance.get("reason")
                }

            ]

        )

        st.dataframe(

            gov_df,

            use_container_width=True,

            hide_index=True

        )

    # ==========================================================
    # Compliance
    # ==========================================================

    with tab2:

        rows = _canonical_compliance_controls(result)

        st.subheader(
            "Compliance Controls"
        )

        st.dataframe(

            pd.DataFrame(rows),

            use_container_width=True,

            hide_index=True

        )

        score = compliance.get(
            "compliance_score",
            "-"
        )

        status = _canonical_compliance_status(result)

        st.divider()

        c1, c2 = st.columns(2)

        c1.metric(
            "Compliance Score",
            score
        )

        c2.metric(
            "Status",
            status
        )

    # ==========================================================
    # Audit Trail
    # ==========================================================

    with tab3:

        audit_trail = audit.get(
            "audit_trail",
            []
        )

        if audit_trail:

            rows = []

            ordered_audit_trail = sorted(
                [item for item in audit_trail if isinstance(item, dict)],
                key=lambda item: (
                    int(_numeric_score(item.get("sequence"), 999999)),
                    str(item.get("timestamp") or ""),
                    str(item.get("event_type") or ""),
                ),
            )

            for display_sequence, item in enumerate(ordered_audit_trail, start=1):

                rows.append(

                    {

                        "Sequence": display_sequence,

                        "Event": item.get(
                            "event_type"
                        ),

                        "Decision": item.get(
                            "decision",
                            ""
                        ),

                        "Control": item.get(
                            "control",
                            ""
                        ),

                        "Status": item.get(
                            "status",
                            ""
                        ),

                        "Review": item.get(
                            "review_required",
                            ""
                        ),

                        "Reason": item.get(
                            "reason",
                            ""
                        )

                    }

                )

            st.dataframe(

                pd.DataFrame(rows),

                use_container_width=True,

                hide_index=True

            )

        metrics = audit.get(
            "audit_metrics",
            {}
        )

        if metrics:

            st.divider()

            st.subheader(
                "Audit Metrics"
            )

            metric_df = pd.DataFrame(

                [

                    {

                        "Metric": k.replace(
                            "_",
                            " "
                        ).title(),

                        "Value": v

                    }

                    for k, v in metrics.items()

                ]

            )

            st.dataframe(

                metric_df,

                use_container_width=True,

                hide_index=True

            )

        replay = audit.get(
            "replay",
            []
        )

        if replay:

            st.divider()

            st.subheader(
                "Audit Replay"
            )

            st.dataframe(

                pd.DataFrame(replay),

                use_container_width=True,

                hide_index=True

            )



   # ==========================================================
# Human Approval (HITL)
# ==========================================================

    with tab4:

        approval = governance.get(
            "approval",
            result.get(
                "approval",
                {}
            )
        )

        if not approval:

            approval = audit.get(
                "approval",
                {}
            )

        if approval:

            st.subheader("Human-in-the-Loop Approval")
            release_assessment = _governance_release_assessment(result)
            effective_review_required = bool(release_assessment["review_required"])

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Approval Status",
                "PENDING" if effective_review_required else "NOT REQUIRED"
            )

            c2.metric(
                "Review Required",
                "YES" if effective_review_required else "NO"
            )

            c3.metric(
                "Approver",
                approval.get(
                    "approver",
                    "-"
                )
            )

            c4.metric(
                "Release Route",
                release_assessment["release_route"]
            )

            st.divider()

            rows = [

                {

                    "Property": "Approval Status",

                    "Value": "PENDING" if effective_review_required else "NOT REQUIRED"

                },

                {

                    "Property": "Release Route",

                    "Value": release_assessment["release_route"]

                },

                {

                    "Property": "Approver",

                    "Value": approval.get(
                        "approver",
                        "-"
                    )

                },

                {

                    "Property": "Review Required",

                    "Value": "YES" if effective_review_required else "NO"

                },

                {

                    "Property": "Approval Time",

                    "Value": approval.get(
                        "approval_time",
                        "-"
                    )

                },

                {

                    "Property": "Comments",

                    "Value": approval.get(
                        "comments",
                        "-"
                    )

                }

            ]

            st.dataframe(

                pd.DataFrame(rows),

                use_container_width=True,

                hide_index=True

            )

        else:

            st.info(
                "No Human Approval information available."
            )
    st.divider()


# ============================================================
# Banking Intelligence
# ============================================================

def render_banking(result):

    st.header("Banking Intelligence")

    tabs = st.tabs([
        "Customer Health",
        "Case Management",
        "Risk",
        "Dashboard"
    ])

    with tabs[0]:

        banking = result.get(
            "banking_intelligence",
            {}
        )

        render_table(
            "Customer Health",
            banking.get(
                "customer_health",
                {}
            )
        )

        render_table(
            "Relationship",
            banking.get(
                "relationship",
                {}
            )
        )

    with tabs[1]:

        render_table(
            "Case Management",
            result.get(
                "case_management",
                {}
            )
        )

    with tabs[2]:

        render_table(
            "Risk Profile",
            result.get(
                "risk_profile",
                {}
            )
        )

    with tabs[3]:

        render_table(
            "Dashboard Metrics",
            result.get(
                "dashboard_metrics",
                {}
            )
        )

    st.divider()


# ============================================================
# Executive
# ============================================================

def render_executive(result):

    st.header("Executive Intelligence")

    tabs = st.tabs([
        "Narrative",
        "Executive Package",
        "Recommendation",
        "Control Tower",
        "Executive Dashboard"
    ])

    with tabs[0]:

        render_table(
            "Executive Narrative",
            result.get(
                "executive_narrative",
                {}
            )
        )

    with tabs[1]:

        render_table(
            "Executive Package",
            result.get(
                "executive_package",
                {}
            )
        )

    with tabs[2]:

        render_table(
            "Recommendation Package",
            result.get(
                "recommendation_package",
                {}
            )
        )

        render_table(
            "Technical Explanation",
            result.get(
                "technical_explanation",
                {}
            )
        )

    with tabs[3]:

        render_table(
            "Control Tower Summary",
            result.get(
                "control_tower_summary",
                {}
            )
        )

    # ======================================================
# Executive Dashboard
# ======================================================

    with tabs[4]:

        st.subheader("Executive Decision Dashboard")

        runtime = result.get(
            "runtime_summary",
            {}
        )

        control = result.get(
            "control_tower_summary",
            {}
        )

        recommendation = result.get(
            "recommendation",
            "-"
        )

        quality = _canonical_quality_scores(result)
        trust = f"{quality['trust_score']:.1f}"
        confidence = f"{quality['confidence']:.1f}"

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Recommendation",
            recommendation
        )

        c2.metric(
            "Trust Score",
            trust
        )

        c3.metric(
            "Confidence",
            confidence
        )

        c4.metric(
            "Runtime",
            runtime.get(
                "status",
                "-"
            )
        )

        st.divider()

        summary_rows = [

            {

                "Category":"Recommendation",

                "Value":recommendation

            },

            {

                "Category":"Trust Score",

                "Value":trust

            },

            {

                "Category":"Confidence",

                "Value":confidence

            },

            {

                "Category":"Decision",

                "Value":runtime.get(
                    "recommendation",
                    "-"
                )

            },

            {

                "Category":"Runtime Status",

                "Value":runtime.get(
                    "status",
                    "-"
                )

            },

            {

                "Category":"Overall Health",

                "Value":runtime.get(
                    "runtime_health",
                    "-"
                )

            }

        ]

        st.dataframe(

            pd.DataFrame(summary_rows),

            use_container_width=True,

            hide_index=True

        )

        executive = result.get(
            "executive_package",
            {}
        )

        if executive:

            st.divider()

            st.subheader(
                "Executive Package Summary"
            )

            render_table(

                "Executive Package",

                executive

            )

        narrative = result.get(
            "executive_narrative",
            {}
        )

        if narrative:

            st.divider()

            st.subheader(
                "Executive Narrative"
            )

            render_table(

                "Executive Narrative",

                narrative

            )

        recommendation_package = result.get(
            "recommendation_package",
            {}
        )

        if recommendation_package:

            st.divider()

            st.subheader(
                "Recommendation Summary"
            )

            render_table(

                "Recommendation Package",

                recommendation_package

            )

        technical = result.get(
            "technical_explanation",
            {}
        )

        if technical:

            st.divider()

            st.subheader(
                "Technical Summary"
            )

            render_table(

                "Technical Explanation",

                technical

            )

        if control:

            st.divider()

            st.subheader(
                "Control Tower Summary"
            )

            render_table(

                "Control Tower Summary",

                control

            )
    st.divider()


# ============================================================
# Runtime Explorer
# ============================================================

def render_runtime_explorer(result):

    with st.expander(
        " Runtime Explorer",
        expanded=False
    ):

        keys = sorted(result.keys())

        df = pd.DataFrame({

            "Object": keys,

            "Type": [

                type(result[k]).__name__

                for k in keys

            ]

        })

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# RECOMMENDATION CENTER V3
# ============================================================

def render_recommendation(result):

    st.header("Executive Recommendation")


    summary = result.get("runtime_summary", {})
    telemetry = result.get("runtime_telemetry", {})
    recommendation = (
        result.get("recommendation")
        or summary.get("recommendation")
        or "UNKNOWN"
    )
    telemetry = result.get("runtime_telemetry", {})

    package = result.get("recommendation_package", {})
    executive = result.get("executive_explanation", {})
    technical = result.get("technical_explanation", {})
    technical = dict(technical) if isinstance(technical, dict) else {}
    evidence_count = (
        result.get("evidence_count")
        or len(result.get("evidence_pack", []) or [])
        or len(result.get("retrieved_chunks", []) or [])
    )
    technical["evidence_count"] = evidence_count
    technical["grounded"] = technical.get("grounded", bool(evidence_count))
    hallucination_results = result.get("hallucination_results", {})
    if isinstance(hallucination_results, dict):
        technical["hallucination_risk"] = (
            hallucination_results.get("risk_level")
            or hallucination_results.get("hallucination_risk")
            or technical.get("hallucination_risk")
            or "LOW"
        )
    technical["explainability_status"] = technical.get("explainability_status", "PASS")

    # ======================================================
    # Executive KPI
    # ======================================================

    governance = _safe_dict(result.get("governance"))
    _, risk_level = _runtime_recommendation_and_risk(result)
    release_assessment = _governance_release_assessment(result)
    review_required = bool(release_assessment["review_required"])
    governance_status = release_assessment["governance_status"]

    c1, c2, c3, c4 = st.columns(4)

    release_route = release_assessment["release_route"]

    c1.metric(
        "Proposed Recommendation",
        recommendation
    )

    c2.metric(
        "Release Route",
        release_route
    )

    c3.metric(
        "Review Required",
        "YES" if review_required else "NO"
    )

    c4.metric(
        "Governance Status",
        governance_status
    )

    st.divider()


    tabs = st.tabs(

        [

            "Authority",

            "Recommendation",

            "Technical",

            "Decision Intelligence"

        ]

    )

    with tabs[0]:
        st.subheader("Recommendation Authority")
        authority = _safe_dict(result.get("recommendation_authority"))
        release_assessment = _governance_release_assessment(result)
        human_review_required = bool(release_assessment["review_required"])
        render_table(
            "Authority Summary",
            [
                {"Property": "Recommendation", "Value": recommendation},
                {"Property": "Decision", "Value": package.get("decision", recommendation) if isinstance(package, dict) else recommendation},
                {"Property": "Human Review Required", "Value": human_review_required},
                {"Property": "Release Route", "Value": release_assessment["release_route"]},
                {"Property": "Next Best Action", "Value": authority.get("next_best_action") or package.get("next_best_action", "-") if isinstance(package, dict) else "-"},
                {"Property": "Source", "Value": authority.get("source", "terminal_reconciliation")},
            ],
        )

    # ======================================================
    # Recommendation Package
    # ======================================================

    with tabs[1]:

        if package:

            rows = []

            for k, v in package.items():

                if isinstance(v, (dict, list)):

                    continue

                rows.append(

                    {

                        "Property": k.replace(
                            "_",
                            " "
                        ).title(),

                        "Value": v

                    }

                )

            if rows:

                st.dataframe(

                    pd.DataFrame(rows),

                    use_container_width=True,

                    hide_index=True

                )

    # ======================================================
    # Technical Explanation
    # ======================================================

    with tabs[2]:

        if technical:

            rows = []

            for k, v in technical.items():

                if isinstance(v, (dict, list)):

                    continue
                if _is_unknown_value(v) and k in {"trust_score", "evidence_count"}:
                    continue

                rows.append(

                    {

                        "Property": k.replace(
                            "_",
                            " "
                        ).title(),

                        "Value": v

                    }

                )

            st.dataframe(

                pd.DataFrame(rows),

                use_container_width=True,

                hide_index=True

            )

            reason = technical.get(
                "reason"
            )

            if reason:

                st.divider()

                st.subheader(
                    "Technical Reason"
                )

                st.info(reason)

    # ======================================================
# Decision Intelligence
# ======================================================

    with tabs[3]:

        st.subheader("Decision Intelligence")

        c1, c2 = st.columns(2)

        c1.metric(
            "Recommendation",
            recommendation
        )

        c2.metric(
            "Decision",
            package.get(
                "decision",
                recommendation
            )
        )

        st.divider()

        rows = [

            {

                "Property":"Recommendation",

                "Value":recommendation

            },

            {

                "Property":"Decision",

                "Value":package.get(
                    "decision",
                    recommendation
                )

            },

            {

                "Property":"Recommendation Type",

                "Value":package.get(
                    "recommendation_type",
                    "-"
                )

            },

            {

                "Property":"Application Impact",

                "Value":package.get(
                    "business_impact",
                    "-"
                )

            },

            {

                "Property":"Risk Level",

                "Value":package.get(
                    "risk_level",
                    "-"
                )

            },

            {

                "Property":"Priority",

                "Value":package.get(
                    "priority",
                    "-"
                )

            }

        ]

        st.dataframe(

            pd.DataFrame(rows),

            use_container_width=True,

            hide_index=True

        )

        simulations = package.get(
            "simulations",
            []
        )

        if simulations:

            st.divider()

            st.subheader(
                "Simulation Results"
            )

            st.dataframe(

                pd.DataFrame(simulations),

                use_container_width=True,

                hide_index=True

            )

        alternatives = package.get(
            "alternative_recommendations",
            []
        )

        if alternatives:

            st.divider()

            st.subheader(
                "Alternative Recommendations"
            )

            alt_df = pd.DataFrame(

                {

                    "Alternative": alternatives

                }

            )

            st.dataframe(

                alt_df,

                use_container_width=True,

                hide_index=True

            )

        decision_path = package.get(
            "decision_path",
            []
        )

        if decision_path:

            st.divider()

            st.subheader(
                "Decision Flow"
            )

            flow_rows = []

            for idx, step in enumerate(
                decision_path,
                start=1
            ):

                flow_rows.append(

                    {

                        "Step": idx,

                        "Decision Stage": step

                    }

                )

            st.dataframe(

                pd.DataFrame(flow_rows),

                use_container_width=True,

                hide_index=True

            )

        impact = package.get(
            "impact_analysis",
            {}
        )

        if impact:

            st.divider()

            st.subheader(
                "Impact Analysis"
            )

            render_table(

                "Impact Analysis",

                impact

            )

        recommendation_llm = package.get(
            "recommendation_llm",
            {}
        )

        if recommendation_llm:

            st.divider()

            st.subheader(
                "Recommendation LLM"
            )

            render_table(

                "Recommendation LLM",

                recommendation_llm

            )
    st.divider()

# ============================================================
# Control Tower
# ============================================================

# ============================================================
# OWASP SECURITY CENTER
# ============================================================

def render_owasp_security(result):

        st.header("OWASP Security Center")

        security = result.get("security_analysis") or result.get("security") or {}

        if not isinstance(security, dict) or not security:
            st.info("No security analysis available.")
            return

        score = _numeric_score(security.get("security_score", 0))
        security_status = security.get("security_status") or security.get("status") or "UNKNOWN"

        grade = security.get("security_grade")
        if not grade:
            grade = "N/A" if security_status == "ERROR" else (
                "A+" if score >= 95 else "A" if score >= 90 else
                "B" if score >= 80 else "C" if score >= 70 else "D"
            )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Security Score",
            score
        )

        c2.metric(
            "Risk Level",
            security.get("risk_level", "-")
        )

        c3.metric(
            "Overall Status",
            security_status
        )

        c4.metric(
            "OWASP Grade",
            grade
        )

        if security_status == "ERROR":
            st.error(f"Security analysis failed: {security.get('error', 'unknown validation error')}")

        st.divider()

        # ----------------------------------------------------
        # OWASP Controls
        # ----------------------------------------------------

        st.subheader("OWASP Security Controls")
        render_security_control_heatmap(security)

        controls = [

            {
                "OWASP Control": "Prompt Injection",
                "Status": security.get(
                    "prompt_injection",
                    {}
                ).get(
                    "status",
                    "-"
                ),
                "Detected": security.get(
                    "prompt_injection",
                    {}
                ).get(
                    "detected",
                    "-"
                )
            },

            {
                "OWASP Control": "Jailbreak Detection",
                "Status": security.get(
                    "jailbreak_detection",
                    {}
                ).get(
                    "status",
                    "-"
                ),
                "Detected": security.get(
                    "jailbreak_detection",
                    {}
                ).get(
                    "detected",
                    "-"
                )
            },

            {
                "OWASP Control": "Sensitive Data Exposure",
                "Status": security.get(
                    "pii_exposure",
                    {}
                ).get(
                    "status",
                    "-"
                ),
                "Detected": len(
                    security.get(
                        "pii_exposure",
                        {}
                    ).get(
                        "sensitive_fields",
                        []
                    )
                )
            },

            {
                "OWASP Control": "Data Leakage",
                "Status": security.get(
                    "data_leakage",
                    {}
                ).get(
                    "status",
                    "-"
                ),
                "Detected": security.get(
                    "data_leakage",
                    {}
                ).get(
                    "detected",
                    "-"
                )
            },

            {
                "OWASP Control": "Tool Security",
                "Status": security.get(
                    "tool_security",
                    {}
                ).get(
                    "status",
                    "-"
                ),
                "Detected": len(
                    security.get(
                        "tool_security",
                        {}
                    ).get(
                        "unauthorized_tools",
                        []
                    )
                )
            }

        ]

        st.dataframe(
            pd.DataFrame(_complete_security_controls(security, controls)),
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # ----------------------------------------------------
        # Executive Assessment
        # ----------------------------------------------------

        llm = security.get(
            "security_llm",
            {}
        )

        parsed = llm.get(
            "parsed_output",
            {}
        )

        st.subheader("Executive Security Assessment")

        if parsed:

            st.success(

                parsed.get(

                    "executive_summary",

                    "Security assessment completed."

                )

            )

        else:

            failed = security.get("failed_controls", [])
            review = security.get("review_controls", [])
            if failed:
                st.error("Security controls failed: " + ", ".join(map(str, failed)))
            elif review:
                st.warning("Security controls requiring review: " + ", ".join(map(str, review)))
            else:
                st.success("All evaluated OWASP security controls passed.")

        st.divider()

        # ----------------------------------------------------
        # Identified Risks
        # ----------------------------------------------------

        st.subheader("Identified Risks")

        risks = parsed.get(
            "identified_risks",
            []
        )

        if risks:

            risk_df = pd.DataFrame(

                {

                    "Risk": risks

                }

            )

            st.dataframe(

                risk_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            st.success(

                "No active security risks detected."

            )

        st.divider()

        # ----------------------------------------------------
        # Recommended Actions
        # ----------------------------------------------------

        st.subheader("Recommended Actions")

        actions = parsed.get(
            "recommended_actions",
            []
        )

        if actions:

            action_df = pd.DataFrame(

                {

                    "Priority": range(
                        1,
                        len(actions) + 1
                    ),

                    "Action": actions

                }

            )

            st.dataframe(

                action_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            st.success(

                "No remediation actions required."

            )

        st.divider()

        # ----------------------------------------------------
        # Security Agents
        # ----------------------------------------------------

        st.subheader("Security Agents")

        rows = []

        for agent_name, agent in _safe_dict(security).get(
            "agents",
            {}
        ).items():

            rows.append(

                {

                    "Agent": agent_name,

                    "Status": _safe_get(
                        agent,
                        "status",
                        "-"
                    ),

                    "Confidence": _safe_get(
                        agent,
                        "confidence",
                        "-"
                    )

                }

            )

        if rows:

            st.dataframe(

                pd.DataFrame(rows),

                use_container_width=True,

                hide_index=True

            )

        st.divider()

        # ----------------------------------------------------
        # Security Timeline
        # ----------------------------------------------------

        st.subheader("Security Timeline")

        timeline = [

            {

                "Stage": "Prompt Injection",

                "Result": security.get(
                    "prompt_injection",
                    {}
                ).get(
                    "status",
                    "-"
                )

            },

            {

                "Stage": "Jailbreak",

                "Result": security.get(
                    "jailbreak_detection",
                    {}
                ).get(
                    "status",
                    "-"
                )

            },

            {

                "Stage": "PII Exposure",

                "Result": security.get(
                    "pii_exposure",
                    {}
                ).get(
                    "status",
                    "-"
                )

            },

            {

                "Stage": "Data Leakage",

                "Result": security.get(
                    "data_leakage",
                    {}
                ).get(
                    "status",
                    "-"
                )

            },

            {

                "Stage": "Tool Security",

                "Result": security.get(
                    "tool_security",
                    {}
                ).get(
                    "status",
                    "-"
                )

            }

        ]

        st.dataframe(

            pd.DataFrame(timeline),

            use_container_width=True,

            hide_index=True

        )

        st.divider()

def _reported(value, default=None):
    if value in (None, "", [], {}):
        return default
    return value


def _technical_rows(rows):
    """Keep technical facts only when the runtime supplied a value."""
    return [
        row for row in rows
        if any(
            value not in (None, "", "Not reported", "Unavailable", "N/A")
            for index, value in enumerate(row.values())
            if index > 0
        )
    ]


def _asset_status(value):
    text = str(value or "").upper()
    if text in {"COMPLETED", "SUCCESS", "PASS", "COMPLIANT", "SAVED", "ACTIVE", "OBSERVED"}:
        return "Active"
    if text in {"FAILED", "ERROR", "FAIL", "BLOCKED"}:
        return "Exception"
    if text in {"NOT EXECUTED", "SKIPPED", "PLANNED"}:
        return "Planned"
    return text.title() if text and text != "-" else "Registered"


def _normalize_model_asset(provider, model):
    provider_text = str(provider or "").strip()
    model_text = str(model or "").strip()
    artifact_location = "-"
    engine_keywords = ("policy-engine", "deterministic", "rules-engine", "risk-engine")
    asset_type = "Runtime Engine" if any(keyword in model_text.lower() for keyword in engine_keywords) or provider_text.upper() == "AEGIS_DETERMINISTIC" else "LLM Model"

    if model_text and (":\\" in model_text or "/" in model_text or "\\models--" in model_text or "models--" in model_text):
        artifact_location = model_text
        match = re.search(r"models--([^\\/]+)--([^\\/]+)", model_text)
        if match:
            model_text = f"{match.group(1)}/{match.group(2)}"
        else:
            model_text = Path(model_text).name or model_text
    if model_text.endswith("snapshots") or model_text == "snapshots":
        parent = Path(artifact_location).parent if artifact_location != "-" else None
        if parent:
            match = re.search(r"models--([^\\/]+)--([^\\/]+)", str(parent))
            if match:
                model_text = f"{match.group(1)}/{match.group(2)}"
    if provider_text.upper() == "LOCAL" and model_text.lower().startswith("models--"):
        model_text = model_text.replace("models--", "").replace("--", "/")
    if asset_type == "Runtime Engine" and not provider_text:
        provider_text = "AEGIS_DETERMINISTIC"
    return asset_type, provider_text or "-", model_text or "-", artifact_location


def _observed_llm_assets(result):
    rows = []
    seen = set()
    registry = result.get("llm_registry", {})
    sources = list(registry.items()) if isinstance(registry, dict) else []
    llm_trace = result.get("llm_trace", [])
    if isinstance(llm_trace, list):
        sources.extend(
            (row.get("agent_name") or row.get("agent") or "Runtime", row)
            for row in llm_trace
            if isinstance(row, dict)
        )
    elif isinstance(llm_trace, dict):
        sources.extend(llm_trace.items())
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    if telemetry.get("model") or telemetry.get("provider"):
        sources.append(("Runtime", telemetry))

    for role, raw in sources:
        for detail in (raw if isinstance(raw, list) else [raw]):
            if not isinstance(detail, dict):
                continue
            nested = _safe_dict(detail.get("telemetry"))
            provider = detail.get("provider") or nested.get("provider")
            model = detail.get("model") or detail.get("model_name") or nested.get("model")
            if not provider and not model:
                continue
            asset_type, provider_name, model_name, artifact_location = _normalize_model_asset(provider, model)
            key = (str(role), str(provider_name), str(model_name), str(asset_type))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "Asset ID": f"{'ENGINE' if asset_type == 'Runtime Engine' else 'MODEL'}::{str(role).replace(' ', '_').upper()}",
                "Asset Type": asset_type,
                "Owner / Role": str(role).replace("_", " ").title(),
                "Provider": provider_name,
                "Name / Version": model_name,
                "Artifact / Runtime Location": artifact_location,
                "Status": _asset_status(detail.get("status") or ("SUCCESS" if detail.get("success") else "OBSERVED")),
                "Governance Signal": "Deterministic policy engine" if asset_type == "Runtime Engine" else "Model/provider observed in runtime telemetry",
            })
    return rows


def _asset_file_metadata(path_text):
    path = Path(str(path_text))
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    if not path.exists() or not path.is_file():
        return {"Size": "-", "Last Modified": "-"}
    return {
        "Size": f"{path.stat().st_size:,} bytes",
        "Last Modified": path.stat().st_mtime,
    }


def render_ai_asset_registry(result):
    st.header("AI Asset Registry")
    st.caption(
        "Governed inventory of the agents, models, prompts, data sources, vector assets, tools, controls, and audit records used by this AEGIS run."
    )

    trace = _normalized_agent_trace(result)
    agent_counts = _canonical_agent_counts(result)
    model_assets = _observed_llm_assets(result)
    evidence_rows = []
    for key in ("evidence_pack", "retrieved_chunks"):
        value = result.get(key)
        if isinstance(value, list):
            evidence_rows.extend(value)
    source_names = sorted({
        str(_evidence_item_source(row))
        for row in evidence_rows
        if isinstance(row, dict) and _evidence_item_source(row) not in {"-", "", "Unresolved source"}
    })
    vector_inventory = result.get("vector_inventory", [])
    vector_count = len(vector_inventory) if isinstance(vector_inventory, list) else _safe_count(vector_inventory)
    tools = result.get("selected_tools") or _safe_get(result, "planner", {}).get("selected_tools") or []
    if isinstance(tools, dict):
        tools = list(tools.values())
    tools = tools if isinstance(tools, list) else []
    export = _safe_dict(result.get("artifact_export"))
    ledger = _safe_dict(export.get("audit_ledger"))

    render_compact_status_grid([
        ("Agents Registered", agent_counts.get("total", 0)),
        ("Agents Executed", agent_counts.get("executed", 0)),
        ("Models Observed", len(model_assets)),
        ("Data Sources", len(source_names)),
        ("Vector Assets", vector_count),
        ("Tools Registered", len(tools)),
        ("Audit Ledger", ledger.get("status", "-")),
        ("Runtime ID", result.get("runtime_id", "-")),
    ])

    tabs = st.tabs([
        "Agents",
        "Models & Engines",
        "Prompts & Queries",
        "Data & Vector Assets",
        "Tools",
        "Controls",
        "Audit Assets",
    ])

    with tabs[0]:
        agent_rows = []
        for row in trace:
            if not isinstance(row, dict):
                continue
            agent = row.get("agent") or row.get("agent_name") or "-"
            agent_rows.append({
                "Asset ID": f"AGENT::{str(agent).replace(' ', '_').upper()}",
                "Agent": agent,
                "Phase": row.get("phase", "-"),
                "Tool": row.get("tool_used") or row.get("tool") or "-",
                "Execution Status": row.get("status", "-"),
                "Registry Status": _asset_status(row.get("status")),
                "Execution Time": _format_agent_latency(row.get("duration_ms", 0)),
                "Execution Count": row.get("execution_count", 1),
                "Skip / Exception Reason": row.get("skip_reason") or row.get("reason") or "-",
            })
        render_table("Registered Agents", agent_rows)

    with tabs[1]:
        if model_assets:
            render_table("Registered Models & Runtime Engines", model_assets)
        else:
            st.info("No model/provider telemetry was captured for this run.")

    with tabs[2]:
        query_rows = [
            {
                "Asset ID": "PROMPT::USER_QUERY",
                "Prompt / Query Asset": "Original User Query",
                "Version / Hash": str(abs(hash(str(result.get("user_query") or result.get("query") or ""))))[:10],
                "Status": "Captured" if (result.get("user_query") or result.get("query")) else "Not captured",
                "Content Preview": _narrative_text(result.get("user_query") or result.get("query"), "-")[:300],
            },
            {
                "Asset ID": "PROMPT::UPDATED_QUERY",
                "Prompt / Query Asset": "Updated / Rewritten Query",
                "Version / Hash": str(abs(hash(str(result.get("updated_query") or result.get("rewritten_query") or result.get("cache_key_query") or ""))))[:10],
                "Status": "Captured" if (result.get("updated_query") or result.get("rewritten_query") or result.get("cache_key_query")) else "Not captured",
                "Content Preview": _narrative_text(result.get("updated_query") or result.get("rewritten_query") or result.get("cache_key_query"), "-")[:300],
            },
        ]
        render_table("Prompt & Query Assets", query_rows)

    with tabs[3]:
        data_rows = []
        source_counts = {}
        for row in evidence_rows:
            if not isinstance(row, dict):
                continue
            source = str(_evidence_item_source(row))
            if source in {"-", "", "Unresolved source"}:
                continue
            source_counts[source] = source_counts.get(source, 0) + 1
        for source, count in sorted(source_counts.items()):
            metadata = _asset_file_metadata(source)
            data_rows.append({
                "Asset ID": f"DATA::{source.upper()}",
                "Asset Type": "Evidence Source",
                "Source": source,
                "Observed Evidence Rows": count,
                "Size": metadata["Size"],
                "Last Modified": metadata["Last Modified"],
                "Status": "Observed",
                "Governance Signal": "Customer-scoped evidence source",
            })
        embedding_model = (
            _safe_get(result, "retrieval", {}).get("embedding_model")
            or result.get("embedding_model")
            or _safe_get(result, "embedding_statistics", {}).get("model")
            or "BAAI/bge-small-en-v1.5"
        )
        data_rows.append({
            "Asset ID": "VECTOR::CUSTOMER_EVIDENCE_INDEX",
            "Asset Type": "Vector Index",
            "Source": "vector_db / embedding index",
            "Observed Evidence Rows": vector_count,
            "Size": "-",
            "Last Modified": "-",
            "Status": "Active" if vector_count else "Registered",
            "Governance Signal": f"Embedding model: {embedding_model}",
        })
        render_table("Data, Evidence & Vector Assets", data_rows)

    with tabs[4]:
        tool_rows = []
        for index, tool in enumerate(tools, start=1):
            if isinstance(tool, dict):
                name = tool.get("name") or tool.get("tool") or tool.get("id") or f"Tool {index}"
                status = tool.get("status") or tool.get("availability") or "Registered"
            else:
                name = str(tool)
                status = "Registered"
            tool_rows.append({
                "Asset ID": f"TOOL::{str(name).replace(' ', '_').upper()}",
                "Tool": name,
                "Status": _asset_status(status),
                "Governance Signal": "Selected by planner/tool router" if tools else "-",
            })
        if not tool_rows:
            tool_rows = [{"Asset ID": "TOOL::NONE_RECORDED", "Tool": "-", "Status": "Not captured", "Governance Signal": "No selected tool list was published"}]
        render_table("Registered Tools", tool_rows)

    with tabs[5]:
        recommendation, risk_level = _runtime_recommendation_and_risk(result)
        controls = [
            ("POLICY::OWASP_LLM", "OWASP AI Controls", "Prompt injection, jailbreak, PII, data leakage, tool security", "Active"),
            ("POLICY::GOVERNANCE", "Governance Decision Policy", f"Recommendation {recommendation}; Risk {risk_level}", "Active"),
            ("POLICY::COMPLIANCE", "KYC / AML Compliance", _canonical_compliance_status(result), "Active"),
            ("POLICY::HITL", "Human Review Threshold", "Review required when risk/evidence/recommendation requires oversight", "Active"),
            ("POLICY::GROUNDING", "Grounding & Hallucination Guard", f"Hallucination {_canonical_quality_scores(result)['hallucination_risk']}", "Active"),
            ("POLICY::CACHE", "Cache Reuse Policy", str(_runtime_cache_payload(result).get("status", "-")), "Active"),
        ]
        render_table("Registered Controls & Policies", [
            {"Asset ID": asset_id, "Control / Policy": name, "Scope": scope, "Status": status}
            for asset_id, name, scope, status in controls
        ])

    with tabs[6]:
        manifest = _safe_dict(export.get("manifest"))
        files = manifest.get("files", []) if isinstance(manifest.get("files"), list) else []
        audit_rows = [
            {
                "Asset ID": "AUDIT::LEDGER",
                "Audit Asset": "SQLite Audit Ledger",
                "Status": ledger.get("status", "-"),
                "Location": ledger.get("path", "-"),
            },
            {
                "Asset ID": "AUDIT::PACKAGE",
                "Audit Asset": "Investigation Evidence Package",
                "Status": export.get("status", "-"),
                "Location": export.get("zip_path", "-"),
            },
        ]
        for file_info in files[:20]:
            if isinstance(file_info, dict):
                audit_rows.append({
                    "Asset ID": f"AUDIT_FILE::{file_info.get('name', '-')}",
                    "Audit Asset": file_info.get("name", "-"),
                    "Status": "Saved",
                    "Location": export.get("directory", "-"),
                    "Size / Hash": f"{file_info.get('bytes', '-')} bytes; sha256 {str(file_info.get('sha256', '-'))[:16]}",
                })
        render_table("Registered Audit Assets", audit_rows)


def _aegis_output_file(filename):
    return Path(__file__).resolve().parents[2] / "outputs" / filename


def _download_output_asset(label, filename, mime, key):
    path = _aegis_output_file(filename)
    if not path.exists():
        st.caption(f"{label}: file not generated yet.")
        return
    st.download_button(
        label,
        data=path.read_bytes(),
        file_name=path.name,
        mime=mime,
        key=key,
    )


@st.cache_data(show_spinner=False)
def _load_onboarding_contract(workbook_path):
    path = Path(workbook_path)
    if not path.exists():
        return {}
    try:
        return pd.read_excel(path, sheet_name=None)
    except Exception:
        return {}


def render_reference_architecture_visual(title="AEGIS Reference Architecture", caption=None, show_positioning=False):
    svg_path = _aegis_output_file("aegis-control-tower-architecture.svg")
    st.subheader(title)
    if caption:
        st.caption(caption)
    if not svg_path.exists():
        st.info("Architecture diagram has not been generated yet.")
        return
    svg = svg_path.read_text(encoding="utf-8")
    st.markdown(
        """
        <style>
        .aegis-architecture-wrap {
            width: 100%;
            overflow-x: auto;
            background: #ffffff;
            border: 1px solid #d8dee9;
            border-radius: 8px;
            padding: 10px;
        }
        .aegis-architecture-wrap svg {
            width: 100%;
            min-width: 900px;
            height: auto;
            display: block;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div class='aegis-architecture-wrap'>{svg}</div>",
        unsafe_allow_html=True,
    )


def render_control_tower_architecture(result):
    st.header("Control Tower Architecture")
    st.caption(
        "Boardroom view of how enterprise AI applications connect to the AEGIS control plane through canonical runtime events "
        "and final decision records."
    )

    render_reference_architecture_visual(
        title="AEGIS Reference Architecture",
        caption=(
            "AEGIS observes and governs AI applications built across Dify, Claude, OpenAI, Azure AI Foundry, "
            "LangChain, Bedrock, and custom agentic systems."
        ),
        show_positioning=False,
    )


def _agent_canonical_parameter_rows():
    return [
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "agent_id",
            "Type": "string",
            "Required": "Mandatory",
            "Description": "Stable unique identifier for the agent execution node.",
            "AEGIS Pillar": "Auditable AI, Scalable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "agent_name",
            "Type": "string",
            "Required": "Mandatory",
            "Description": "Human-readable agent name shown in trace, graph, audit package, and reports.",
            "AEGIS Pillar": "Measurable AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "agent_type",
            "Type": "enum",
            "Required": "Mandatory",
            "Description": "Application Workflow Agent, AEGIS Control Agent, Tool Agent, Retrieval Agent, or External Service Agent.",
            "AEGIS Pillar": "Governable AI, Scalable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "phase",
            "Type": "string / enum",
            "Required": "Mandatory",
            "Description": "Execution phase such as query rewrite, planning, retrieval, governance, grounding, recommendation, or audit.",
            "AEGIS Pillar": "Measurable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "execution_order",
            "Type": "integer",
            "Required": "Mandatory",
            "Description": "Observed order in the runtime trace. Parallel agents can share stage_id while keeping their own order.",
            "AEGIS Pillar": "Measurable AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "stage_id",
            "Type": "string",
            "Required": "Optional",
            "Description": "Groups agents that run in parallel or as co-equal controls in the same execution stage.",
            "AEGIS Pillar": "Measurable AI, Resilient AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "status",
            "Type": "enum",
            "Required": "Mandatory",
            "Description": "NOT_STARTED, RUNNING, COMPLETED, SKIPPED, FAILED, DEGRADED, or TIMEOUT.",
            "AEGIS Pillar": "Measurable AI, Resilient AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "started_at / completed_at",
            "Type": "ISO-8601 datetime",
            "Required": "Mandatory",
            "Description": "Start and completion timestamps used for runtime observability and audit reconstruction.",
            "AEGIS Pillar": "Measurable AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "duration_ms",
            "Type": "integer",
            "Required": "Mandatory",
            "Description": "Measured execution time in milliseconds. Used for bottleneck analysis, not for cost allocation.",
            "AEGIS Pillar": "Measurable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "retry_count",
            "Type": "integer",
            "Required": "Mandatory",
            "Description": "Number of retry attempts actually performed by the agent or runtime wrapper.",
            "AEGIS Pillar": "Resilient AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "max_retries",
            "Type": "integer",
            "Required": "Mandatory",
            "Description": "Configured retry limit for the agent invocation.",
            "AEGIS Pillar": "Resilient AI, Governable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "retry_reason",
            "Type": "string",
            "Required": "Optional",
            "Description": "Reason for retry, such as timeout, rate limit, validation failure, transient API error, or parsing failure.",
            "AEGIS Pillar": "Resilient AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "previous_agents / next_agents",
            "Type": "array[string]",
            "Required": "Mandatory",
            "Description": "Lineage links showing where the agent received input from and where it passed output next.",
            "AEGIS Pillar": "Auditable AI, Measurable AI",
        },
        {
            "Agent Category": "LLM Agents",
            "Canonical Parameter": "provider / model / model_version",
            "Type": "string",
            "Required": "Mandatory",
            "Description": "Model provider and version used by the agent, for model governance and repeatability.",
            "AEGIS Pillar": "Governable AI, Auditable AI",
        },
        {
            "Agent Category": "LLM Agents",
            "Canonical Parameter": "prompt_hash / prompt_template_id",
            "Type": "string",
            "Required": "Mandatory",
            "Description": "Prompt identity without exposing sensitive full prompt text by default.",
            "AEGIS Pillar": "Governable AI, Auditable AI",
        },
        {
            "Agent Category": "LLM Agents",
            "Canonical Parameter": "input_tokens / output_tokens / total_tokens",
            "Type": "integer",
            "Required": "Mandatory",
            "Description": "Token usage for cost, capacity, and model economics.",
            "AEGIS Pillar": "Measurable AI, Scalable AI",
        },
        {
            "Agent Category": "Retrieval Agents",
            "Canonical Parameter": "retrieval_method",
            "Type": "enum",
            "Required": "Mandatory",
            "Description": "BM25, semantic/vector, hybrid, graph, SQL, API, or cache.",
            "AEGIS Pillar": "Trustworthy AI, Auditable AI",
        },
        {
            "Agent Category": "Retrieval Agents",
            "Canonical Parameter": "retrieved_chunks / reranked_chunks",
            "Type": "array[object]",
            "Required": "Mandatory",
            "Description": "Evidence candidates before and after reranking, with source, rank, score, and content hash.",
            "AEGIS Pillar": "Trustworthy AI, Auditable AI",
        },
        {
            "Agent Category": "Control Agents",
            "Canonical Parameter": "control_id / control_status / findings",
            "Type": "string / enum / array",
            "Required": "Mandatory",
            "Description": "Governance, OWASP, grounding, hallucination, PII, compliance, and policy control outcomes.",
            "AEGIS Pillar": "Governable AI, Trustworthy AI",
        },
        {
            "Agent Category": "Decision Agents",
            "Canonical Parameter": "recommendation / risk_level / confidence / rationale",
            "Type": "string / numeric",
            "Required": "Mandatory",
            "Description": "Decision tuple required before release: recommendation is the action, risk_level is the exposure, confidence is decision certainty, and rationale explains why the action is allowed or needs review.",
            "AEGIS Pillar": "Trustworthy AI, Governable AI, Auditable AI",
        },
        {
            "Agent Category": "All Agents",
            "Canonical Parameter": "error_code / error_message / fallback_used",
            "Type": "string / boolean",
            "Required": "Mandatory when applicable",
            "Description": "Failure and degraded-mode signal used for resilience monitoring and alerting.",
            "AEGIS Pillar": "Resilient AI, Auditable AI",
        },
    ]


def _split_canonical_parameter_names(parameter):
    text = str(parameter or "").replace(" / ", "/").replace(",", "/")
    return [part.strip() for part in text.split("/") if part.strip()]


def _canonical_parameter_catalog_rows():
    examples = {
        "agent_id": "agent_customer_context_01",
        "agent_name": "Customer 360 Investigation",
        "agent_type": "Application Workflow Agent",
        "phase": "Evidence Retrieval",
        "execution_order": "4",
        "stage_id": "evidence_runtime",
        "status": "COMPLETED",
        "started_at": "2026-07-22T13:58:02.601902",
        "completed_at": "2026-07-22T13:58:03.212911",
        "duration_ms": "611",
        "retry_count": "0",
        "max_retries": "2",
        "retry_reason": "timeout",
        "previous_agents": "[\"App Planner\"]",
        "next_agents": "[\"Evidence Packager\"]",
        "provider": "OpenAI",
        "model": "gpt-4.1",
        "model_version": "2026-xx",
        "prompt_hash": "sha256:ab12...",
        "prompt_template_id": "fraud-review-v3",
        "input_tokens": "147",
        "output_tokens": "440",
        "total_tokens": "587",
        "retrieval_method": "Hybrid BM25 + Vector",
        "retrieved_chunks": "[{\"chunk_id\":\"TX001\",\"rank\":1,\"score\":0.87}]",
        "reranked_chunks": "[{\"chunk_id\":\"TX001\",\"rank\":1,\"score\":0.92}]",
        "control_id": "OWASP-LLM02",
        "control_status": "REVIEW",
        "findings": "PII-like fields observed",
        "recommendation": "APPROVE",
        "risk_level": "LOW",
        "confidence": "65.86",
        "rationale": "Policy-approved route with evidence-backed response.",
        "error_code": "TIMEOUT",
        "error_message": "API timeout",
        "fallback_used": "true",
    }
    lifecycle_overrides = {
        "stage_id": "Runtime",
        "retry_reason": "Runtime when retry occurs",
        "prompt_hash": "Before release + runtime",
        "prompt_template_id": "Before release + runtime",
        "provider": "Before release + runtime",
        "model": "Before release + runtime",
        "model_version": "Before release + runtime",
        "control_id": "Runtime before release gate",
        "control_status": "Runtime before release gate",
        "findings": "Runtime before release gate",
        "recommendation": "Runtime before release gate",
        "risk_level": "Runtime before release gate",
        "confidence": "Runtime before release gate",
        "rationale": "Runtime before release gate",
        "error_code": "Runtime when failure/degradation occurs",
        "error_message": "Runtime when failure/degradation occurs",
        "fallback_used": "Runtime when failure/degradation occurs",
    }
    object_descriptions = {
        "recommendation": "Final proposed application/action decision from the agent, such as APPROVE, MONITOR, ESCALATE, RETRY, REVIEW, or BLOCK.",
        "risk_level": "Risk exposure attached to the recommendation, so AEGIS can apply policy, HITL, and release routing.",
        "confidence": "Decision certainty score used to decide whether the output is strong enough for release or needs review.",
        "rationale": "Human-readable explanation for why the recommendation and risk decision were reached.",
    }
    type_overrides = {
        "started_at": "datetime",
        "completed_at": "datetime",
        "previous_agents": "array[string]",
        "next_agents": "array[string]",
        "provider": "string",
        "model": "string",
        "model_version": "string",
        "prompt_hash": "string",
        "prompt_template_id": "string",
        "input_tokens": "integer",
        "output_tokens": "integer",
        "total_tokens": "integer",
        "retrieved_chunks": "array[object]",
        "reranked_chunks": "array[object]",
        "control_id": "string",
        "control_status": "string",
        "findings": "array[string] or string",
        "recommendation": "string",
        "risk_level": "string",
        "confidence": "numeric",
        "rationale": "string",
        "error_code": "string",
        "error_message": "string",
        "fallback_used": "boolean",
    }
    catalog = []
    serial = 1
    for row in _agent_canonical_parameter_rows():
        raw_parameter = row.get("Canonical Parameter")
        required = str(row.get("Required") or "")
        if "Optional" in required:
            mandatory_label = "Non Mandatory"
        elif "when applicable" in required.casefold():
            mandatory_label = "Conditional Mandatory"
        else:
            mandatory_label = "Mandatory"
        parameters = _split_canonical_parameter_names(raw_parameter)
        if not parameters:
            parameters = [raw_parameter]
        for parameter in parameters:
            lifecycle = lifecycle_overrides.get(parameter, lifecycle_overrides.get(raw_parameter, "Runtime"))
            runtime_classification = (
                "Runtime parameter"
                if str(lifecycle).startswith("Runtime")
                else "Pre-release + runtime enrichment"
            )
            catalog.append(
                {
                    "#": serial,
                    "Canonical Object / Parameter": parameter,
                    "Original Contract Group": raw_parameter,
                    "Agent Category": row.get("Agent Category"),
                    "Data Type": type_overrides.get(parameter, row.get("Type")),
                    "Mandatory / Non Mandatory": mandatory_label,
                    "Runtime Classification": runtime_classification,
                    "Emission Stage": lifecycle,
                    "Example Value": examples.get(parameter, "-"),
                    "Why AEGIS Requires It": object_descriptions.get(parameter, row.get("Description")),
                    "Used For": row.get("AEGIS Pillar"),
                    "Expected Source": "Runtime log/event, SDK payload, API callback, or pre-release onboarding contract",
                }
            )
            serial += 1
    return catalog


def _dataframe_to_xlsx_bytes(df, sheet_name="Canonical Parameters"):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name[:31])
    output.seek(0)
    return output.getvalue()


def _persona_tabs_to_xlsx_bytes(rows_by_persona):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        index_rows = []
        used_sheet_names = set()
        for persona, rows in rows_by_persona.items():
            base_sheet_name = re.sub(r"[\\/*?:\[\]]", " ", str(persona)).strip()[:31] or "Persona"
            sheet_name = base_sheet_name
            suffix = 2
            while sheet_name in used_sheet_names:
                suffix_text = f" {suffix}"
                sheet_name = f"{base_sheet_name[:31 - len(suffix_text)]}{suffix_text}"
                suffix += 1
            used_sheet_names.add(sheet_name)

            persona_df = _arrow_safe_dataframe(rows)
            persona_df.to_excel(writer, index=False, sheet_name=sheet_name)
            index_rows.append({"Persona": persona, "Worksheet": sheet_name, "Metric Count": len(rows)})

            worksheet = writer.sheets[sheet_name]
            worksheet.freeze_panes = "A2"
            for column_cells in worksheet.columns:
                max_length = max(len(str(cell.value or "")) for cell in column_cells)
                worksheet.column_dimensions[column_cells[0].column_letter].width = min(max(max_length + 2, 16), 60)

        index_df = pd.DataFrame(index_rows)
        index_df.to_excel(writer, index=False, sheet_name="Index")
        index_sheet = writer.sheets["Index"]
        index_sheet.freeze_panes = "A2"
        for column_cells in index_sheet.columns:
            max_length = max(len(str(cell.value or "")) for cell in column_cells)
            index_sheet.column_dimensions[column_cells[0].column_letter].width = min(max(max_length + 2, 16), 50)
    output.seek(0)
    return output.getvalue()


def _agent_adoption_registry_rows(result):
    registry = result.get("agent_adoption_registry") or result.get("agent_registry") or result.get("adopted_agents") or []
    if isinstance(registry, dict):
        registry = registry.get("agents") or registry.get("items") or list(registry.values())
    rows = []
    if isinstance(registry, list):
        for index, item in enumerate(registry, start=1):
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "Agent ID": item.get("agent_id") or item.get("id") or f"agent_{index}",
                    "Agent Name": item.get("agent_name") or item.get("name") or "-",
                    "Version": item.get("version") or item.get("agent_version") or "-",
                    "Owner / Team": item.get("owner") or item.get("team") or "-",
                    "Environment": item.get("environment") or item.get("runtime_env") or "-",
                    "Adoption Status": item.get("adoption_status") or item.get("status") or "REGISTERED",
                    "Downloaded / Adopted By": item.get("downloaded_by") or item.get("adopted_by") or "-",
                    "Downloaded At": item.get("downloaded_at") or item.get("adopted_at") or "-",
                    "Usage Count": item.get("usage_count") or item.get("runs") or "-",
                    "Last Used At": item.get("last_used_at") or item.get("last_run_at") or "-",
                    "Source Variable": "agent_adoption_registry / agent_registry / adopted_agents",
                }
            )
    if rows:
        return rows

    for index, item in enumerate(_normalized_agent_trace(result), start=1):
        rows.append(
            {
                "Agent ID": item.get("agent_id") or item.get("id") or f"runtime_agent_{index}",
                "Agent Name": item.get("agent") or item.get("agent_name") or item.get("phase") or f"Runtime Agent {index}",
                "Version": item.get("version") or "-",
                "Owner / Team": item.get("owner") or "-",
                "Environment": item.get("environment") or "Runtime observed",
                "Adoption Status": "OBSERVED IN CURRENT RUN",
                "Downloaded / Adopted By": item.get("downloaded_by") or "-",
                "Downloaded At": item.get("downloaded_at") or "-",
                "Usage Count": "1",
                "Last Used At": item.get("timestamp") or item.get("end_time") or item.get("start_time") or "-",
                "Source Variable": "agent_trace fallback until registry telemetry is emitted",
            }
        )
    return rows


def _agent_telemetry_log_schema_rows():
    return [
        {"Field": "runtime_id", "Data Type": "string", "Mandatory": "Mandatory", "Example": "cb614954", "Why Required": "Correlates all events, agents, evidence, controls, and audit records for one run."},
        {"Field": "app_id", "Data Type": "string", "Mandatory": "Mandatory", "Example": "customer_360_app", "Why Required": "Identifies the onboarded application sending telemetry."},
        {"Field": "agent_id", "Data Type": "string", "Mandatory": "Mandatory", "Example": "app_planner_01", "Why Required": "Links execution, adoption, owner, version, and control evidence to one agent."},
        {"Field": "agent_name", "Data Type": "string", "Mandatory": "Mandatory", "Example": "App Planner", "Why Required": "Human-readable trace and operations view."},
        {"Field": "agent_version", "Data Type": "string", "Mandatory": "Mandatory", "Example": "1.3.0", "Why Required": "Tracks which adopted/downloaded agent version produced the runtime output."},
        {"Field": "owner_team", "Data Type": "string", "Mandatory": "Mandatory", "Example": "Digital AI Platform", "Why Required": "Assigns accountability for defects, policy gaps, and adoption."},
        {"Field": "environment", "Data Type": "string", "Mandatory": "Mandatory", "Example": "local / server / prod", "Why Required": "Separates local testing from server and production usage."},
        {"Field": "event_type", "Data Type": "string", "Mandatory": "Mandatory", "Example": "agent_started / agent_completed / retry / error", "Why Required": "Allows AEGIS to reconstruct the lifecycle."},
        {"Field": "status", "Data Type": "string", "Mandatory": "Mandatory", "Example": "COMPLETED", "Why Required": "Drives health, success rate, failure rate, and DORA signals."},
        {"Field": "timestamp", "Data Type": "datetime", "Mandatory": "Mandatory", "Example": "2026-07-22T13:58:02.601902", "Why Required": "Supports ordering, latency, audit, and replay."},
        {"Field": "duration_ms", "Data Type": "integer", "Mandatory": "Mandatory", "Example": "611", "Why Required": "Measures latency, bottlenecks, SLA, and cost/performance."},
        {"Field": "retry_count", "Data Type": "integer", "Mandatory": "Mandatory", "Example": "0", "Why Required": "Shows resilience behavior and rework pressure."},
        {"Field": "input_tokens", "Data Type": "integer", "Mandatory": "Conditional Mandatory", "Example": "147", "Why Required": "Needed for actual token cost attribution when an LLM is used."},
        {"Field": "output_tokens", "Data Type": "integer", "Mandatory": "Conditional Mandatory", "Example": "440", "Why Required": "Needed for actual completion cost attribution when an LLM is used."},
        {"Field": "model", "Data Type": "string", "Mandatory": "Conditional Mandatory", "Example": "gpt-4.1", "Why Required": "Identifies which model produced the result."},
        {"Field": "downloaded_by", "Data Type": "string", "Mandatory": "Optional", "Example": "user@company.com", "Why Required": "Tracks adoption/download events when agents are reused from a catalog."},
        {"Field": "downloaded_at", "Data Type": "datetime", "Mandatory": "Optional", "Example": "2026-07-24T10:00:00", "Why Required": "Supports agent adoption reporting and version governance."},
    ]


def _portfolio_trend_rows_from_ledger(ledger, current_result):
    path = _safe_get(ledger, "path")
    rows = []
    if path and Path(str(path)).exists():
        try:
            with sqlite3.connect(str(path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT runtime_id, customer_id, status, recommendation, risk_level,
                           trust_score, confidence, hitl_required, tests_passed, created_at
                    FROM audit_run
                    ORDER BY created_at DESC
                    LIMIT 25
                    """
                )
                for item in cursor.fetchall():
                    rows.append(
                        {
                            "Runtime ID": item["runtime_id"],
                            "Customer / App": item["customer_id"] or "-",
                            "Created At": item["created_at"] or "-",
                            "Status": item["status"] or "-",
                            "Recommendation": item["recommendation"] or "-",
                            "Risk Level": item["risk_level"] or "-",
                            "Trust": item["trust_score"] if item["trust_score"] is not None else "-",
                            "Confidence": item["confidence"] if item["confidence"] is not None else "-",
                            "HITL Required": "YES" if item["hitl_required"] else "NO",
                            "Tests Passed": "YES" if item["tests_passed"] else "NO",
                            "Source Variable": "artifact_export.audit_ledger.audit_run",
                        }
                    )
        except sqlite3.Error:
            rows = []
    if not rows:
        quality = _canonical_quality_scores(current_result)
        rows.append(
            {
                "Runtime ID": current_result.get("runtime_id", "-"),
                "Customer / App": current_result.get("customer_id", "-"),
                "Created At": current_result.get("created_at", current_result.get("timestamp", "-")),
                "Status": current_result.get("runtime_status", current_result.get("status", "-")),
                "Recommendation": current_result.get("recommendation", "-"),
                "Risk Level": current_result.get("risk_level", "-"),
                "Trust": quality.get("trust_score", "-"),
                "Confidence": quality.get("confidence", "-"),
                "HITL Required": "YES" if current_result.get("hitl_required") else "NO",
                "Tests Passed": "-",
                "Source Variable": "current runtime_state fallback",
            }
        )
    return rows


def render_app_onboarding_contract(result):
    st.header("Application Onboarding Contract")
    st.caption(
        "The exhaustive payload contract an AI application should emit to be governed by AEGIS. "
        "Fields are categorized as mandatory or optional and mapped to the six AEGIS pillars."
    )

    workbook_path = _aegis_output_file("AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx")
    sheets = _load_onboarding_contract(str(workbook_path))
    contract_df = sheets.get("Telemetry Contract", pd.DataFrame())

    if contract_df.empty:
        st.warning("Telemetry contract workbook is not available yet. Generate the onboarding workbook first.")
        return

    required_col = "Required" if "Required" in contract_df.columns else None
    pillar_col = "AEGIS Pillar(s)" if "AEGIS Pillar(s)" in contract_df.columns else None
    object_col = "Object / Category" if "Object / Category" in contract_df.columns else ("Object" if "Object" in contract_df.columns else None)
    category_col = "Category" if "Category" in contract_df.columns else None

    mandatory = int((contract_df[required_col].astype(str).str.lower() == "mandatory").sum()) if required_col else 0
    optional = int((contract_df[required_col].astype(str).str.lower() == "optional").sum()) if required_col else 0
    categories = int(contract_df[category_col].nunique()) if category_col else (int(contract_df[object_col].nunique()) if object_col else 0)
    pillars = 6

    render_compact_status_grid([
        ("Total Parameters", len(contract_df)),
        ("Mandatory", mandatory),
        ("Optional", optional),
        ("Object Groups", categories),
        ("AEGIS Pillars", pillars),
        ("Workbook", "Available" if workbook_path.exists() else "Unavailable"),
    ])

    c1, c2 = st.columns([1, 3])
    with c1:
        _download_output_asset(
            "Download Excel Contract",
            "AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "download_onboarding_contract_xlsx",
        )
    with c2:
        st.info(
            "Recommended onboarding path: start with mandatory run, application, request, agent, evidence, decision, "
            "governance, score, audit, and cache fields. Add optional cost, resiliency, lineage, and asset-registry fields "
            "as the application matures."
        )

    st.subheader("Canonical Signal Flow")
    st.caption(
        "External AI applications keep their own workflow. AEGIS receives runtime events while agents execute, "
        "then validates the final canonical decision before audit, release, or human review."
    )
    render_table("How Applications Connect To AEGIS", [
        {
            "Step": "1",
            "Flow Node": "External AI Application",
            "What Happens": "Dify, Claude, OpenAI, Azure AI Foundry, Bedrock, LangChain, or a custom app runs its own agents.",
            "Payload To AEGIS": "Application identity and run identity",
        },
        {
            "Step": "2",
            "Flow Node": "Runtime Canonical Events",
            "What Happens": "Every app agent emits start, complete, skip, retry, tool, evidence, latency, cost, and error signals.",
            "Payload To AEGIS": "Streaming event payload or SDK/API callback",
        },
        {
            "Step": "3",
            "Flow Node": "AEGIS Runtime Monitor",
            "What Happens": "AEGIS reconstructs traversal, detects slow/failed/skipped branches, and records live observability.",
            "Payload To AEGIS": "Normalized runtime event store",
        },
        {
            "Step": "4",
            "Flow Node": "Final Canonical Decision",
            "What Happens": "The app sends recommendation, risk, confidence, evidence pack, and proposed response.",
            "Payload To AEGIS": "Completed decision record",
        },
        {
            "Step": "5",
            "Flow Node": "Governance, Audit & Release Gate",
            "What Happens": "AEGIS checks grounding, OWASP/PII, policy, HITL, auditability, cost, cache, and release readiness.",
            "Payload To AEGIS": "Governed decision record and audit artifacts",
        },
    ])

    completeness_rows = [
        {"Contract Area": "Runtime Identity", "Completeness": 100, "Why It Matters": "Identifies app, run, environment, customer, and ownership."},
        {"Contract Area": "Runtime Events", "Completeness": 100, "Why It Matters": "Powers traversal, status, latency, skipped-path, and resilience views."},
        {"Contract Area": "Decision Record", "Completeness": 100, "Why It Matters": "Creates the canonical source for recommendation, risk, trust, confidence, and HITL."},
        {"Contract Area": "Evidence Objects", "Completeness": 100, "Why It Matters": "Supports grounding, lineage, retrieval/rerank transparency, and audit review."},
        {"Contract Area": "Cost & Cache", "Completeness": 85, "Why It Matters": "Shows USD cost, token usage, cache reuse, TTL, and repeat-run savings."},
        {"Contract Area": "Asset & Audit Metadata", "Completeness": 80, "Why It Matters": "Connects app, agents, prompts, models, tools, and generated artifacts to audit records."},
    ]
    fig = go.Figure(go.Bar(
        x=[row["Completeness"] for row in completeness_rows],
        y=[row["Contract Area"] for row in completeness_rows],
        orientation="h",
        marker_color=["#11845b", "#11845b", "#11845b", "#11845b", "#f79009", "#f79009"],
        text=[f"{row['Completeness']}%" for row in completeness_rows],
        textposition="inside",
        insidetextanchor="middle",
    ))
    fig.update_layout(
        title="Onboarding Contract Completeness",
        height=330,
        margin=dict(l=20, r=20, t=55, b=25),
        xaxis=dict(range=[0, 100], title="Coverage (%)"),
        yaxis=dict(autorange="reversed"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)
    st.info(
        "Legend: Green means the mandatory contract area is fully covered. "
        "Amber means the capability is supported, but some fields are optional or maturity-dependent for the onboarded application."
    )
    render_table("Contract Completeness Interpretation", completeness_rows)

    tabs = st.tabs([
        "Executive View",
        "Runtime Canonical Objects",
        "Agent Canonical Parameters",
        "Agent Adoption & Telemetry",
        "Telemetry Contract",
        "Mandatory Fields",
        "Pillar Mapping",
        "Object Groups",
        "Enums & Guidance",
    ])

    with tabs[0]:
        st.subheader("Two Payloads An Application Emits To AEGIS")
        render_table("Canonical Payload Model", [
            {
                "Payload": "Runtime Canonical Events",
                "When Sent": "During execution, while app agents/tools are still running",
                "Examples": "Agent started/completed, tool called, evidence retrieved, risk updated, control evaluated, error/fallback triggered",
                "AEGIS Use": "Live traversal, partial evidence, runtime alerts, latency monitoring, pre-output governance gate",
                "Integration": "Event stream, SDK callback, or API event endpoint",
            },
            {
                "Payload": "Completed Canonical Decision Record",
                "When Sent": "At the end of the run, before or after final response release depending on governance mode",
                "Examples": "Recommendation, risk, trust, confidence, evidence pack, governance status, HITL flag, audit IDs, artifact hashes",
                "AEGIS Use": "Single source of truth for executive UI, reports, audit package, lineage, and canonical consistency checks",
                "Integration": "API submit, SDK finalization call, or batch ingestion",
            },
        ])

        render_table("Minimum Payload Needed to Onboard an Application", [
            {
                "Payload Area": "Application & Run Identity",
                "Why AEGIS Needs It": "Uniquely identifies the source application, domain, run, environment, and ownership.",
                "Pillar": "Scalable AI, Auditable AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Runtime Canonical Events",
                "Why AEGIS Needs It": "Lets AEGIS observe agent/tool progress, evidence retrieval, control checks, errors, and latency while the app is still executing.",
                "Pillar": "Measurable AI, Resilient AI, Auditable AI",
                "Priority": "Mandatory for real-time mode",
            },
            {
                "Payload Area": "Completed Canonical Decision Record",
                "Why AEGIS Needs It": "Provides the final reconciled source of truth used by dashboards, reports, alerts, lineage, and audit evidence.",
                "Pillar": "Trustworthy AI, Governable AI, Auditable AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Request & User Query",
                "Why AEGIS Needs It": "Connects the original application request to rewritten prompts, retrieval intent, and final output.",
                "Pillar": "Trustworthy AI, Governable AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Agent Execution Trace",
                "Why AEGIS Needs It": "Shows which agents ran, skipped, looped, failed, or handed off work, with execution time and status.",
                "Pillar": "Measurable AI, Resilient AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Evidence & Retrieval",
                "Why AEGIS Needs It": "Proves what data supported the decision, including source, rank, retrieval method, rerank score, and lineage.",
                "Pillar": "Trustworthy AI, Auditable AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Decision, Risk & Governance",
                "Why AEGIS Needs It": "Captures recommendation, risk level, approval state, HITL requirement, policy status, and rationale.",
                "Pillar": "Governable AI",
                "Priority": "Mandatory",
            },
            {
                "Payload Area": "Cost, Cache, Resilience & Audit",
                "Why AEGIS Needs It": "Measures reuse, latency, model cost, fallback behavior, audit record location, and report artifact hashes.",
                "Pillar": "Measurable AI, Scalable AI, Resilient AI, Auditable AI",
                "Priority": "Optional to Mandatory by maturity",
            },
        ])

    with tabs[1]:
        st.subheader("Runtime Canonical Events and Onboarding Objects")
        st.caption(
            "These are the stable objects that an onboarded application must emit. Runtime events can stream while "
            "the app is still running; the final decision record is emitted before publication or post-run audit."
        )
        render_table("Runtime Canonical Object Contract", [
            {
                "Canonical Object": "Runtime Canonical Event",
                "Emitter": "Every application agent and every AEGIS control agent",
                "When Emitted": "During execution: start, complete, skip, retry, tool call, evidence retrieval, failure, fallback",
                "Mandatory Fields": "runtime_id, app_id, agent_id, event_type, status, timestamp, execution_time_ms, retry_count, receives_from, passes_to",
                "Used By AEGIS": "Live traversal, observability, latency, skipped paths, retries, resilience, cost, audit trail",
            },
            {
                "Canonical Object": "Agent Execution Record",
                "Emitter": "Each agent or tool wrapper",
                "When Emitted": "At agent completion or failure",
                "Mandatory Fields": "agent_id, agent_name, agent_type, phase, status, execution_order, duration_ms, previous_agents, next_agents",
                "Used By AEGIS": "Agent trace, app-vs-AEGIS separation, handoff map, bottleneck table, runtime health",
            },
            {
                "Canonical Object": "Evidence Object",
                "Emitter": "Retrieval/evidence layer or AI application",
                "When Emitted": "When evidence is retrieved, reranked, selected, or attached to final answer",
                "Mandatory Fields": "evidence_id, source, content_hash, retrieval_method, rank, score, rerank_score, evidence_trust, trust_basis",
                "Used By AEGIS": "Evidence lineage, grounding, trust calculation, audit package, reranking transparency",
            },
            {
                "Canonical Object": "Control Outcome",
                "Emitter": "OWASP, grounding, governance, compliance, LLM judge, or policy agent",
                "When Emitted": "When a control is evaluated",
                "Mandatory Fields": "control_id, control_name, pillar, status, severity, score, finding, remediation, hitl_trigger",
                "Used By AEGIS": "Governance center, OWASP AI, HITL gate, alerts, auditability, six-pillar view",
            },
            {
                "Canonical Object": "Final Canonical Decision Record",
                "Emitter": "AI application response generator or final app orchestrator",
                "When Emitted": "Before final publication or at end of post-run assurance mode",
                "Mandatory Fields": "recommendation, risk_level, trust_score, confidence, evidence_count, compliance_status, proposed_answer, rationale",
                "Used By AEGIS": "Canonical consistency, executive summary, release gate, report generation, audit package",
            },
            {
                "Canonical Object": "Governed Decision Record",
                "Emitter": "AEGIS control plane",
                "When Emitted": "After AEGIS validation and release/HITL decision",
                "Mandatory Fields": "governed_recommendation, governed_risk, governance_status, hitl_required, release_allowed, audit_id, artifact_hashes",
                "Used By AEGIS": "Return to app, management dashboard, audit ledger, regulator/risk review",
            },
        ])
        st.info(
            "Runtime canonical events are the live signal feed. Onboarding objects are the formal contract. "
            "Together they allow AEGIS to monitor during execution and also audit the completed decision."
        )
        contract_status = _safe_dict(result.get("canonical_runtime_event_contract"))
        runtime_ingestion = _safe_dict(result.get("runtime_ingestion"))
        required_fields = contract_status.get("required_fields") or runtime_ingestion.get("required_fields") or []
        if isinstance(required_fields, list):
            required_fields_display = ", ".join(str(field) for field in required_fields)
        else:
            required_fields_display = str(required_fields or "-")
        render_table("Runtime Ingestion Contract Status", [{
            "Status": contract_status.get("status") or runtime_ingestion.get("status") or "-",
            "Schema Version": contract_status.get("schema_version") or runtime_ingestion.get("schema_version") or "-",
            "Events Captured": contract_status.get("event_count") or runtime_ingestion.get("event_count") or 0,
            "Invalid Events": contract_status.get("invalid_count") or runtime_ingestion.get("invalid_count") or 0,
            "Required Fields": required_fields_display,
        }])
        event_rows = []
        for event in runtime_ingestion.get("events", [])[:30]:
            if not isinstance(event, dict):
                continue
            event_rows.append({
                "Order": event.get("execution_order"),
                "Agent": event.get("agent_name"),
                "Agent Type": event.get("agent_type"),
                "Event": event.get("event_type"),
                "Status": event.get("status"),
                "Execution Time": event.get("execution_time_ms"),
                "Retries": f"{event.get('retry_count', 0)} / {event.get('max_retries', 3)}",
                "Contract": event.get("contract_status"),
            })
        render_table("Canonical Runtime Events Captured", event_rows)

    with tabs[2]:
        st.subheader("Accepted Canonical Parameters for Onboarded Agents")
        st.caption(
            "Every external application or agent platform should emit these fields so AEGIS can observe, govern, "
            "measure, scale, recover, and audit execution consistently. Retry count is mandatory because it proves resilience behavior."
        )
        render_table("Agent Canonical Parameter Contract", _canonical_parameter_catalog_rows())
        st.info(
            "Minimum retry contract: emit retry_count, max_retries, and retry_reason when a retry occurs. "
            "If no retry occurs, retry_count should be 0 and max_retries should still show the configured policy."
        )

    with tabs[3]:
        st.subheader("Agent Adoption & Telemetry Contract")
        st.caption(
            "Tracks whether an agent has been adopted/downloaded, where it is running, which version is in use, "
            "and what local/server log fields AEGIS needs to read the agent reliably."
        )
        adoption_rows = _agent_adoption_registry_rows(result)
        schema_rows = _agent_telemetry_log_schema_rows()
        adopted_count = sum(1 for row in adoption_rows if str(row.get("Adoption Status", "")).upper() not in {"-", "UNKNOWN"})
        render_compact_status_grid([
            ("Agents Tracked", len(adoption_rows)),
            ("Adoption Records", adopted_count),
            ("Schema Fields", len(schema_rows)),
            ("Mandatory Log Fields", sum(1 for row in schema_rows if row.get("Mandatory") == "Mandatory")),
            ("Runtime Source", "Registry" if result.get("agent_adoption_registry") or result.get("agent_registry") or result.get("adopted_agents") else "Agent Trace Fallback"),
            ("Downloadable", "YES"),
        ])
        adoption_df = _arrow_safe_dataframe(adoption_rows)
        schema_df = _arrow_safe_dataframe(schema_rows)
        st.download_button(
            "Download agent adoption and telemetry schema (Excel)",
            data=_dataframe_to_xlsx_bytes(
                pd.concat(
                    [
                        adoption_df.assign(Sheet="Agent Adoption Registry"),
                        schema_df.assign(Sheet="Local/Server Log Schema"),
                    ],
                    ignore_index=True,
                    sort=False,
                ),
                sheet_name="Agent Adoption Telemetry",
            ),
            file_name="AEGIS_Agent_Adoption_Telemetry_Contract.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="download_agent_adoption_telemetry_contract",
        )
        render_table("Agent Adoption Registry", adoption_rows)
        render_table("Local / Server Agent Log Fields AEGIS Can Read", schema_rows)
        st.info(
            "For production, emit agent_adoption_registry or agent_registry from the catalog/download service. "
            "Until that exists, AEGIS derives a current-run adoption view from agent_trace so leaders still see which agents actually ran."
        )

    with tabs[4]:
        display_df = contract_df.copy()
        if required_col:
            selected_required = st.multiselect(
                "Filter by mandatory / optional",
                sorted(display_df[required_col].dropna().astype(str).unique()),
                default=sorted(display_df[required_col].dropna().astype(str).unique()),
                key="onboarding_contract_required_filter",
            )
            if selected_required:
                display_df = display_df[display_df[required_col].astype(str).isin(selected_required)]
        if pillar_col:
            all_pillars = sorted({
                part.strip()
                for raw in display_df[pillar_col].dropna().astype(str)
                for part in raw.split(",")
                if part.strip()
            })
            selected_pillars = st.multiselect(
                "Filter by AEGIS pillar",
                all_pillars,
                default=[],
                key="onboarding_contract_pillar_filter",
            )
            if selected_pillars:
                display_df = display_df[
                    display_df[pillar_col].astype(str).apply(
                        lambda value: any(pillar in value for pillar in selected_pillars)
                    )
                ]
        st.dataframe(_arrow_safe_dataframe(display_df), use_container_width=True, hide_index=True, height=560)

    with tabs[5]:
        mandatory_df = contract_df[
            contract_df[required_col].astype(str).str.lower() == "mandatory"
        ] if required_col else contract_df
        st.dataframe(_arrow_safe_dataframe(mandatory_df), use_container_width=True, hide_index=True, height=560)

    with tabs[6]:
        if "Pillar Mapping" in sheets and not sheets["Pillar Mapping"].empty:
            render_table("Parameter Coverage by AEGIS Pillar", sheets["Pillar Mapping"])
        elif pillar_col:
            pillar_rows = []
            for pillar in [
                "Trustworthy AI",
                "Governable AI",
                "Measurable AI",
                "Scalable AI",
                "Resilient AI",
                "Auditable AI",
            ]:
                pillar_df = contract_df[contract_df[pillar_col].astype(str).str.contains(pillar, regex=False, na=False)]
                pillar_rows.append({
                    "AEGIS Pillar": pillar,
                    "Total Parameters": len(pillar_df),
                    "Mandatory": int((pillar_df[required_col].astype(str).str.lower() == "mandatory").sum()) if required_col else "-",
                    "Optional": int((pillar_df[required_col].astype(str).str.lower() == "optional").sum()) if required_col else "-",
                    "What It Proves": {
                        "Trustworthy AI": "Grounded, safe, low-hallucination outputs.",
                        "Governable AI": "Policy-controlled decisions with approvals and review logic.",
                        "Measurable AI": "Execution time, cost, quality, and operational telemetry.",
                        "Scalable AI": "Reusable cache, asset inventory, and repeatable integration contract.",
                        "Resilient AI": "Fallbacks, retries, partial results, and degraded-mode behavior.",
                        "Auditable AI": "Traceable evidence, decisions, artifacts, and immutable run records.",
                    }.get(pillar, "-"),
                })
            render_table("Parameter Coverage by AEGIS Pillar", pillar_rows)
        else:
            st.info("Pillar mapping column was not found in the workbook.")

    with tabs[7]:
        if "Object Groups" in sheets and not sheets["Object Groups"].empty:
            render_table("Onboarding Object Groups", sheets["Object Groups"])
        else:
            grouping_col = category_col or object_col
            if grouping_col:
                grouped = (
                    contract_df.groupby([grouping_col, required_col])
                    .size()
                    .reset_index(name="Parameter Count")
                    if required_col else
                    contract_df.groupby(grouping_col).size().reset_index(name="Parameter Count")
                )
                st.dataframe(_arrow_safe_dataframe(grouped), use_container_width=True, hide_index=True, height=520)
            else:
                st.info("Object/category column was not found in the workbook.")

    with tabs[8]:
        if "Enums & Guidance" in sheets and not sheets["Enums & Guidance"].empty:
            render_table("Enums & Guidance", sheets["Enums & Guidance"])
        else:
            grouped = (
                contract_df[["Field Name", "Data Type", "Validation / Notes"]]
                if {"Field Name", "Data Type", "Validation / Notes"}.issubset(set(contract_df.columns))
                else pd.DataFrame()
            )
            if not grouped.empty:
                render_table("Validation Guidance", grouped)
            else:
                st.info("No enum or implementation guidance sheet was found in the workbook.")


def _runtime_observed_signal_keys(result):
    keys = set()
    for row in _normalized_agent_trace(result):
        if isinstance(row, dict):
            keys.update(str(key).casefold() for key, value in row.items() if not _is_unknown_value(value))
    for container in [
        result,
        result.get("canonical_runtime_event_contract"),
        result.get("canonical_values"),
        result.get("canonical_display"),
        result.get("canonical_control_tower_measurements"),
        result.get("release_assessment"),
        result.get("policy_as_code"),
        result.get("security_analysis"),
        result.get("cache_lookup"),
    ]:
        if isinstance(container, dict):
            keys.update(str(key).casefold() for key, value in container.items() if not _is_unknown_value(value))
    return keys


def _canonical_missing_signal_rows(result):
    live_keys = _runtime_observed_signal_keys(result)
    rows = []
    for row in _canonical_parameter_catalog_rows():
        required = str(row.get("Mandatory / Non Mandatory", ""))
        if not required.casefold().startswith("mandatory"):
            continue
        parameter = row.get("Canonical Object / Parameter")
        observed = str(parameter or "").casefold() in live_keys
        rows.append(
            {
                "#": row.get("#"),
                "Canonical Parameter": parameter,
                "Required": required,
                "Data Type": row.get("Data Type"),
                "Status": "PASS" if observed else "MISSING",
                "Emit / Derive Guidance": (
                    "Observed in this runtime."
                    if observed
                    else "External app should emit this source signal, or AEGIS must derive it from other emitted signals."
                ),
                "Why Required": row.get("Why AEGIS Requires It"),
            }
        )
    return rows


def render_missing_runtime_signals(result):
    st.header("Missing Signals")
    st.caption(
        "This section shows which mandatory canonical parameters were observed in the current external app runtime log "
        "and which ones still need onboarding attention."
    )
    rows = _canonical_missing_signal_rows(result)
    missing = [row for row in rows if row.get("Status") == "MISSING"]
    passed = len(rows) - len(missing)
    render_compact_status_grid([
        ("Mandatory Signals", len(rows)),
        ("Observed", passed),
        ("Missing", len(missing)),
        ("Coverage", f"{passed}/{len(rows)} passed" if rows else "-"),
    ])
    if missing:
        st.warning(f"{len(missing)} mandatory signal(s) are missing from this runtime.")
        render_table("Missing Required Canonical Signals", missing)
    else:
        st.success("All mandatory canonical signals are present for this runtime.")
    render_table("Canonical Signal Checklist", rows)
    render_table("Minimum JSONL Event Envelope", [
        {"Field": "runtime_id", "Type": "string", "Example": "RUN-001"},
        {"Field": "app_id", "Type": "string", "Example": "EXT_APP"},
        {"Field": "agent_id", "Type": "string", "Example": "decision_agent"},
        {"Field": "agent_name", "Type": "string", "Example": "Decision Agent"},
        {"Field": "event_type", "Type": "string", "Example": "FINAL_CANONICAL_OBJECTS"},
        {"Field": "status", "Type": "string", "Example": "COMPLETED"},
        {"Field": "timestamp", "Type": "datetime/string", "Example": "2026-08-02T10:30:00Z"},
    ])


def render_technical_project_summary(result):
    """Audience-facing technical synopsis derived only from runtime telemetry."""
    st.header("Technical Architecture")
    st.caption(
        "Live architecture and implementation details for this AEGIS execution."
    )

    trace = _normalized_agent_trace(result)
    agent_counts = _canonical_agent_counts(result)
    graph = result.get("agent_execution_graph", {})
    graph_summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    telemetry = result.get("runtime_telemetry", {})
    telemetry = telemetry if isinstance(telemetry, dict) else {}
    health = result.get("runtime_health_v2") or result.get("runtime_health") or {}
    health = health if isinstance(health, dict) else {}
    cache = result.get("cache_metrics", {})
    cache = cache if isinstance(cache, dict) else {}

    llm_inventory = []
    seen_llms = set()
    registry = result.get("llm_registry", {})
    sources = list(registry.items()) if isinstance(registry, dict) else []
    llm_trace = result.get("llm_trace", [])
    if isinstance(llm_trace, list):
        sources.extend((row.get("agent_name") or row.get("agent") or "Runtime", row)
                       for row in llm_trace if isinstance(row, dict))
    for role, raw in sources:
        for detail in (raw if isinstance(raw, list) else [raw]):
            if not isinstance(detail, dict):
                continue
            nested = detail.get("telemetry", {}) if isinstance(detail.get("telemetry"), dict) else {}
            provider = detail.get("provider") or nested.get("provider")
            model = detail.get("model") or detail.get("model_name") or nested.get("model")
            if not provider and not model:
                continue
            identity = (str(role), str(provider), str(model))
            if identity in seen_llms:
                continue
            seen_llms.add(identity)
            llm_inventory.append({
                "Runtime Role / Agent": str(role).replace("_", " ").title(),
                "Provider": provider,
                "Model": model,
                "Invocation": detail.get("status") or ("SUCCESS" if detail.get("success") else "RECORDED"),
            })

    retrieval_config = result.get("retrieval", {})
    retrieval_config = retrieval_config if isinstance(retrieval_config, dict) else {}
    embedding_stats = result.get("embedding_statistics", {})
    embedding_stats = embedding_stats if isinstance(embedding_stats, dict) else {}
    embedding_model = (
        retrieval_config.get("embedding_model") or result.get("embedding_model") or
        embedding_stats.get("model") or "BAAI/bge-small-en-v1.5"
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Runtime", _reported(result.get("runtime_id")))
    c2.metric("Executed Agents", f"{agent_counts['executed']}/{agent_counts['total']}")
    c3.metric("Observed Handoffs", agent_counts.get("observed_handoffs", agent_counts.get("transitions", 0)))
    c4.metric("Execution Status", _reported(result.get("runtime_status", result.get("status"))))

    st.subheader("Implementation Boundary")
    render_table("Technical Architecture Summary", [
        {
            "Layer": "External AI Applications",
            "Implementation Detail": "Current demo runs the sample Streamlit customer-investigation workflow locally.",
            "AEGIS Boundary": "Future external apps should emit the same canonical runtime payload through API, SDK, or event stream.",
        },
        {
            "Layer": "Runtime Contract",
            "Implementation Detail": "Runtime state normalizes query, customer, agents, evidence, decisions, scores, cache, and audit metadata.",
            "AEGIS Boundary": "This is the stable onboarding object that AI applications must publish.",
        },
        {
            "Layer": "Control Plane Services",
            "Implementation Detail": "Governance, compliance, OWASP, evidence lineage, cache intelligence, observability, audit, and asset registry services.",
            "AEGIS Boundary": "AEGIS evaluates and records controls; it does not own the AI application's core workflow.",
        },
        {
            "Layer": "Evidence & Retrieval",
            "Implementation Detail": "Hybrid retrieval combines customer-scoped CSV evidence, BM25/semantic retrieval signals, reranking, and evidence packaging.",
            "AEGIS Boundary": "Retrieval is sample-app capability today; external applications can provide their own evidence objects under the onboarding contract.",
        },
        {
            "Layer": "Audit & Reporting",
            "Implementation Detail": "Run artifacts, evidence package, audit ledger rows, downloadable reports, and canonical consistency checks.",
            "AEGIS Boundary": "AEGIS makes every decision traceable and presentation-ready for risk, technology, audit, and executives.",
        },
    ])

    st.subheader("End-to-End AEGIS Technical Workflow")
    st.caption(
        "This section explains the complete project stack and the runtime controls used to produce, validate, "
        "and audit the final banking investigation decision."
    )
    render_table("How AEGIS Works", [
        {
            "Stage": "1. Investigation Launch & Input Contract",
            "What AEGIS Does": "Accepts customer ID, investigation objective, and selected agent/tool scope from the Streamlit Control Tower.",
            "Why It Matters": "Creates a repeatable runtime contract so every agent works from the same customer, query, and audit context.",
        },
        {
            "Stage": "2. Prompt Safety & OWASP LLM Checks",
            "What AEGIS Does": "Runs prompt-injection, jailbreak, PII exposure, data leakage, unsafe tool-use, and policy-control checks mapped to OWASP LLM risk categories.",
            "Why It Matters": "Prevents unsafe or contaminated instructions from entering retrieval, agent reasoning, or report generation.",
        },
        {
            "Stage": "3. Cache Intelligence",
            "What AEGIS Does": "Checks runtime, retrieval, embedding, prompt, and key-value caches with TTL, hit/miss, and freshness metadata.",
            "Why It Matters": "Improves execution time while avoiding stale customer evidence; source CSV fingerprints force refresh when file contents change.",
        },
        {
            "Stage": "4. Query Rewrite & Planning",
            "What AEGIS Does": "Rewrites the user objective into a banking-specific investigation plan and selects required agents/tools.",
            "Why It Matters": "Converts a plain question into a structured customer-360 workflow covering profile, accounts, transactions, risk, compliance, and evidence.",
        },
        {
            "Stage": "5. Hybrid Retrieval",
            "What AEGIS Does": "Retrieves evidence using hybrid lexical BM25 plus vector/embedding search, scoped by customer/entity identifiers.",
            "Why It Matters": "Combines exact banking identifiers with semantic matching so the report uses the correct customer chunks and supporting documents.",
        },
        {
            "Stage": "6. Reranking, Fusion & Reprioritization",
            "What AEGIS Does": "Applies reciprocal-rank/fusion-style ranking, evidence scores, source priority, and customer relevance checks.",
            "Why It Matters": "Moves the most customer-specific and decision-relevant evidence to the top instead of trusting raw retrieval order.",
        },
        {
            "Stage": "7. Evidence Assembly & Grounding",
            "What AEGIS Does": "Builds an evidence pack from customer, account, transaction, alert, case, loan/card, risk, and retrieved chunks.",
            "Why It Matters": "Ensures recommendation and executive summary cite actual banking facts instead of abstract trust/confidence numbers.",
        },
        {
            "Stage": "8. Agent Orchestration",
            "What AEGIS Does": "Runs planner, router, customer, retrieval, evidence, recommendation, governance, compliance, trust, hallucination, reflection, and evaluation agents.",
            "Why It Matters": "Separates responsibilities so decisioning, controls, validation, and audit telemetry are independently visible.",
        },
        {
            "Stage": "9. Recommendation & Decision Policy",
            "What AEGIS Does": "Calculates canonical recommendation, risk level, human-review flag, next-best-action, and management summary from authoritative customer evidence.",
            "Why It Matters": "Prevents contradictory APPPROVE/MONITOR/ESCALATE outputs across dashboards, LLM traces, and reports.",
        },
        {
            "Stage": "10. Governance & Compliance Validation",
            "What AEGIS Does": "Runs governance and compliance controls with explicit policy/control reasoning and deterministic fallback when no LLM provider is configured.",
            "Why It Matters": "Avoids placeholder PASS/COMPLETED states; every governance/compliance result must include model/provider or deterministic policy evidence.",
        },
        {
            "Stage": "11. Output Validation & Hallucination Guard",
            "What AEGIS Does": "Checks groundedness, coverage, hallucination risk, consistency of trust/confidence/recommendation, and reflection quality.",
            "Why It Matters": "Blocks unsupported claims such as governance escalation, compliance breach, or trust failure unless evidence supports them.",
        },
        {
            "Stage": "12. Runtime Observability & Audit Package",
            "What AEGIS Does": "Publishes agent traces, execution graph, token/cost telemetry, cache metrics, invariants, PDF/HTML/JSON/CSV outputs, and ZIP audit package.",
            "Why It Matters": "Makes the system explainable to executives, engineers, auditors, and regulators from the same runtime record.",
        },
    ])

    architecture, ai_stack = st.columns(2)
    with architecture:
        st.subheader("Architecture & Orchestration")
        render_table("Runtime Architecture", [
            {"Component": "Application", "Implementation": "Streamlit Enterprise Control Tower"},
            {"Component": "Orchestrator", "Implementation": "AEGIS Runtime Orchestrator V5"},
            {"Component": "Execution Pattern", "Implementation": "Planner -> Router -> Retrieval -> Evidence -> Answer -> Controls -> Evaluation"},
            {"Component": "Agent Graph", "Implementation": "Runtime-derived planned and observed transitions"},
            {"Component": "State Contract", "Implementation": "Canonical runtime_state with telemetry and audit trace"},
        ])
    with ai_stack:
        st.subheader("AI & Retrieval Stack")
        retrieval = result.get("retrieval", {})
        retrieval = retrieval if isinstance(retrieval, dict) else {}
        llm = result.get("llm_trace", {}) or result.get("llm_observability", {})
        render_table("Runtime AI Configuration", _technical_rows([
            {"Capability": "LLM / Model", "Runtime Detail": _reported(telemetry.get("model") or (llm.get("model") if isinstance(llm, dict) else None))},
            {"Capability": "Retrieval", "Runtime Detail": _reported(retrieval.get("strategy") or result.get("retrieval_strategy"), "Enterprise hybrid retrieval")},
            {"Capability": "Documents Retrieved", "Runtime Detail": len(result.get("retrieved_chunks", []) or [])},
            {"Capability": "Evidence Objects", "Runtime Detail": len(result.get("evidence_pack", []) or [])},
            {"Capability": "Vector Inventory", "Runtime Detail": len(result.get("vector_inventory", []) or [])},
            {"Capability": "Embedding Model", "Runtime Detail": embedding_model},
            {"Capability": "Observed LLM Providers", "Runtime Detail": ", ".join(sorted({str(x["Provider"]) for x in llm_inventory if x.get("Provider")}))},
            {"Capability": "Observed LLM Models", "Runtime Detail": ", ".join(sorted({str(x["Model"]) for x in llm_inventory if x.get("Model")}))},
        ]))

    st.subheader("Technology Stack")
    render_table("AEGIS Implementation Stack", [
        {"Layer": "Application", "Technology": "Python - Streamlit Enterprise Control Tower - session-state runtime contract"},
        {"Layer": "Data & Analytics", "Technology": "Pandas - NumPy - governed external application datasets - source coverage notices"},
        {"Layer": "LLM Runtime", "Technology": "Local Qwen runtime - per-agent model/provider telemetry - deterministic policy fallback"},
        {"Layer": "Embeddings", "Technology": f"Sentence-transformer - {embedding_model}"},
        {"Layer": "Hybrid Retrieval", "Technology": "BM25 lexical retrieval - vector similarity retrieval - entity/customer scoping - CSV fingerprint refresh"},
        {"Layer": "Ranking & Prioritization", "Technology": "Reciprocal-rank/fusion scoring - reranking - source priority - evidence weighting - reprioritized customer chunks"},
        {"Layer": "Evidence Engine", "Technology": "Customer/account/transaction/alert/case/loan/card evidence pack - citation coverage - average trust"},
        {"Layer": "Agent Orchestration", "Technology": "AEGIS Runtime Orchestrator V5 - planner/router - agent graph - canonical runtime_state"},
        {"Layer": "Decision Engine", "Technology": "Canonical recommendation - trust score - confidence - risk authority - human-review authority - next-best-action"},
        {"Layer": "Governance & Compliance", "Technology": "Governance Agent - Compliance Agent - explicit banking control ledger - deterministic policy engines"},
        {"Layer": "Security", "Technology": "OWASP LLM Top 10 mapped controls - prompt injection - jailbreak - PII exposure - data leakage - tool security"},
        {"Layer": "Validation", "Technology": "Hallucination guard - reflection scoring - groundedness - coverage - invariant tests - contradiction checks"},
        {"Layer": "Caching", "Technology": "Runtime - retrieval - embedding - prompt - KV caches with TTL, freshness, hit/miss and cache-hit ratio"},
        {"Layer": "Observability", "Technology": "Agent/LLM traces - execution time - tokens - health - trust - confidence - audit timeline - execution graph"},
        {"Layer": "Executive Reporting", "Technology": "Streamlit dashboard - PDF - self-contained HTML - PNG - CSV/JSON evidence - ZIP audit package"},
    ])

    if llm_inventory:
        st.subheader("LLM Provider, Model & Agent Inventory")
        st.caption("Only models recorded in this execution are labelled as used.")
        render_table("Observed LLM Runtime", llm_inventory)

    st.subheader("Executed Agent & Tool Topology")
    topology = []
    for row in trace:
        if not isinstance(row, dict):
            continue
        topology.append({
            "Order": row.get("execution_order"),
            "Agent": row.get("agent"),
            "Phase": row.get("phase"),
            "Tool": row.get("tool_used") or row.get("tool"),
            "Status": row.get("status"),
            "Execution Count": row.get("execution_count", 1),
            "Execution Time (ms)": row.get("duration_ms", 0),
        })
    render_table("Runtime Agent Inventory", topology)

    controls, operations = st.columns(2)
    with controls:
        st.subheader("Trust, Risk & Security Controls")
        security = result.get("security", {})
        governance = result.get("governance", {})
        compliance = result.get("compliance", {})
        recommendation, risk_level = _runtime_recommendation_and_risk(result)
        compliance_status = _canonical_compliance_status(result)
        release_assessment = _governance_release_assessment(result)
        review_required = bool(release_assessment["review_required"])
        governance_status = release_assessment["governance_status"]
        render_table("Control Plane", _technical_rows([
            {"Control": "Trust", "Result": f"{_canonical_quality_scores(result)['trust_score']:.1f}", "Status": "CANONICAL"},
            {"Control": "Governance", "Result": _reported(recommendation), "Status": governance_status},
            {"Control": "Compliance", "Result": _reported(compliance_status), "Status": compliance_status},
            {"Control": "Security", "Result": _reported(security.get("risk_level") if isinstance(security, dict) else None), "Status": _reported(security.get("status") if isinstance(security, dict) else None)},
            {"Control": "OWASP LLM Checks", "Result": "Prompt injection, jailbreak, PII, data leakage, tool security", "Status": _reported(security.get("status") if isinstance(security, dict) else None, "ENFORCED")},
            {"Control": "Hybrid Retrieval Validation", "Result": _reported(retrieval_config.get("retrieval_method") or retrieval_config.get("strategy"), "BM25 + Vector + Reranking"), "Status": "ACTIVE"},
            {"Control": "Output Validation", "Result": "Groundedness, coverage, hallucination, consistency, invariant checks", "Status": "ACTIVE"},
            {"Control": "Release Route", "Result": release_assessment["release_route"], "Status": governance_status},
        ]))
    with operations:
        st.subheader("Operations & Observability")
        render_table("Runtime Operations", _technical_rows([
            {"Metric": "Health Score", "Value": _reported(health.get("health_score"))},
            {"Metric": "Agent Success Rate", "Value": _reported(health.get("agent_success_rate"))},
            {"Metric": "Execution Time (sec)", "Value": _reported(result.get("execution_time_seconds"))},
            {"Metric": "Execution Checkpoints", "Value": f"{len(result.get('execution_timeline', []) or [])} logged runtime milestones"},
            {"Metric": "Cache Hit Ratio", "Value": _reported(cache.get("cache_hit_ratio"))},
            {"Metric": "Memory Objects", "Value": _reported(result.get("memory_metrics", {}).get("total_memory_objects") if isinstance(result.get("memory_metrics"), dict) else None)},
        ]))

    with st.expander("Runtime contract coverage"):
        domains = (
            "planner", "router", "retrieval", "evidence", "answer", "trust",
            "reflection", "governance", "compliance", "evaluation_results",
            "security", "telemetry", "memory", "audit"
        )
        render_table("Published Technical Domains", [
            {"Domain": domain.replace("_", " ").title(), "Published": bool(result.get(domain))}
            for domain in domains
        ])

    data_quality = result.get("data_quality", [])
    if isinstance(data_quality, list) and data_quality:
        st.subheader("Source Data Quality Notices")
        st.caption("These are confirmed source-file gaps, not system-generated estimates.")
        render_table("CSV Coverage", data_quality)


def render_investigation_artifacts(result):
    export = result.get("artifact_export", {})
    st.header("Audit & Evidence Package")
    render_audit_readiness_meter(result)

    # A completed result can predate the automatic export hook (for example,
    # when Streamlit hot-reloads after an execution). Recover the package from
    # the in-memory runtime instead of requiring the investigation to run again.
    runtime_status = str(
        result.get("runtime_status") or result.get("status") or ""
    ).upper()
    current_phase = str(result.get("current_phase") or result.get("phase") or "").upper()
    is_terminal = (
        runtime_status in {"COMPLETED", "COMPLETE", "SUCCESS", "SUCCEEDED"}
        or current_phase in {"RUNTIME_COMPLETE", "COMPLETED", "COMPLETE"}
    )
    export_saved = isinstance(export, dict) and export.get("status") == "SAVED"

    if not export_saved and is_terminal:
        try:
            from services1.investigation_artifact_service import save_investigation_artifacts
            export = save_investigation_artifacts(result)
            result["artifact_export"] = export
            st.session_state["runtime_state"] = result
            export_saved = export.get("status") == "SAVED"
        except Exception as artifact_error:
            export = {"status": "FAILED", "error": str(artifact_error)}
            result["artifact_export"] = export

    if not export_saved:
        if is_terminal:
            st.error(f"Package export failed: {export.get('error', 'unknown export error')}")
            if st.button("Retry Export Investigation Package", type="primary"):
                st.rerun()
        else:
            st.info("The investigation package becomes available after execution completes.")
        return

    tests = export.get("test_results", {})
    c1, c2, c3 = st.columns(3)
    c1.metric("Artifact Status", "SAVED")
    c2.metric("Invariant Tests", f"{tests.get('passed_count', 0)}/{tests.get('total', 0)}")
    c3.metric("Test Result", "PASS" if tests.get("passed") else "REVIEW")
    st.caption(f"Audit directory: {export.get('directory')}")
    zip_path = Path(str(export.get("zip_path", "")))
    if zip_path.is_file():
        st.download_button(
            "Download Investigation Package",
            data=zip_path.read_bytes(),
            file_name=zip_path.name,
            mime="application/zip",
            type="primary",
        )
    with st.expander("Saved regression checks"):
        render_table("Runtime Invariants", tests.get("checks", []))


def render_auditability(result):
    st.header("Auditability Control Center")
    st.caption(
        "Board-ready audit view showing what was captured, reconciled, stored, and exported for this investigation."
    )

    export = _safe_dict(result.get("artifact_export"))
    runtime_status = str(result.get("runtime_status") or result.get("status") or "").upper()
    current_phase = str(result.get("current_phase") or result.get("phase") or "").upper()
    is_terminal = (
        runtime_status in {"COMPLETED", "COMPLETE", "SUCCESS", "SUCCEEDED"}
        or current_phase in {"RUNTIME_COMPLETE", "COMPLETED", "COMPLETE"}
    )
    export_saved = export.get("status") == "SAVED"
    ledger_ready = bool(_safe_get(export.get("audit_ledger"), "path"))
    if is_terminal and (not export_saved or not ledger_ready):
        try:
            from services1.investigation_artifact_service import save_investigation_artifacts
            export = save_investigation_artifacts(result)
            result["artifact_export"] = export
            st.session_state["runtime_state"] = result
        except Exception as artifact_error:
            export = {"status": "FAILED", "error": str(artifact_error)}
            result["artifact_export"] = export

    ledger = _safe_dict(export.get("audit_ledger"))
    manifest = _safe_dict(export.get("manifest"))
    tests = _safe_dict(export.get("test_results"))
    test_checks = tests.get("checks", []) if isinstance(tests.get("checks"), list) else []
    consistency_rows = _canonical_consistency_audit_rows(result)
    mismatch_rows = [row for row in consistency_rows if row.get("Status") == "MISMATCH"]
    agent_counts = _canonical_agent_counts(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    artifact_files = manifest.get("files", []) if isinstance(manifest.get("files"), list) else []

    ledger_status = str(ledger.get("status") or "-").upper()
    export_status = str(export.get("status") or "-").upper()
    consistency_status = "PASS" if not mismatch_rows else f"{len(mismatch_rows)} mismatch(es)"

    render_compact_status_grid([
        ("Artifact Package", export_status),
        ("Audit Ledger", ledger_status),
        ("Invariant Tests", f"{tests.get('passed_count', 0)}/{tests.get('total', 0)} passed" if tests else "-"),
        ("Canonical Consistency", consistency_status),
        ("Agent Records", agent_counts.get("executed", 0)),
        ("Evidence Records", evidence_count),
        ("Artifact Files", len(artifact_files)),
        ("Ledger Location", ledger.get("path") or "Generated after package export"),
    ])

    render_story_strip([
        {
            "eyebrow": "STEP 1",
            "title": "Runtime Captured",
            "detail": f"{agent_counts.get('executed', 0)}/{agent_counts.get('total', 0)} agents recorded",
            "state": "pass" if agent_counts.get("executed", 0) else "review",
        },
        {
            "eyebrow": "STEP 2",
            "title": "Canonical Reconciled",
            "detail": consistency_status,
            "state": "pass" if not mismatch_rows else "review",
        },
        {
            "eyebrow": "STEP 3",
            "title": "Evidence Retained",
            "detail": f"{evidence_count} evidence rows",
            "state": "pass" if evidence_count else "review",
        },
        {
            "eyebrow": "STEP 4",
            "title": "Ledger Stored",
            "detail": ledger_status,
            "state": "pass" if ledger_status == "SAVED" else "review",
        },
        {
            "eyebrow": "STEP 5",
            "title": "Package Exported",
            "detail": export_status,
            "state": "pass" if export_status == "SAVED" else "review",
        },
    ])

    st.subheader("Audit Ledger Map")
    st.caption("These are the durable tables maintained for audit review and operational replay.")
    ledger_counts = _audit_ledger_table_counts(ledger, result.get("runtime_id"))
    if not ledger_counts:
        st.info("Ledger row counts appear after the audit package is generated or refreshed for this run.")
    render_table("Audit Tables", [
        {
            "Table": "audit_run",
            "Purpose": "One row per investigation with customer, query, recommendation, scores, and package location.",
            "Rows": ledger_counts.get("audit_run", "-"),
        },
        {
            "Table": "audit_agent_execution",
            "Purpose": "Agent execution status, order, phase, tool, and execution time.",
            "Rows": ledger_counts.get("audit_agent_execution", "-"),
        },
        {
            "Table": "audit_evidence",
            "Purpose": "Evidence chunk source, trust score, rank, and content hash for traceability.",
            "Rows": ledger_counts.get("audit_evidence", "-"),
        },
        {
            "Table": "audit_decision",
            "Purpose": "Final recommendation, risk level, governance status, HITL requirement, and rationale.",
            "Rows": ledger_counts.get("audit_decision", "-"),
        },
        {
            "Table": "audit_consistency_check",
            "Purpose": "Canonical value checks across tabs, summaries, exports, and runtime objects.",
            "Rows": ledger_counts.get("audit_consistency_check", "-"),
        },
        {
            "Table": "audit_cache_event",
            "Purpose": "Cache layer lookup, hit/miss, TTL, and interpretation for reuse audits.",
            "Rows": ledger_counts.get("audit_cache_event", "-"),
        },
        {
            "Table": "audit_artifact",
            "Purpose": "Generated report, JSON, CSV, image, and ZIP file inventory with hashes.",
            "Rows": ledger_counts.get("audit_artifact", "-"),
        },
    ])

    if mismatch_rows:
        st.warning("Canonical mismatches require review before this run is presented externally.")
        render_table("Canonical Consistency Exceptions", mismatch_rows)
    else:
        st.success("Canonical recommendation, risk, compliance, trust, and confidence values are consistent across audited objects.")

    failed_checks = [
        row for row in test_checks
        if isinstance(row, dict) and not bool(row.get("passed"))
    ]
    if failed_checks:
        st.warning("Runtime invariant checks found exceptions.")
        def failed_check_explanation(row):
            check_id = str(row.get("id") or "")
            actual = row.get("actual")
            if check_id == "executive_llm_grounding":
                forbidden = []
                validation = {}
                if isinstance(actual, dict):
                    forbidden = actual.get("forbidden_terms") or []
                    validation = actual.get("validation") if isinstance(actual.get("validation"), dict) else {}
                if forbidden:
                    return (
                        "Executive generated content contains non-banking strategy language "
                        f"({', '.join(str(item) for item in forbidden)}).",
                        "Regenerate/refresh the executive narrative so it is grounded only in customer, risk, governance, and evidence data.",
                    )
                if not validation.get("passed"):
                    return (
                        "Executive grounding validation did not pass.",
                        "Review the executive narrative against retrieved evidence and rerun the package export.",
                    )
            if check_id == "recommendation_consistency":
                return (
                    "One or more runtime objects carries an old recommendation value.",
                    "Use the canonical recommendation as the source of truth and rerun the investigation/export.",
                )
            if check_id == "trust_consistency":
                return (
                    "One or more runtime objects carries an old trust score.",
                    "Use the canonical trust score and rerun the investigation/export.",
                )
            if check_id == "confidence_consistency":
                return (
                    "One or more runtime objects carries an old confidence value.",
                    "Use the canonical confidence value and rerun the investigation/export.",
                )
            if check_id == "human_review_consistency":
                return (
                    "The saved artifact carries an old human-review flag that does not match the final release decision.",
                    "Regenerate the audit package so the saved invariant uses the same HITL/release authority as the live UI.",
                )
            if check_id == "retrieval_scope_enforced":
                return (
                    "Retrieved evidence was present but the runtime did not mark customer/entity scoping as enforced.",
                    "Check retrieval scope metadata before presenting evidence lineage.",
                )
            if check_id == "no_runtime_errors":
                return (
                    "The runtime recorded one or more execution errors.",
                    "Review the runtime error list and rerun after correction.",
                )
            return (
                "The saved runtime invariant did not meet its expected condition.",
                "Open the raw actual value for diagnosis and rerun the export after correction.",
            )

        explained_failed_checks = []
        for row in failed_checks:
            reason, action = failed_check_explanation(row)
            explained_failed_checks.append({
                "Check": row.get("id"),
                "Status": "FAILED",
                "Reason": reason,
                "Recommended Action": action,
                "Actual": row.get("actual"),
            })
        render_table("Failed Runtime Checks", explained_failed_checks)
    elif test_checks:
        render_table("Runtime Checks", test_checks[:12])
    else:
        st.info("Runtime invariant checks are populated after the audit package is generated.")

    if artifact_files:
        st.subheader("Artifact Inventory")
        render_table("Saved Audit Assets", artifact_files[:30])
    else:
        st.info("Artifact inventory is populated after the audit package is generated.")


def render_llm_cost_summary(result):
    st.header("Model Cost & Token Economics")
    telemetry = _safe_dict(result.get("runtime_telemetry"))
    token = (
        result.get("token_metrics")
        or telemetry.get("token_metrics")
        or _safe_get(result, "runtime_health_v2", {}).get("token_metrics", {})
    )
    token = token if isinstance(token, dict) else {}
    cost = telemetry.get("cost_metrics") or result.get("cost_metrics") or {}
    cost = cost if isinstance(cost, dict) else {}
    observed_provider, observed_model = _observed_llm_identity(result, token)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Provider", observed_provider or "-")
    c2.metric("Model", observed_model or "-")
    c3.metric("Total Tokens", token.get("total_tokens", 0))
    c4.metric("Estimated Cost (USD)", token.get("estimated_cost_usd", cost.get("estimated_cost_usd", 0)))

    render_token_execution_chart(result, token)

    render_table("Token Consumption", [
        {"Metric": "Prompt Tokens", "Value": token.get("prompt_tokens", 0)},
        {"Metric": "Completion Tokens", "Value": token.get("completion_tokens", 0)},
        {"Metric": "Embedding Tokens", "Value": token.get("embedding_tokens", 0)},
        {"Metric": "Token Efficiency", "Value": token.get("token_efficiency", "-")},
        {"Metric": "Agents", "Value": token.get("agents", "-")},
        {"Metric": "Average Tokens / Agent", "Value": token.get("avg_tokens_per_agent", "-")},
        {"Metric": "Status", "Value": token.get("status", "-")},
    ])

    if cost:
        render_table(
            "Cost Monitoring",
            [
                {
                    "Metric": _cost_metric_label(k),
                    "Value": v,
                }
                for k, v in cost.items()
            ],
        )
    else:
        st.info("Cost metrics not available.")

    llm_trace = result.get("llm_trace", {})
    if isinstance(llm_trace, list) and llm_trace:
        llm_cost_rows = list(_llm_trace_rows_with_cost(result, token, cost))
        render_table("LLM Trace", llm_cost_rows)
        if any(str(row.get("Cost Basis")) == "Not attributable - token telemetry not available" for row in llm_cost_rows):
            st.info(
                "Per-agent model cost is calculated only from token telemetry. Latency is not used for cost allocation because "
                "waiting time, retrieval, CPU processing, and serialization do not necessarily burn model tokens."
            )
    elif isinstance(llm_trace, dict) and llm_trace:
        render_table(
            "LLM Trace",
            [{"LLM": k, **v} if isinstance(v, dict) else {"LLM": k, "Value": v} for k, v in llm_trace.items()],
        )
    else:
        st.info("LLM trace unavailable.")


def render_cache_intelligence(result):
    st.header("Cache Acceleration")
    cache = _runtime_cache_payload(result)
    cache_statistics = result.get("cache_statistics", {})
    cache_statistics = cache_statistics if isinstance(cache_statistics, dict) else {}
    cache_decision = result.get("cache_decision", {})
    cache_decision = cache_decision if isinstance(cache_decision, dict) else {}
    cache_savings = result.get("cache_savings", {})
    cache_savings = cache_savings if isinstance(cache_savings, dict) else {}
    query_cache = result.get("query_cache", {})
    query_cache = query_cache if isinstance(query_cache, dict) else {}

    if not cache:
        st.info("Cache intelligence metrics unavailable.")
        return

    status = str(cache.get("status", "ANALYZED")).upper()
    render_cache_business_impact_visual(result, cache)

    if status == "HIT":
        st.success(
            "Runtime response served from cache. The agent traversal and model calls were avoided for this request."
        )
    elif status == "STORED":
        st.info(
            "Fresh full-runtime result stored. Query cache may already be reused, but full-result reuse starts on the next identical customer, investigation type, and analyst query."
        )
    elif status == "BYPASSED":
        st.warning(cache.get("reason", "Runtime cache was bypassed for this execution."))
    else:
        st.caption("Runtime cache lookup completed. Layer cache health is shown below.")

    render_compact_status_grid([
        ("Runtime Cache Status", status),
        ("Query Cache Status", query_cache.get("status", "-")),
        ("Cache Key", cache.get("cache_key", "-")),
        ("Cache Query", result.get("cache_key_query", "-")),
        ("Entries", cache.get("entries", 0)),
        ("TTL", _format_agent_latency(int(_numeric_score(cache.get("ttl_seconds"), 0)) * 1000) if cache.get("ttl_seconds") else "-"),
        ("Remaining TTL", _cache_remaining_ttl_display(cache)),
        ("Age", _cache_age_display(cache)),
        ("Cache Explanation", _cache_miss_reason(cache, query_cache)),
    ])

    key_dimensions = cache.get("key_dimensions")
    if isinstance(key_dimensions, dict) and key_dimensions:
        render_table(
            "Full Runtime Cache Exact-Match Contract",
            [
                {
                    "Dimension": str(key).replace("_", " ").title(),
                    "Value / Fingerprint": value,
                    "Why It Is In The Key": {
                        "customer_id": "Prevents serving another customer's result.",
                        "query": "Ensures the analyst objective is identical after canonical normalization.",
                        "app_version": "Invalidates cache when the onboarded app workflow changes.",
                        "data_fingerprint": "Invalidates cache when CSV/source knowledge changes.",
                        "model_version": "Invalidates cache when the model/runtime changes.",
                        "policy_version": "Invalidates cache when governance/risk policy changes.",
                        "cache_version": "Invalidates old cache contracts after AEGIS logic changes.",
                    }.get(str(key), "Part of the exact runtime reuse contract."),
                }
                for key, value in key_dimensions.items()
            ],
        )

    layers = _cache_layer_payload(result)
    render_cache_acceleration_visual(cache, layers, query_cache)
    if isinstance(layers, dict) and layers:
        cdc = layers.get("embedding_cdc", {})
        if isinstance(cdc, dict) and _numeric_score(cdc.get("hit_ratio"), 0) > 0:
            st.success(
                f"Persistent embedding reuse is active: Embedding CDC hit ratio is {cdc.get('hit_ratio', 0)}% "
                f"with {cdc.get('hits', 0)} hit(s)."
            )
        layer_rows = _cache_layer_display_rows(layers, query_cache)
        render_table("Cache Layer Reuse", layer_rows)

    with st.expander("Cache Diagnostics"):
        render_table(
            "Runtime Cache Telemetry",
            [{"Metric": str(k).replace("_", " ").title(), "Value": v} for k, v in cache.items() if k != "layers"],
        )
        if cache_statistics:
            render_table(
                "Cache Statistics",
                [{"Metric": str(k).replace("_", " ").title(), "Value": v} for k, v in cache_statistics.items()],
            )
        if query_cache:
            render_table(
                "Query Cache Telemetry",
                [{"Metric": str(k).replace("_", " ").title(), "Value": v} for k, v in query_cache.items()],
            )
        if cache_decision:
            render_table(
                "Cache Decision",
                [{"Metric": str(k).replace("_", " ").title(), "Value": v} for k, v in cache_decision.items()],
            )
        if cache_savings:
            render_table(
                "Estimated Cache Savings",
                [{"Metric": str(k).replace("_", " ").title(), "Value": v} for k, v in cache_savings.items()],
            )


def render_persona_operating_model(result):
    """Persona-first framing so AEGIS is read by role before deep technical tabs."""
    release_assessment = _governance_release_assessment(result)
    agent_counts = _canonical_agent_counts(result)
    quality = _canonical_quality_scores(result)
    evidence_count = _safe_count(result.get("evidence_pack") or result.get("retrieved_chunks"))
    policy = _safe_dict(result.get("policy_as_code"))
    failed_policy = int(policy.get("failed_count") or 0)
    critical_failed = int(policy.get("critical_failed_count") or 0)
    policy_exception_label = (
        "No active policy exception"
        if failed_policy == 0 and critical_failed == 0
        else f"{failed_policy} policy exception(s), {critical_failed} critical"
    )
    policy_controls_payload = policy.get("controls") or policy.get("checks") or policy.get("results") or []
    if isinstance(policy_controls_payload, dict):
        policy_controls_payload = list(policy_controls_payload.values())
    named_policy_exceptions = []
    unnamed_policy_signals = []
    if isinstance(policy_controls_payload, list):
        for index, item in enumerate(policy_controls_payload, start=1):
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or item.get("result") or "").upper()
            severity = str(item.get("severity") or item.get("level") or "").upper()
            if status in {"FAIL", "FAILED", "ERROR", "BLOCK", "REVIEW"} or severity in {"CRITICAL", "HIGH"}:
                control_name = item.get("control") or item.get("name") or item.get("id")
                rationale = item.get("rationale") or item.get("reason") or item.get("description")
                if control_name or rationale:
                    named_policy_exceptions.append(
                        {
                            "Exception": control_name or f"Policy signal {index}",
                            "Status": item.get("status") or item.get("result") or "REVIEW",
                            "Severity": item.get("severity") or item.get("level") or "REVIEW",
                            "Why It Is An Exception": rationale or "Runtime emitted a policy exception with partial rationale.",
                            "Source Variable": "policy_as_code.controls/checks/results",
                        }
                    )
                else:
                    unnamed_policy_signals.append(
                        {
                            "signal_index": index,
                            "status": item.get("status") or item.get("result") or "REVIEW",
                            "severity": item.get("severity") or item.get("level") or "REVIEW",
                        }
                    )
    policy_rationale_text = str(release_assessment.get("rationale") or "")
    policy_rationale_conflict = failed_policy > 0 and "passed" in policy_rationale_text.casefold()
    exact_policy_issue = (
        f"Policy count/rationale mismatch: policy_as_code.failed_count={failed_policy}, "
        f"policy_as_code.critical_failed_count={critical_failed}, but release_assessment.rationale says "
        f"'{policy_rationale_text or '-'}'."
        if policy_rationale_conflict
        else (
            f"Policy failed count is present but unnamed: policy_as_code.failed_count={failed_policy}, "
            f"policy_as_code.critical_failed_count={critical_failed}. The emitting policy agent must provide "
            "control name, status, rationale, severity, and remediation."
        )
    )
    if not named_policy_exceptions and (failed_policy > 0 or critical_failed > 0):
        named_policy_exceptions.append(
            {
                "Exception": "Policy count and rationale consistency gap" if policy_rationale_conflict else "Unnamed policy exception count",
                "Status": "REVIEW",
                "Severity": "REVIEW" if critical_failed == 0 else "CRITICAL",
                "Exact Issue": exact_policy_issue,
                "Why It Is An Exception": (
                    "The failed-control count and release narrative are not aligned, so AEGIS must surface the mismatch explicitly."
                ) if policy_rationale_conflict else "policy_as_code reports failed controls but did not emit named failed-control details.",
                "Source Variable": "policy_as_code.failed_count, release_assessment.rationale",
            }
        )
    elif unnamed_policy_signals:
        named_policy_exceptions.append(
            {
                "Exception": f"{len(unnamed_policy_signals)} unnamed policy signal(s)",
                "Status": "REVIEW",
                "Severity": "REVIEW" if any(sig["severity"] == "HIGH" for sig in unnamed_policy_signals) else "LOW",
                "Exact Issue": (
                    f"{len(unnamed_policy_signals)} policy signal(s) had REVIEW/HIGH/CRITICAL status "
                    "but no named control or rationale in policy_as_code.controls/checks/results."
                ),
                "Why It Is An Exception": (
                    "Policy runtime emitted severity/review signals without named controls or rationales. "
                    "This is a telemetry enrichment item and should be improved at the source."
                ),
                "Source Variable": "policy_as_code.controls/checks/results",
            }
        )
    cost = result.get("estimated_cost_usd") or _safe_get(result, "token_metrics", {}).get("estimated_cost_usd") or "-"
    executed_agents = int(agent_counts.get("executed") or 0)
    completed_agents = int(agent_counts.get("completed") or 0)
    failed_agents = int(agent_counts.get("failed") or 0)
    agent_success_rate = (
        f"{(completed_agents / executed_agents) * 100:.1f}%"
        if executed_agents
        else "-"
    )
    expected_behavior = (
        "YES"
        if result.get("runtime_status", result.get("status", "")).upper() == "COMPLETED"
        and failed_agents == 0
        and failed_policy == 0
        and release_assessment["release_allowed"]
        else "REVIEW"
    )
    recommendation_label = (
        release_assessment.get("recommendation")
        or release_assessment.get("governance_status")
        or release_assessment.get("release_route")
        or "-"
    )
    release_route_label = release_assessment.get("release_route") or "-"
    security = _safe_dict(result.get("security_analysis") or result.get("security"))
    security_score = _numeric_score(security.get("security_score"), "-")
    security_status = security.get("security_status") or security.get("status") or "-"
    security_risk = security.get("risk_level") or "-"
    security_checks = security.get("checks") if isinstance(security.get("checks"), list) else []
    owasp_review_count = sum(
        1 for check in security_checks
        if str(check.get("status", "")).upper() in {"REVIEW", "WARN", "WARNING"}
    )
    owasp_failed_count = sum(
        1 for check in security_checks
        if str(check.get("status", "")).upper() in {"FAILED", "FAIL", "ERROR", "CRITICAL", "BLOCK"}
    )
    if not security_checks:
        owasp_failed_count = _safe_count(security.get("failed_controls"))
        owasp_review_count = _safe_count(security.get("review_controls"))
    owasp_top10_fallback = [
        {"OWASP IDs": "LLM01", "OWASP Control": "Prompt Injection", "Status": security.get("prompt_injection", {}).get("status", "-"), "Score": security.get("prompt_injection", {}).get("score", "-"), "Reason / Findings": "Direct or indirect prompt manipulation checks."},
        {"OWASP IDs": "LLM02", "OWASP Control": "Sensitive Information Disclosure", "Status": security.get("pii_exposure", {}).get("status", "-"), "Score": security.get("pii_exposure", {}).get("score", "-"), "Reason / Findings": "PII, confidential data, and sensitive-field exposure checks."},
        {"OWASP IDs": "LLM03", "OWASP Control": "Supply Chain", "Status": security.get("supply_chain", {}).get("status", "REFERENCE"), "Score": security.get("supply_chain", {}).get("score", "-"), "Reason / Findings": "Model, dependency, plugin, package, or external component provenance checks."},
        {"OWASP IDs": "LLM04", "OWASP Control": "Data and Model Poisoning", "Status": security.get("data_poisoning", {}).get("status", "REFERENCE"), "Score": security.get("data_poisoning", {}).get("score", "-"), "Reason / Findings": "Training, retrieval, memory, or knowledge-source contamination checks."},
        {"OWASP IDs": "LLM05", "OWASP Control": "Improper Output Handling", "Status": security.get("output_handling", {}).get("status", "-"), "Score": security.get("output_handling", {}).get("score", "-"), "Reason / Findings": "Unsafe downstream action, unescaped output, and release-gate checks."},
        {"OWASP IDs": "LLM06", "OWASP Control": "Excessive Agency", "Status": security.get("tool_security", {}).get("status", "-"), "Score": security.get("tool_security", {}).get("score", "-"), "Reason / Findings": "Tool access, unauthorized action, and agent permission checks."},
        {"OWASP IDs": "LLM07", "OWASP Control": "System Prompt Leakage", "Status": security.get("prompt_leakage", {}).get("status", "-"), "Score": security.get("prompt_leakage", {}).get("score", "-"), "Reason / Findings": "System prompt, hidden instruction, and internal policy leakage checks."},
        {"OWASP IDs": "LLM08", "OWASP Control": "Vector and Embedding Weaknesses", "Status": security.get("vector_embedding", {}).get("status", "-"), "Score": security.get("vector_embedding", {}).get("score", "-"), "Reason / Findings": "Retrieval scope, embedding leakage, and vector-store integrity checks."},
        {"OWASP IDs": "LLM09", "OWASP Control": "Misinformation", "Status": security.get("misinformation", {}).get("status", "-"), "Score": security.get("misinformation", {}).get("score", "-"), "Reason / Findings": "Grounding, hallucination, unsupported claim, and evidence-alignment checks."},
        {"OWASP IDs": "LLM10", "OWASP Control": "Unbounded Consumption", "Status": security.get("runtime_limits", {}).get("status", "-"), "Score": security.get("runtime_limits", {}).get("score", "-"), "Reason / Findings": "Token, latency, retry, recursion, and resource-consumption checks."},
    ]
    owasp_control_rows = _complete_security_controls(security, owasp_top10_fallback)
    existing_owasp_ids = {
        str(row.get("OWASP IDs", "")).split(",")[0].strip()
        for row in owasp_control_rows
        if isinstance(row, dict)
    }
    for fallback_row in owasp_top10_fallback:
        fallback_id = str(fallback_row.get("OWASP IDs", "")).strip()
        if fallback_id and fallback_id not in existing_owasp_ids:
            owasp_control_rows.append(
                {
                    **fallback_row,
                    "Status": fallback_row.get("Status") or "REFERENCE",
                    "Reason / Findings": fallback_row.get("Reason / Findings") or "Control category is available in the AEGIS OWASP catalog.",
                }
            )

    onboarding_contract_status = "Unavailable"
    onboarding_total = "-"
    onboarding_mandatory = "-"
    onboarding_optional = "-"
    onboarding_groups = "-"
    contract_df = pd.DataFrame()
    required_col = None
    object_col = None
    category_col = None
    try:
        workbook_path = _aegis_output_file("AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx")
        sheets = _load_onboarding_contract(str(workbook_path))
        contract_df = sheets.get("Telemetry Contract", pd.DataFrame())
        if not contract_df.empty:
            required_col = "Required" if "Required" in contract_df.columns else None
            object_col = "Object / Category" if "Object / Category" in contract_df.columns else ("Object" if "Object" in contract_df.columns else None)
            category_col = "Category" if "Category" in contract_df.columns else None
            onboarding_contract_status = "Available"
            onboarding_total = len(contract_df)
            onboarding_mandatory = int((contract_df[required_col].astype(str).str.lower() == "mandatory").sum()) if required_col else "-"
            onboarding_optional = int((contract_df[required_col].astype(str).str.lower() == "optional").sum()) if required_col else "-"
            onboarding_groups = int(contract_df[category_col].nunique()) if category_col else (int(contract_df[object_col].nunique()) if object_col else "-")
    except Exception:
        onboarding_contract_status = "Unavailable"

    st.subheader("Persona-Specific AEGIS Views")
    st.caption(
        "A role-based operating model for AI applications and agents: leadership sees value and risk, "
        "administrators see exceptions, developers see trace/debug detail, and onboarders see contract readiness."
    )

    runtime_status = result.get("runtime_status", result.get("status", "-"))
    avg_agent_time = _format_agent_latency(agent_counts.get("avg_latency_ms", 0))
    cache = _runtime_cache_payload(result)
    cache_status = str(cache.get("status", "-")).upper()
    cache_hit_ratio = cache.get("cache_hit_ratio", 0)
    cache_hits = int(_numeric_score(cache.get("cache_hits"), 0))
    cache_misses = int(_numeric_score(cache.get("cache_misses"), 0))
    cache_entries = cache.get("entries", 0)
    cache_ttl = _format_agent_latency(int(_numeric_score(cache.get("ttl_seconds"), 0)) * 1000) if cache.get("ttl_seconds") else "-"
    cache_remaining_ttl = _cache_remaining_ttl_display(cache)
    cache_age = _cache_age_display(cache)
    cache_mode = "Served from cache" if cache_status == "HIT" else "Stored for reuse" if cache_status == "STORED" else cache_status
    export = _safe_dict(result.get("artifact_export"))
    ledger = _safe_dict(export.get("audit_ledger"))
    manifest = _safe_dict(export.get("manifest"))
    tests = _safe_dict(export.get("test_results"))
    artifact_files = manifest.get("files", []) if isinstance(manifest.get("files"), list) else []
    consistency_rows_for_persona = _canonical_consistency_audit_rows(result)
    mismatch_count = sum(1 for row in consistency_rows_for_persona if row.get("Status") == "MISMATCH")
    ledger_counts_for_persona = _audit_ledger_table_counts(ledger, result.get("runtime_id"))
    export_status = str(export.get("status") or "-").upper()
    ledger_status = str(ledger.get("status") or "-").upper()
    consistency_status = "PASS" if mismatch_count == 0 else f"{mismatch_count} mismatch(es)"
    invariant_value = f"{tests.get('passed_count', 0)}/{tests.get('total', 0)} passed" if tests else "-"
    trace_for_dora = _normalized_agent_trace(result)
    total_retry_count = sum(int(_numeric_score(row.get("retry_count", row.get("retries", 0)), 0)) for row in trace_for_dora)
    task_completed = runtime_status == "COMPLETED"
    autonomous_resolution = bool(task_completed and release_assessment["release_allowed"] and not release_assessment["review_required"])
    human_override_value = "YES" if release_assessment["review_required"] else "NO"
    escalation_rate_proxy = "100%" if release_assessment["review_required"] else "0%"
    exception_rate_proxy = f"{((failed_agents / executed_agents) * 100):.1f}%" if executed_agents else "-"
    retry_rate_proxy = f"{((total_retry_count / executed_agents) * 100):.1f}%" if executed_agents else "-"
    cost_per_task = cost if task_completed else "-"
    total_execution_latency = _format_agent_latency(agent_counts.get("latency_ms", 0))
    sla_status = "PASS" if _numeric_score(agent_counts.get("latency_ms"), 0) <= 30 * 60 * 1000 else "REVIEW"
    hallucination_signal = quality.get("hallucination_score", quality.get("hallucination", "-"))
    grounding_signal = quality.get("groundedness", quality.get("grounding_score", "-"))
    context_utilization_signal = quality.get("coverage", "-")
    rag_quality_signal = f"Grounding: {grounding_signal} | Coverage: {context_utilization_signal} | Evidence: {evidence_count}"
    auditability_rate = "100%" if export.get("status") == "SAVED" and mismatch_count == 0 else "REVIEW"
    policy_compliance_rate = "100%" if failed_policy == 0 and critical_failed == 0 else "REVIEW"
    security_incident_proxy = owasp_failed_count + owasp_review_count

    def _canonical_key_tokens(parameter):
        text = str(parameter or "").replace(" / ", "/").replace(",", "/")
        return [part.strip() for part in text.split("/") if part.strip()]

    def _live_runtime_keys():
        keys = set()
        for row in trace_for_dora:
            if isinstance(row, dict):
                keys.update(str(key) for key, value in row.items() if not _is_unknown_value(value))
        for container in [
            result,
            result.get("canonical_runtime_event_contract"),
            result.get("canonical_values"),
            result.get("canonical_display"),
            result.get("artifact_export"),
            result.get("policy_as_code"),
            result.get("security_analysis"),
            result.get("cache_lookup"),
        ]:
            if isinstance(container, dict):
                keys.update(str(key) for key, value in container.items() if not _is_unknown_value(value))
        return {key.casefold() for key in keys}

    def _canonical_parameter_coverage_rows():
        live_keys = _live_runtime_keys()
        required_rows = [
            row for row in _canonical_parameter_catalog_rows()
            if str(row.get("Mandatory / Non Mandatory", "")).casefold().startswith("mandatory")
        ]
        rows = []
        missing = []
        for row in required_rows:
            parameter = row.get("Canonical Object / Parameter")
            emitted = str(parameter or "").casefold() in live_keys
            if not emitted:
                missing.append(str(parameter))
            rows.append(
                {
                    "#": row.get("#"),
                    "Canonical Parameter": parameter,
                    "Required": row.get("Mandatory / Non Mandatory"),
                    "Data Type": row.get("Data Type"),
                    "Added / Emitted": "YES" if emitted else "NO",
                    "Telemetry Status": "Observed in current runtime" if emitted else "Catalog reference field",
                    "Why Required": row.get("Why AEGIS Requires It"),
                    "Source Variable": "agent_trace, canonical_runtime_event_contract, canonical_values, canonical_display",
                }
            )
        return rows, missing

    canonical_coverage_rows, missing_canonical_parameters = _canonical_parameter_coverage_rows()
    canonical_catalog_count = len(_canonical_parameter_catalog_rows())
    canonical_required_count = len(canonical_coverage_rows)
    canonical_added_count = sum(1 for row in canonical_coverage_rows if row.get("Added / Emitted") == "YES")
    canonical_gap_count = canonical_required_count - canonical_added_count
    agent_adoption_rows = _agent_adoption_registry_rows(result)
    agent_telemetry_schema_rows = _agent_telemetry_log_schema_rows()
    agent_adoption_source = (
        "Registry telemetry"
        if result.get("agent_adoption_registry") or result.get("agent_registry") or result.get("adopted_agents")
        else "Agent trace fallback"
    )
    agent_adoption_summary = (
        f"Tracked: {len(agent_adoption_rows)} | Schema fields: {len(agent_telemetry_schema_rows)} | Source: {agent_adoption_source}"
    )
    persona_rows = []

    def _persona_metric_derivation(metric, source_variable):
        metric_text = str(metric or "").casefold()
        if "deployment frequency" in metric_text:
            return "Counts the current run as one governed release-readiness event when release is allowed; portfolio frequency needs historical run aggregation."
        if "lead-time" in metric_text:
            return "Uses total observed runtime duration as the current-run lead-time proxy."
        if "mttr" in metric_text or "recovery" in metric_text:
            return "Uses runtime completion, failed-agent count, retry count, and recovery/release route as the current-run recovery proxy."
        if "task completion" in metric_text:
            return "100% when the runtime status is COMPLETED; otherwise 0% for the current run."
        if "autonomous resolution" in metric_text:
            return "100% when runtime completed, release is allowed, and no human review is required."
        if "human override" in metric_text or "escalation" in metric_text:
            return "100% when human review is required for this run; otherwise 0%."
        if "first-time success" in metric_text:
            return "Passes when release is allowed with no retries, no failed agents, and no critical control failures."
        if "rework" in metric_text:
            return "Review signal when retry, human review, or critical control failure indicates rework."
        if "hallucination" in metric_text:
            return "Reads hallucination/misinformation signal from quality and OWASP/security evaluation."
        if "rag quality" in metric_text:
            return "Combines grounding, context coverage, and evidence count for retrieval-backed agent quality."
        if "context utilization" in metric_text:
            return "Reads context/evidence coverage from quality scoring."
        if "collaboration success" in metric_text:
            return "Uses completed agents, executed agents, and observed handoffs as the multi-agent collaboration proxy."
        if "sla compliance" in metric_text:
            return "Compares total observed runtime against the configured current-run SLA threshold."
        if "policy compliance" in metric_text:
            return "100% when failed and critical policy counts are zero; otherwise review."
        if "auditability rate" in metric_text:
            return "100% when audit package is saved and canonical consistency has no mismatches."
        if "security incident" in metric_text:
            return "Counts OWASP review and failed controls as current-run AI security incident signals."
        if "cost per task" in metric_text:
            return "Uses estimated runtime/model cost as cost per completed investigation task."
        if "maturity" in metric_text:
            return "Classifies current-run maturity from observed agent count and presence of governance/audit controls."
        if "success rate" in metric_text:
            return "Completed observed agents divided by executed observed agents, multiplied by 100."
        if "execution coverage" in metric_text or "signal coverage" in metric_text:
            return "Executed observed agents compared with total registered/planned countable agents."
        if "failed agents" in metric_text or "agent failure" in metric_text:
            return "Count of observed agents whose runtime status is FAILED, ERROR, or CRITICAL."
        if "handoff" in metric_text:
            return "Count of observed graph transitions between countable runtime agents."
        if "evidence" in metric_text:
            return "Count of evidence objects available in the evidence pack or retrieved chunks."
        if "cache" in metric_text:
            return "Reads runtime cache status, hit/miss, TTL, entry count, and age from the cache payload."
        if "audit" in metric_text or "ledger" in metric_text or "artifact" in metric_text or "invariant" in metric_text:
            return "Reads saved audit package, ledger, invariant checks, artifact manifest, and canonical consistency audit."
        if "measur" in metric_text or "execution time" in metric_text or "latency" in metric_text:
            return "Uses runtime telemetry, agent timing, token metrics, cost metrics, and observed execution events."
        if "scalab" in metric_text or "reuse" in metric_text:
            return "Uses cache reuse, onboarding contract, asset inventory, and repeatable telemetry contract signals."
        if "resilien" in metric_text or "reliability" in metric_text or "retry" in metric_text:
            return "Uses runtime completion, failed agents, retry fields, cache status, and release-route resilience signals."
        if "owasp" in metric_text or "security" in metric_text:
            return "Summarizes OWASP/security control statuses, review findings, failed controls, risk level, and security score from runtime security analysis."
        if "onboarding" in metric_text or "mandatory contract" in metric_text or "canonical contract" in metric_text:
            return "Summarizes the onboarding telemetry contract workbook and mandatory fields required for AEGIS governance."
        if "policy" in metric_text or "exception" in metric_text or "control failures" in metric_text:
            return "Count of failed or critical policy-as-code checks emitted by the governance runtime."
        if "hitl" in metric_text:
            return "Boolean release assessment flag showing whether human review is required."
        if "release route" in metric_text or "release readiness" in metric_text or "governed release" in metric_text:
            return "Final governance route selected from the release assessment after policy, quality, and runtime checks."
        if "trust" in metric_text or "confidence" in metric_text or "assurance" in metric_text or "quality" in metric_text:
            return "Latest quality scores emitted by AEGIS trust, confidence, grounding, or evaluation checks."
        if "cost" in metric_text:
            return "Estimated model/runtime cost from token economics for the current execution."
        if "average agent time" in metric_text:
            return "Total observed agent duration divided by executed observed agents."
        if "runtime completion" in metric_text or "runtime decision" in metric_text:
            return "Current runtime status emitted by the orchestrator for this investigation."
        if "expected-behavior" in metric_text:
            return "YES only when runtime completed, no agents failed, no policy exception exists, and release is allowed."
        if "recommendation" in metric_text:
            return "Application recommendation selected from release assessment, governance status, or release route fallback."
        if "runtime source" in metric_text or "contract source" in metric_text:
            return "Telemetry source selected by AEGIS for the current agent count and runtime trace."
        return f"Value is read or summarized from {source_variable} for the current live runtime."

    def add_persona_metric(persona, metric, significance, live_value, source_variable):
        persona_rows.append(
            {
                "Persona": persona,
                "What They Track": metric,
                "Significance of the Metric": significance,
                "Live AEGIS Metrics": live_value,
                "How the Value is Derived / Calculated": _persona_metric_derivation(metric, source_variable),
                "From Which Variable the Value is Coming": source_variable,
            }
        )

    def render_persona_matrix(rows):
        st.info(
            "Current build implements the comprehensive persona set requested during review. "
            "For executive rollout, this can be simplified into a lean set: Executive / AI Application Owner, "
            "AI Platform Lead / AI Manager, AI Agent Onboarder / Developer, Risk / Governance / Model Risk Reviewer, "
            "and DORA / Test Lead. The detailed persona tabs below can be merged without losing the underlying AEGIS metrics."
        )
        grouped = []
        for row in rows:
            if not grouped or grouped[-1]["persona"] != row["Persona"]:
                grouped.append({"persona": row["Persona"], "rows": []})
            grouped[-1]["rows"].append(row)

        html_parts = [
            """
            <style>
              .persona-matrix {
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
                font-size: 0.92rem;
              }
              .persona-matrix th {
                background: #eef4ff;
                color: #1f2937;
                border: 1px solid #cbd5e1;
                padding: 10px 12px;
                text-align: left;
                vertical-align: top;
                font-weight: 700;
              }
              .persona-matrix td {
                border: 1px solid #d9e2ef;
                padding: 10px 12px;
                vertical-align: top;
                color: #111827;
                line-height: 1.35;
                background: #ffffff;
                overflow-wrap: anywhere;
              }
              .persona-matrix .persona-cell {
                background: #f8fbff;
                font-weight: 700;
                color: #0f172a;
                width: 18%;
              }
              .persona-matrix .metric-cell {
                width: 18%;
                font-weight: 600;
              }
              .persona-matrix .value-cell {
                width: 20%;
                color: #0f3b73;
                font-weight: 650;
              }
              .persona-matrix .source-cell {
                width: 22%;
                color: #475569;
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                font-size: 0.84rem;
              }
            </style>
            <table class="persona-matrix">
              <thead>
                <tr>
                  <th>Persona</th>
                  <th>What They Track</th>
                  <th>Significance of the Metric</th>
                  <th>Live AEGIS Metrics</th>
                  <th>How the Value is Derived / Calculated</th>
                  <th>From Which Variable the Value is Coming</th>
                </tr>
              </thead>
              <tbody>
            """
        ]
        for group in grouped:
            group_rows = group["rows"]
            for index, row in enumerate(group_rows):
                html_parts.append("<tr>")
                if index == 0:
                    html_parts.append(
                        f'<td class="persona-cell" rowspan="{len(group_rows)}">{html.escape(str(group["persona"]))}</td>'
                    )
                html_parts.extend(
                    [
                        f'<td class="metric-cell">{html.escape(str(row["What They Track"]))}</td>',
                        f'<td>{html.escape(str(row["Significance of the Metric"]))}</td>',
                        f'<td class="value-cell">{html.escape(str(row["Live AEGIS Metrics"]))}</td>',
                        f'<td>{html.escape(str(row["How the Value is Derived / Calculated"]))}</td>',
                        f'<td class="source-cell">{html.escape(str(row["From Which Variable the Value is Coming"]))}</td>',
                    ]
                )
                html_parts.append("</tr>")
        html_parts.append("</tbody></table>")
        st.markdown("".join(html_parts), unsafe_allow_html=True)

    def render_persona_metric_drilldowns(selected_persona, metric_rows):
        persona_drilldown_sets = {
            "AI Application Owner / Executive": {"runtime", "evidence", "policy", "audit", "cost"},
            "AI Platform Lead / AI Manager": {"agents", "policy", "owasp", "audit", "runtime", "cache"},
            "AI Administrator": {"agents", "policy", "audit", "runtime", "cache"},
            "AI Developer / Agent Builder": {"agents", "onboarding", "owasp", "evidence", "runtime", "cost"},
            "DORA Lead": {"agents", "policy", "owasp", "audit", "runtime", "cost"},
            "DORA Member / Test Lead": {"evidence", "policy", "owasp", "audit", "runtime"},
            "Model Risk / AI Assurance": {"evidence", "policy", "owasp", "audit", "runtime"},
            "Audit / Regulator Viewer": {"evidence", "policy", "audit", "onboarding", "runtime"},
            "AI Product / Application Owner": {"runtime", "evidence", "policy", "audit", "cache", "cost"},
            "SRE / Platform Operations": {"agents", "runtime", "audit", "cache", "cost"},
        }
        enabled_drilldowns = persona_drilldown_sets.get(
            selected_persona,
            {"agents", "evidence", "policy", "owasp", "audit", "runtime"},
        )

        def show_drilldown(name):
            return name in enabled_drilldowns

        st.markdown(f"#### {selected_persona} Metric Drilldowns")
        st.caption(
            "These drilldowns are filtered to the source result sets that support the metrics shown in this persona tab."
        )

        def _render_audit_package_health_drilldown():
            audit_ledger_counts = _audit_ledger_table_counts(ledger, result.get("runtime_id"))
            audit_consistency_rows = _canonical_consistency_audit_rows(result)
            audit_mismatch_rows = [row for row in audit_consistency_rows if row.get("Status") == "MISMATCH"]

            render_compact_status_grid([
                ("Artifact Package", export_status),
                ("Audit Ledger", ledger_status),
                ("Invariant Tests", f"{tests.get('passed_count', 0)}/{tests.get('total', 0)} passed" if tests else "-"),
                ("Canonical Consistency", "PASS" if not audit_mismatch_rows else f"{len(audit_mismatch_rows)} mismatch(es)"),
                ("Agent Records", agent_counts.get("executed", 0)),
                ("Evidence Records", evidence_count),
                ("Artifact Files", len(artifact_files)),
                ("Ledger Location", ledger.get("path") or "Generated after package export"),
            ])

            render_story_strip([
                {
                    "eyebrow": "STEP 1",
                    "title": "Runtime Captured",
                    "detail": f"{agent_counts.get('executed', 0)}/{agent_counts.get('total', 0)} agents recorded",
                    "state": "pass" if agent_counts.get("executed", 0) else "review",
                },
                {
                    "eyebrow": "STEP 2",
                    "title": "Canonical Reconciled",
                    "detail": "PASS" if not audit_mismatch_rows else f"{len(audit_mismatch_rows)} mismatch(es)",
                    "state": "pass" if not audit_mismatch_rows else "review",
                },
                {
                    "eyebrow": "STEP 3",
                    "title": "Evidence Retained",
                    "detail": f"{evidence_count} evidence rows",
                    "state": "pass" if evidence_count else "review",
                },
                {
                    "eyebrow": "STEP 4",
                    "title": "Ledger Stored",
                    "detail": ledger_status,
                    "state": "pass" if ledger_status == "SAVED" else "review",
                },
                {
                    "eyebrow": "STEP 5",
                    "title": "Package Exported",
                    "detail": export_status,
                    "state": "pass" if export_status == "SAVED" else "review",
                },
            ])

            st.subheader("Audit Ledger Map")
            st.caption("These are the durable tables maintained for audit review and operational replay.")
            if not audit_ledger_counts:
                st.info("Ledger row counts appear after the audit package is generated or refreshed for this run.")
            render_table("Audit Tables", [
                {
                    "Table": "audit_run",
                    "Purpose": "One row per investigation with customer, query, recommendation, scores, and package location.",
                    "Rows": audit_ledger_counts.get("audit_run", "-"),
                },
                {
                    "Table": "audit_agent_execution",
                    "Purpose": "Agent execution status, order, phase, tool, and execution time.",
                    "Rows": audit_ledger_counts.get("audit_agent_execution", "-"),
                },
                {
                    "Table": "audit_evidence",
                    "Purpose": "Evidence chunk source, trust score, rank, and content hash for traceability.",
                    "Rows": audit_ledger_counts.get("audit_evidence", "-"),
                },
                {
                    "Table": "audit_decision",
                    "Purpose": "Final recommendation, risk level, governance status, HITL requirement, and rationale.",
                    "Rows": audit_ledger_counts.get("audit_decision", "-"),
                },
                {
                    "Table": "audit_consistency_check",
                    "Purpose": "Canonical value checks across tabs, summaries, exports, and runtime objects.",
                    "Rows": audit_ledger_counts.get("audit_consistency_check", "-"),
                },
                {
                    "Table": "audit_cache_event",
                    "Purpose": "Cache layer lookup, hit/miss, TTL, and interpretation for reuse audits.",
                    "Rows": audit_ledger_counts.get("audit_cache_event", "-"),
                },
                {
                    "Table": "audit_artifact",
                    "Purpose": "Generated report, JSON, CSV, image, and ZIP file inventory with hashes.",
                    "Rows": audit_ledger_counts.get("audit_artifact", "-"),
                },
            ])

            if audit_mismatch_rows:
                st.warning("Canonical mismatches require review before this run is presented externally.")
                render_table("Canonical Consistency Exceptions", audit_mismatch_rows)
            else:
                st.success("Canonical recommendation, risk, compliance, trust, and confidence values are consistent across audited objects.")

            if artifact_files:
                st.subheader("Artifact Inventory")
                render_table("Saved Audit Assets", artifact_files[:30])
            else:
                st.info("Artifact inventory is populated after the audit package is generated.")

        def _agent_execution_parameter_rows():
            trace_rows = _normalized_agent_trace(result)
            token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))
            cost_payload = _safe_dict(result.get("cost_metrics") or result.get("cost") or {})
            llm_cost_rows = list(_llm_trace_rows_with_cost(result, token, cost_payload))
            llm_by_agent = {}
            for llm_row in llm_cost_rows:
                key = _agent_lineage_key(llm_row.get("Agent") or llm_row.get("agent") or llm_row.get("agent_name") or "")
                if key:
                    llm_by_agent[key] = llm_row
            agent_rows = []
            for index, row in enumerate(trace_rows, start=1):
                agent_name = row.get("agent") or row.get("agent_name") or row.get("name") or f"Agent {index}"
                llm_row = llm_by_agent.get(_agent_lineage_key(agent_name), {})
                duration_ms = int(_numeric_score(row.get("duration_ms"), 0))
                prompt_tokens = int(_numeric_score(row.get("prompt_tokens", row.get("input_tokens", llm_row.get("Input Tokens"))), 0))
                completion_tokens = int(_numeric_score(row.get("completion_tokens", row.get("output_tokens", llm_row.get("Output Tokens"))), 0))
                total_tokens = int(_numeric_score(row.get("total_tokens", row.get("tokens", llm_row.get("Total Tokens"))), prompt_tokens + completion_tokens))
                row_cost = _numeric_score(row.get("estimated_cost_usd", row.get("cost_usd")), 0)
                llm_cost = _numeric_score(llm_row.get("Estimated Cost (USD)"), 0)
                if row_cost > 0:
                    agent_cost = round(row_cost, 6)
                    cost_status = "ACTUAL"
                    cost_source = "agent_trace.estimated_cost_usd/cost_usd"
                elif llm_cost > 0 and total_tokens > 0:
                    agent_cost = round(llm_cost, 6)
                    cost_status = "ACTUAL_TOKEN_DERIVED"
                    cost_source = "llm_trace.Estimated Cost (USD)"
                else:
                    agent_cost = "-"
                    cost_status = "NOT_ATTRIBUTED"
                    cost_source = "No per-agent cost telemetry for this agent"
                agent_rows.append(
                    {
                        "#": index,
                        "Agent Name": _canonical_agent_name(agent_name),
                        "Agent Type": row.get("Agent Type") or row.get("agent_type") or _agent_ownership(agent_name, row.get("phase", "")),
                        "Phase": row.get("phase") or "-",
                        "Status": row.get("status") or "-",
                        "Start Time": row.get("start_time") or row.get("started_at") or "-",
                        "End Time": row.get("end_time") or row.get("ended_at") or "-",
                        "Event Time": row.get("timestamp") or row.get("event_time") or "-",
                        "Duration": _format_agent_latency(duration_ms),
                        "Duration (ms)": duration_ms,
                        "Provider": llm_row.get("Provider", row.get("provider", "-")),
                        "Model": llm_row.get("Model", row.get("model", "-")),
                        "Prompt Tokens": prompt_tokens if prompt_tokens else "-",
                        "Completion Tokens": completion_tokens if completion_tokens else "-",
                        "Total Tokens": total_tokens if total_tokens else "-",
                        "Actual Agent Cost (USD)": agent_cost,
                        "Cost Attribution Status": cost_status,
                        "Cost Source Variable": cost_source,
                        "Trust Score": "-" if _is_unknown_value(row.get("trust_score")) else row.get("trust_score"),
                        "Confidence": "-" if _is_unknown_value(row.get("confidence")) else row.get("confidence"),
                        "Retry Count": row.get("retry_count", row.get("retries", 0)),
                        "Max Retries": row.get("max_retries", "-"),
                        "Tool": row.get("tool") or row.get("tool_name") or "-",
                        "Evidence IDs": row.get("evidence_ids", row.get("evidence_id", "-")),
                        "Receives From": row.get("Receives From") or row.get("previous_agent") or "-",
                        "Passes To": row.get("Passes To") or row.get("next_agents") or "-",
                        "Canonical Object": "agent_trace, llm_trace, token_metrics, cost_metrics",
                    }
                )
            return agent_rows

        if selected_persona == "AI Platform Lead / AI Manager":
            def _platform_metric_rows(metric_row):
                metric_name = str(metric_row.get("Metric") or "")
                metric_text = metric_name.casefold()
                common = {
                    "Persona Metric": metric_name,
                    "Metric Value Shown": metric_row.get("Live Runtime Value"),
                    "How Derived / Calculated": metric_row.get("How Derived / Calculated"),
                    "Source Variable": metric_row.get("Source Variable"),
                }
                if "agent execution coverage" in metric_text:
                    return _agent_execution_parameter_rows()
                if "policy exceptions" in metric_text:
                    exception_rows = [
                        {
                            "Policy Exception To Highlight": row.get("Exception"),
                            "Status": row.get("Status"),
                            "Severity": row.get("Severity"),
                            "Decision Impact": release_route_label,
                            "Exact Issue": row.get("Exact Issue") or row.get("Why It Is An Exception"),
                            "Why This Is The Exception": row.get("Why It Is An Exception"),
                            "Platform Lead Action": "Fix policy telemetry if unnamed, or review the named failed control before scaling this agent pattern.",
                            "Canonical Object": row.get("Source Variable"),
                        }
                        for row in named_policy_exceptions
                    ]
                    if not exception_rows:
                        exception_rows = [
                            {
                                "Policy Exception To Highlight": "No active policy exception",
                                "Status": "PASS",
                                "Severity": "LOW",
                                "Decision Impact": release_route_label,
                                "Exact Issue": "No failed policy control is currently reported by policy_as_code.",
                                "Why This Is The Exception": "policy_as_code did not report failed or critical controls.",
                                "Platform Lead Action": "No policy action required for this run.",
                                "Canonical Object": "policy_as_code.failed_count, policy_as_code.critical_failed_count",
                            }
                        ]
                    exception_rows.append(
                        {
                            "Policy Exception To Highlight": "Governance rationale",
                            "Status": "DECISION",
                            "Severity": "Decision",
                            "Decision Impact": release_route_label,
                            "Exact Issue": exact_policy_issue if failed_policy or critical_failed else "No policy exception affects this release route.",
                            "Why This Is The Exception": release_assessment["rationale"],
                            "Platform Lead Action": "Use this as the explainability narrative for release, review, retry, or block.",
                            "Canonical Object": "release_assessment.rationale",
                        }
                    )
                    return exception_rows
                if "model quality trend" in metric_text:
                    return [
                        {"Quality Parameter": "Trust Score", "Live Value": quality.get("trust_score", "-"), "Threshold / Policy": ">= 70 platform baseline", "Performance": "PASS" if _numeric_score(quality.get("trust_score"), 0) >= 70 else "REVIEW", "Runtime Meaning": "AEGIS trust score after governance/evaluation checks.", "Platform Lead Action": "Track by app/agent pattern and investigate recurring low trust.", "Canonical Object": "quality.trust_score"},
                        {"Quality Parameter": "Confidence Score", "Live Value": quality.get("confidence", "-"), "Threshold / Policy": ">= 70 platform baseline", "Performance": "REVIEW" if _numeric_score(quality.get("confidence"), 0) < 70 else "PASS", "Runtime Meaning": "Model confidence for the produced recommendation.", "Platform Lead Action": "Improve prompt, evidence retrieval, or model selection if confidence stays low.", "Canonical Object": "quality.confidence"},
                        {"Quality Parameter": "Grounding Score", "Live Value": grounding_signal, "Threshold / Policy": ">= 80 evidence-backed baseline", "Performance": "PASS" if _numeric_score(grounding_signal, 0) >= 80 else "REVIEW", "Runtime Meaning": "Whether the answer is supported by retrieved/canonical evidence.", "Platform Lead Action": "Review RAG retrieval and grounding evaluator when this drops.", "Canonical Object": "quality.groundedness, quality.grounding_score"},
                        {"Quality Parameter": "Context Coverage", "Live Value": context_utilization_signal, "Threshold / Policy": ">= 80 context use baseline", "Performance": "PASS" if _numeric_score(context_utilization_signal, 0) >= 80 else "REVIEW", "Runtime Meaning": "Whether retrieved context was sufficiently used in reasoning.", "Platform Lead Action": "Tune chunking, retrieval mode, context packing, or prompt instructions.", "Canonical Object": "quality.coverage"},
                        {"Quality Parameter": "Evidence Objects", "Live Value": evidence_count, "Threshold / Policy": "> 0 for governed decisioning", "Performance": "PASS" if evidence_count else "REVIEW", "Runtime Meaning": "Evidence objects available to support the model quality score.", "Platform Lead Action": "Review evidence onboarding/retrieval if no evidence is present.", "Canonical Object": "evidence_pack, retrieved_chunks"},
                    ]
                if "owasp" in metric_text:
                    return [
                        {
                            "OWASP ID": row.get("OWASP IDs", "-"),
                            "OWASP AI Control": row.get("OWASP Control", "-"),
                            "Runtime Status": row.get("Status", "-"),
                            "Score": row.get("Score", "-"),
                            "Performance": "PASS" if str(row.get("Status", "")).upper() == "PASS" else ("REVIEW" if str(row.get("Status", "")).upper() in {"REVIEW", "WARN", "WARNING", "REFERENCE", "-"} else "FAIL"),
                            "Findings / Evidence": row.get("Reason / Findings", "-"),
                            "Platform Lead Action": "Scale with monitoring" if str(row.get("Status", "")).upper() == "PASS" else "Review control evidence before scaling this agent pattern",
                            "Source Variable": "security_analysis.checks, aegis_owasp_control_catalog",
                        }
                        for row in owasp_control_rows[:10]
                    ]
                if "audit package health" in metric_text:
                    audit_rows = [
                        {"Audit Object": "Artifact Package", "Runtime Value": export.get("status", "-"), "Path / Count": export.get("directory", "-"), "Performance": "PASS" if export.get("status") == "SAVED" else "REVIEW", "What It Proves": "The governed run has a saved audit package.", "Canonical Object": "artifact_export.status, artifact_export.directory"},
                        {"Audit Object": "Audit Ledger", "Runtime Value": ledger.get("status", "-"), "Path / Count": ledger.get("path", "-"), "Performance": "PASS" if ledger.get("status") else "REVIEW", "What It Proves": "Runtime activity can be replayed from ledger tables.", "Canonical Object": "artifact_export.audit_ledger.status, artifact_export.audit_ledger.path"},
                        {"Audit Object": "Invariant Tests", "Runtime Value": invariant_value, "Path / Count": f"{tests.get('passed_count', 0)}/{tests.get('total', 0)}" if tests else "-", "Performance": "PASS" if tests and tests.get("passed_count") == tests.get("total") else "REVIEW", "What It Proves": "Saved runtime invariants passed after export.", "Canonical Object": "artifact_export.test_results"},
                        {"Audit Object": "Canonical Consistency", "Runtime Value": "PASS" if mismatch_count == 0 else f"{mismatch_count} mismatch(es)", "Path / Count": mismatch_count, "Performance": "PASS" if mismatch_count == 0 else "REVIEW", "What It Proves": "Displayed values match canonical runtime authority.", "Canonical Object": "canonical consistency audit"},
                    ]
                    audit_rows.append(
                        {
                            "Audit Object": "Artifact Inventory",
                            "Runtime Value": len(artifact_files),
                            "Path / Count": "See Saved Audit Assets below",
                            "Performance": "PASS" if artifact_files else "REVIEW",
                            "What It Proves": "The audit package includes the full saved asset inventory.",
                            "Canonical Object": "artifact_export.manifest.files",
                        }
                    )
                    return audit_rows + [
                        {
                            "Audit Object": "Ledger Tables",
                            "Runtime Value": ledger.get("status", "-"),
                            "Path / Count": ", ".join(f"{k}:{v}" for k, v in ledger_counts_for_persona.items()) if ledger_counts_for_persona else "-",
                            "Performance": "PASS" if ledger_counts_for_persona else "REVIEW",
                            "What It Proves": "The durable audit tables are present for replay and inspection.",
                            "Canonical Object": "artifact_export.audit_ledger",
                        },
                    ]
                if "runtime measurability" in metric_text:
                    timeline = result.get("execution_timeline") or result.get("timeline") or []
                    if isinstance(timeline, dict):
                        timeline = list(timeline.values())
                    if isinstance(timeline, list) and timeline:
                        return [
                            {
                                "#": index,
                                "Stage / Phase": item.get("phase") or item.get("stage") or item.get("name") or f"Stage {index}",
                                "Status": item.get("status", "-"),
                                "Start Time": item.get("start_time", "-"),
                                "End Time": item.get("end_time", "-"),
                                "Duration": _format_agent_latency(int(_numeric_score(item.get("duration_ms"), 0))),
                                "Duration (ms)": int(_numeric_score(item.get("duration_ms"), 0)),
                                "Event Time": item.get("timestamp") or item.get("event_time") or "-",
                                "Telemetry Present": "YES" if item.get("duration_ms") or item.get("timestamp") or item.get("start_time") else "PARTIAL",
                                "Canonical Object": "execution_timeline",
                            }
                            for index, item in enumerate(timeline, start=1)
                            if isinstance(item, dict)
                        ]
                    return [
                        {"Measurability Parameter": "Execution Stages", "Live Value": agent_counts.get("execution_stages", 0), "Telemetry Required": "stage / phase", "Performance": "OBSERVED" if agent_counts.get("execution_stages", 0) else "REFERENCE", "Canonical Object": "agent_counts.execution_stages"},
                        {"Measurability Parameter": "Observed Handoffs", "Live Value": agent_counts.get("observed_handoffs", 0), "Telemetry Required": "from_agent / to_agent", "Performance": "OBSERVED" if agent_counts.get("observed_handoffs", 0) else "REFERENCE", "Canonical Object": "agent_counts.observed_handoffs"},
                        {"Measurability Parameter": "Average Agent Time", "Live Value": avg_agent_time, "Telemetry Required": "duration_ms", "Performance": "OBSERVED" if agent_counts.get("avg_latency_ms") else "REFERENCE", "Canonical Object": "agent_counts.avg_latency_ms"},
                        {"Measurability Parameter": "Total Execution Time", "Live Value": total_execution_latency, "Telemetry Required": "latency_ms", "Performance": "OBSERVED" if agent_counts.get("latency_ms") else "REFERENCE", "Canonical Object": "agent_counts.latency_ms"},
                    ]
                if "cache reuse" in metric_text:
                    return [
                        {"Cache Parameter": "status", "Live Value": cache_status, "Policy Meaning": "HIT=served from cache; STORED=available for reuse; BYPASSED=not used.", "Performance": "REUSABLE" if cache_status in {"HIT", "STORED"} else "REVIEW", "Operational Use": "Explains whether the platform avoided or stored repeat execution.", "Canonical Object": "cache_lookup.status"},
                        {"Cache Parameter": "cache_hit_ratio", "Live Value": f"{cache_hit_ratio}%", "Policy Meaning": "Higher ratio means repeat executions avoid unnecessary agent work.", "Performance": "BASELINE" if _numeric_score(cache_hit_ratio, 0) == 0 else "IMPROVING", "Operational Use": "Measures repeat-run scalability.", "Canonical Object": "cache_lookup.cache_hit_ratio"},
                        {"Cache Parameter": "cache_hits", "Live Value": cache_hits, "Policy Meaning": "Count of served-from-cache runtime results.", "Performance": "OBSERVED", "Operational Use": "Shows realized reuse.", "Canonical Object": "cache_lookup.cache_hits"},
                        {"Cache Parameter": "cache_misses", "Live Value": cache_misses, "Policy Meaning": "Count of fresh executions when cache was unavailable/not matched.", "Performance": "OBSERVED", "Operational Use": "Shows future optimization opportunity.", "Canonical Object": "cache_lookup.cache_misses"},
                        {"Cache Parameter": "entries", "Live Value": cache_entries, "Policy Meaning": "Reusable runtime records currently stored.", "Performance": "STORED" if _numeric_score(cache_entries, 0) > 0 else "EMPTY", "Operational Use": "Shows cache inventory for repeat demos and production acceleration.", "Canonical Object": "cache_lookup.entries"},
                        {"Cache Parameter": "ttl_seconds / freshness", "Live Value": f"TTL: {cache_ttl} | Remaining: {cache_remaining_ttl} | Age: {cache_age}", "Policy Meaning": "Prevents stale governed outcomes from being reused indefinitely.", "Performance": "CONTROLLED" if cache_ttl != "-" else "NOT CONFIGURED", "Operational Use": "Supports auditable controlled reuse.", "Canonical Object": "cache_lookup.ttl_seconds, cache_lookup.remaining_ttl_seconds, cache_lookup.age_seconds"},
                    ]
                if "reliability defect load" in metric_text:
                    defect_rows = []
                    defect_rows.extend(
                        {
                            "Defect Type": "Runtime Agent Defect",
                            "Object Name": _canonical_agent_name(row.get("agent") or row.get("agent_name") or row.get("name") or f"Agent {index}"),
                            "Status / Signal": row.get("status", "-"),
                            "Severity": "REVIEW",
                            "Impact": "Agent did not complete cleanly.",
                            "Recommended Action": "Review agent trace, tool call, retry reason, and handoff source.",
                            "Canonical Object": "agent_trace.status",
                        }
                        for index, row in enumerate(_normalized_agent_trace(result), start=1)
                        if str(row.get("status", "")).upper() in {"FAILED", "FAIL", "ERROR", "CRITICAL"}
                    )
                    defect_rows.extend(
                        {
                            "Defect Type": "Policy Exception",
                            "Object Name": row.get("Exception"),
                            "Status / Signal": row.get("Status"),
                            "Severity": row.get("Severity"),
                            "Impact": row.get("Why It Is An Exception"),
                            "Recommended Action": "Fix policy telemetry if unnamed, or review the named failed control.",
                            "Canonical Object": row.get("Source Variable"),
                        }
                        for row in named_policy_exceptions
                    )
                    defect_rows.extend(
                        {
                            "Defect Type": "OWASP Security Review",
                            "Object Name": row.get("OWASP Control", "-"),
                            "Status / Signal": row.get("Status", "-"),
                            "Severity": "FAIL" if str(row.get("Status", "")).upper() in {"FAILED", "FAIL", "ERROR", "CRITICAL", "BLOCK"} else "REVIEW",
                            "Impact": row.get("Reason / Findings", "-"),
                            "Recommended Action": "Review security evidence before scaling this agent pattern.",
                            "Canonical Object": "security_analysis.checks",
                        }
                        for row in owasp_control_rows
                        if str(row.get("Status", "")).upper() in {"REVIEW", "WARN", "WARNING", "FAILED", "FAIL", "ERROR", "CRITICAL", "BLOCK"}
                    )
                    if total_retry_count:
                        defect_rows.append({"Defect Type": "Retry Pressure", "Object Name": "Runtime retry count", "Status / Signal": total_retry_count, "Severity": "REVIEW", "Impact": "Retries show rework or recovery behavior.", "Recommended Action": "Inspect retry_count, max_retries, and retry_reason per agent.", "Canonical Object": "agent_trace.retry_count"})
                    return defect_rows or [{"Defect Type": "No reliability defect detected", "Object Name": "Current run", "Status / Signal": "PASS", "Severity": "LOW", "Impact": "No failed agents, policy exception details, OWASP failures, or retry pressure detected.", "Recommended Action": "Continue monitoring across runs.", "Canonical Object": "agent_trace, policy_as_code, security_analysis"}]
                return [{**common, "Drilldown Signal": "Runtime Summary", "Live Value": metric_row.get("Live Runtime Value"), "Why Platform Lead Cares": metric_row.get("Significance")}]

            for metric_row in metric_rows:
                with st.expander(str(metric_row.get("Metric") or "Metric Drilldown")):
                    if str(metric_row.get("Metric") or "").casefold() == "audit package health":
                        _render_audit_package_health_drilldown()
                    else:
                        render_table(
                            f"{metric_row.get('Metric')} Drilldown",
                            _platform_metric_rows(metric_row),
                        )
            return

        def _persona_specific_metric_rows(metric_row):
            metric_name = str(metric_row.get("Metric") or "Metric")
            metric_text = metric_name.casefold()
            base = {
                "Persona Metric": metric_name,
                "Live Runtime Value": metric_row.get("Live Runtime Value"),
                "How Derived / Calculated": metric_row.get("How Derived / Calculated"),
                "Source Variable": metric_row.get("Source Variable"),
            }
            if selected_persona == "AI Agent Onboarder" and "canonical signal coverage" in metric_text:
                return canonical_coverage_rows
            if selected_persona == "AI Agent Onboarder" and "runtime contract source" in metric_text:
                contract_rows = _agent_runtime_contract_rows(trace_for_dora)
                health_rows = [
                    {
                        "Runtime Contract Area": "Telemetry Source",
                        "Live Value": agent_counts.get("source", "-"),
                        "Status / Notes": "Shows whether AEGIS read graph telemetry, normalized trace, or fallback runtime data.",
                        "Onboarder Action": "Use graph/trace source as preferred onboarding evidence.",
                        "Source Variable": "agent_counts.source",
                    },
                    {
                        "Runtime Contract Area": "Agents Executed",
                        "Live Value": f"{executed_agents}/{agent_counts.get('total', 0)}",
                        "Status / Notes": "Shows current execution coverage against the registered/planned agent count.",
                        "Onboarder Action": "Check skipped/planned agents and decide whether they should emit runtime events.",
                        "Source Variable": "agent_counts.executed, agent_counts.total",
                    },
                    {
                        "Runtime Contract Area": "Agents Not Running Properly",
                        "Live Value": failed_agents,
                        "Status / Notes": "Failed/error agents require correction before onboarding sign-off." if failed_agents else "No failed/error agents observed.",
                        "Onboarder Action": "Inspect failed agent rows below for status, retry policy, and handoff.",
                        "Source Variable": "agent_counts.failed, agent_trace.status",
                    },
                ]
                return health_rows + contract_rows
            if any(term in metric_text for term in ["agent", "handoff", "success rate", "failure", "retry", "collaboration", "token", "cost attribution"]):
                return _agent_execution_parameter_rows()
            if any(term in metric_text for term in ["policy", "governance", "hitl", "release", "readiness", "exception", "compliance", "route", "rationale", "override", "rework"]):
                rows = [
                    {
                        "Decision Parameter": "Release Route",
                        "Live Value": release_route_label,
                        "Exact Issue": exact_policy_issue if failed_policy or critical_failed else "Release route is consistent with current policy counts.",
                        "Decision Impact": "Release, retry, HITL review, or block decision is taken from this governed route.",
                        "Recommended Action": "Use this as the operating decision for this persona.",
                        "Source Variable": "release_assessment.release_route, release_assessment.rationale",
                    },
                    {
                        "Decision Parameter": "Policy Exceptions",
                        "Live Value": policy_exception_label,
                        "Exact Issue": exact_policy_issue if failed_policy or critical_failed else "No active policy exception reported.",
                        "Decision Impact": "Highlights whether policy telemetry or release narrative needs correction.",
                        "Recommended Action": "If failed count is non-zero, require named control, severity, rationale, and remediation.",
                        "Source Variable": "policy_as_code.failed_count, policy_as_code.critical_failed_count",
                    },
                    {
                        "Decision Parameter": "Human Review Required",
                        "Live Value": "YES" if release_assessment["review_required"] else "NO",
                        "Exact Issue": release_assessment["rationale"],
                        "Decision Impact": "Clarifies whether the result can proceed without HITL.",
                        "Recommended Action": "Approved cases should release; review cases should route to HITL with rationale.",
                        "Source Variable": "release_assessment.review_required",
                    },
                ]
                rows.extend(
                    {
                        "Decision Parameter": row.get("Exception"),
                        "Live Value": row.get("Status"),
                        "Exact Issue": row.get("Exact Issue") or row.get("Why It Is An Exception"),
                        "Decision Impact": release_route_label,
                        "Recommended Action": "Correct policy telemetry or review the named failed control before scaling.",
                        "Source Variable": row.get("Source Variable"),
                    }
                    for row in named_policy_exceptions
                )
                return rows
            if any(term in metric_text for term in ["owasp", "security", "hallucination", "misinformation"]):
                return [
                    {
                        "OWASP ID": row.get("OWASP IDs", "-"),
                        "Control": row.get("OWASP Control", "-"),
                        "Runtime Status": row.get("Status", "-"),
                        "Score": row.get("Score", "-"),
                        "Exact Issue": row.get("Reason / Findings", "-"),
                        "Recommended Action": "PASS can be monitored; REVIEW/FAIL needs security evidence review.",
                        "Source Variable": "security_analysis.checks, aegis_owasp_control_catalog",
                    }
                    for row in owasp_control_rows[:10]
                ]
            if any(term in metric_text for term in ["audit", "ledger", "artifact", "invariant", "consistency"]):
                return [
                    {"Audit Area": "Artifact Package", "Live Value": export.get("status", "-"), "Exact Issue": "Package saved." if export.get("status") == "SAVED" else "Audit package is not saved for this run.", "Recommended Action": "Regenerate/export artifacts if not saved.", "Source Variable": "artifact_export.status"},
                    {"Audit Area": "Audit Ledger", "Live Value": ledger.get("status", "-"), "Exact Issue": f"Ledger tables available: {len(ledger_counts_for_persona)}", "Recommended Action": "Use ledger tables for replay and audit review.", "Source Variable": "artifact_export.audit_ledger.status"},
                    {"Audit Area": "Invariant Tests", "Live Value": invariant_value, "Exact Issue": "Saved runtime checks passed." if "passed" in str(invariant_value).casefold() else "Runtime invariant needs review or package refresh.", "Recommended Action": "Review failed invariant checks before presentation.", "Source Variable": "artifact_export.test_results"},
                    {"Audit Area": "Canonical Consistency", "Live Value": consistency_status, "Exact Issue": "Displayed values match canonical authority." if mismatch_count == 0 else f"{mismatch_count} displayed/canonical mismatch(es) exist.", "Recommended Action": "Resolve mismatches and regenerate audit package.", "Source Variable": "canonical consistency audit"},
                    {"Audit Area": "Artifact Inventory", "Live Value": len(artifact_files), "Exact Issue": "Saved artifact inventory is available." if artifact_files else "No artifact inventory found.", "Recommended Action": "Generate report/JSON/CSV/ZIP assets for audit review.", "Source Variable": "artifact_export.manifest.files"},
                ]
            if any(term in metric_text for term in ["cache", "reuse", "scalability", "repeat"]):
                return [
                    {"Cache Parameter": "Status", "Live Value": cache_status, "Exact Issue": _cache_miss_reason(cache, result.get("query_cache", {})), "Recommended Action": "Use HIT/STORED for repeat demos; inspect reason for misses.", "Source Variable": "cache_lookup.status"},
                    {"Cache Parameter": "Hit Ratio", "Live Value": f"{cache_hit_ratio}%", "Exact Issue": "Shows realized reuse for repeat workloads.", "Recommended Action": "Improve cache key strategy if repeat runs are misses.", "Source Variable": "cache_lookup.cache_hit_ratio"},
                    {"Cache Parameter": "Hits / Misses", "Live Value": f"{cache_hits}/{cache_misses}", "Exact Issue": "Separates cache reuse from fresh execution.", "Recommended Action": "Track across runs for scalability trend.", "Source Variable": "cache_lookup.cache_hits, cache_lookup.cache_misses"},
                    {"Cache Parameter": "TTL / Freshness", "Live Value": f"TTL: {cache_ttl} | Remaining: {cache_remaining_ttl} | Age: {cache_age}", "Exact Issue": "Controls whether cached governed decisions are still fresh.", "Recommended Action": "Tune TTL by risk and application freshness need.", "Source Variable": "cache_lookup.ttl_seconds, remaining_ttl_seconds, age_seconds"},
                ]
            if any(term in metric_text for term in ["evidence", "grounding", "rag", "context"]):
                return [
                    {"Evidence Parameter": "Evidence Count", "Live Value": evidence_count, "Exact Issue": "Evidence is available for grounding." if evidence_count else "Evidence object count is zero for this view.", "Recommended Action": "Review retrieval/chunking if evidence is expected.", "Source Variable": "evidence_pack or retrieved_chunks"},
                    {"Evidence Parameter": "Grounding Signal", "Live Value": grounding_signal, "Exact Issue": "Indicates whether response is evidence-backed.", "Recommended Action": "Tune RAG/evaluator if below baseline.", "Source Variable": "quality.groundedness, quality.grounding_score"},
                    {"Evidence Parameter": "Context Utilization", "Live Value": context_utilization_signal, "Exact Issue": "Shows whether retrieved context was used by response.", "Recommended Action": "Tune prompt/context packer if low.", "Source Variable": "quality.coverage"},
                ]
            if any(term in metric_text for term in ["onboarding", "contract", "canonical", "mandatory"]):
                return [
                    {"Contract Parameter": "Contract Status", "Live Value": onboarding_contract_status, "Exact Issue": "Telemetry contract is available." if onboarding_total else "Telemetry contract fields are not loaded.", "Recommended Action": "Onboard required canonical objects before certification.", "Source Variable": "AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx"},
                    {"Contract Parameter": "Mandatory Parameters", "Live Value": onboarding_mandatory, "Exact Issue": "Required fields needed for governance/audit ingestion.", "Recommended Action": "Ensure local/server agents emit all mandatory fields.", "Source Variable": "Telemetry Contract.Required = Mandatory"},
                    {"Contract Parameter": "Total Parameters", "Live Value": onboarding_total, "Exact Issue": "Full canonical object inventory for onboarding.", "Recommended Action": "Use this as onboarding checklist.", "Source Variable": "Telemetry Contract row count"},
                ]
            if any(term in metric_text for term in ["runtime", "completion", "lead-time", "sla", "task", "expected-behavior", "maturity", "measurability"]):
                return [
                    {"Runtime Parameter": "Runtime Status", "Live Value": runtime_status, "Exact Issue": "Run completed." if str(runtime_status).upper() == "COMPLETED" else "Run is not completed.", "Recommended Action": "Investigate timeline/agent trace when not completed.", "Source Variable": "result.runtime_status or result.status"},
                    {"Runtime Parameter": "Total Execution Time", "Live Value": total_execution_latency, "Exact Issue": "Current run duration for SLA/lead-time proxy.", "Recommended Action": "Use slowest agents for optimization.", "Source Variable": "agent_counts.latency_ms"},
                    {"Runtime Parameter": "Observed Handoffs", "Live Value": agent_counts.get("observed_handoffs", 0), "Exact Issue": "Shows runtime traversal between agents.", "Recommended Action": "Review handoff configuration if expected traversal differs.", "Source Variable": "agent_counts.observed_handoffs"},
                    {"Runtime Parameter": "Expected Behavior", "Live Value": expected_behavior, "Exact Issue": "Combines completion, failed agents, policy exceptions, and release route.", "Recommended Action": "Treat REVIEW as operating follow-up.", "Source Variable": "runtime_status, agent_counts.failed, policy_as_code.failed_count, release_assessment.release_allowed"},
                ]
            return [{**base, "Exact Issue": "Metric is derived from the listed live runtime source variable.", "Recommended Action": "Use the source variable to inspect the underlying runtime object."}]

        for metric_row in metric_rows:
            metric_name = str(metric_row.get("Metric") or "Metric Drilldown")
            with st.expander(metric_name):
                if "audit" in metric_name.casefold() and selected_persona in {"Audit / Regulator Viewer", "AI Administrator", "DORA Member / Test Lead"}:
                    _render_audit_package_health_drilldown()
                elif selected_persona == "AI Agent Onboarder" and "canonical signal coverage" in metric_name.casefold():
                    st.caption(
                        "This separates the run-level onboarding summary from the canonical parameter checklist. "
                        "The run can complete while the catalog remains the reference contract for future onboarding."
                    )
                    render_table(
                        "Canonical Signal Summary",
                        [
                            {
                                "Check": "Canonical parameter catalog",
                                "Value": f"{canonical_catalog_count} total parameters | {canonical_required_count} mandatory",
                                "Meaning": "Accepted AEGIS onboarding reference for app/agent telemetry.",
                                "Onboarder Action": "Use as the mandatory checklist for certification.",
                                "Source": "Agent Canonical Parameter Contract",
                            },
                            {
                                "Check": "Current runtime telemetry",
                                "Value": f"{canonical_added_count} observed signals",
                                "Meaning": "Signals visible in this execution snapshot.",
                                "Onboarder Action": "Use the catalog table below to understand expected fields.",
                                "Source": "agent_trace, canonical_runtime_event_contract, canonical_values, canonical_display",
                            },
                            {
                                "Check": "Agent runtime health",
                                "Value": f"Executed: {executed_agents} | Failed: {failed_agents}",
                                "Meaning": "Confirms whether observed agents completed cleanly.",
                                "Onboarder Action": "Review failed/error agents only when the failed count is non-zero.",
                                "Source": "agent_counts.failed, agent_trace.status",
                            },
                        ],
                    )
                    catalog_display_rows = [
                        {
                            "#": row.get("#"),
                            "Canonical Parameter": row.get("Canonical Parameter"),
                            "Required": row.get("Required"),
                            "Data Type": row.get("Data Type"),
                            "Telemetry Status": row.get("Telemetry Status"),
                            "Why Required": row.get("Why Required"),
                            "Source Variable": row.get("Source Variable"),
                        }
                        for row in canonical_coverage_rows
                    ]
                    render_table("Canonical Parameter Checklist", catalog_display_rows)
                else:
                    render_table(f"{metric_name} Drilldown", _persona_specific_metric_rows(metric_row))
        return

        def _supporting_tables_for_metric(metric_name):
            metric_text = str(metric_name or "").casefold()
            tables = []
            if any(term in metric_text for term in ["agent", "handoff", "success rate", "failure", "retry", "measurability", "execution coverage"]):
                tables.append("Agent Execution Set")
            if any(term in metric_text for term in ["cache", "reuse", "scalability", "repeat"]):
                tables.append("Cache Reuse Policy And Runtime Details")
            if any(term in metric_text for term in ["reliability", "defect", "recovery", "exception", "failed", "control failures", "change failure"]):
                tables.append("Reliability Defect Load")
            if any(term in metric_text for term in ["policy", "exception", "governance", "release route", "hitl", "readiness"]):
                tables.append("Policy And Governance Exceptions")
            if any(term in metric_text for term in ["owasp", "security", "hallucination", "misinformation"]):
                tables.append("OWASP AI Top 10 Control Set")
            if any(term in metric_text for term in ["audit", "ledger", "artifact", "invariant", "consistency"]):
                tables.append("Audit Package And Ledger")
            if any(term in metric_text for term in ["evidence", "grounding", "rag", "context"]):
                tables.append("Evidence Set")
            if any(term in metric_text for term in ["onboarding", "contract", "canonical"]):
                tables.append("Onboarding Contract Summary")
            if any(term in metric_text for term in ["cost", "token", "runtime", "latency", "sla", "lead-time", "completion", "task"]):
                tables.append("Runtime Summary")
            return ", ".join(dict.fromkeys(tables)) or "Runtime Summary"

        render_table(
            f"{selected_persona} Metric-To-Drilldown Map",
            [
                {
                    "Persona Metric": row.get("Metric"),
                    "Live Runtime Value": row.get("Live Runtime Value"),
                    "Supporting Drilldown Table(s)": _supporting_tables_for_metric(row.get("Metric")),
                    "Source Variable": row.get("Source Variable"),
                }
                for row in metric_rows
            ],
        )

        if show_drilldown("agents") or show_drilldown("cost"):
            with st.expander("Agent execution, success rate, cost, retries, and handoffs"):
                trace_rows = _normalized_agent_trace(result)
                if trace_rows:
                    token = _safe_dict(result.get("token_metrics") or _safe_get(result, "runtime_telemetry", {}).get("token_metrics"))
                    cost_payload = _safe_dict(result.get("cost_metrics") or result.get("cost") or {})
                    llm_cost_rows = list(_llm_trace_rows_with_cost(result, token, cost_payload))
                    llm_by_agent = {}
                    for llm_row in llm_cost_rows:
                        key = _agent_lineage_key(llm_row.get("Agent") or llm_row.get("agent") or llm_row.get("agent_name") or "")
                        if key:
                            llm_by_agent[key] = llm_row
                    enriched_agent_rows = []
                    for index, row in enumerate(trace_rows, start=1):
                        agent_name = row.get("agent") or row.get("agent_name") or row.get("name") or f"Agent {index}"
                        agent_key = _agent_lineage_key(agent_name)
                        llm_row = llm_by_agent.get(agent_key, {})
                        duration_ms = int(_numeric_score(row.get("duration_ms"), 0))
                        prompt_tokens = int(_numeric_score(
                            row.get("prompt_tokens", row.get("input_tokens", llm_row.get("Input Tokens"))),
                            0,
                        ))
                        completion_tokens = int(_numeric_score(
                            row.get("completion_tokens", row.get("output_tokens", llm_row.get("Output Tokens"))),
                            0,
                        ))
                        total_tokens = int(_numeric_score(
                            row.get("total_tokens", row.get("tokens", llm_row.get("Total Tokens"))),
                            prompt_tokens + completion_tokens,
                        ))
                        row_cost_value = row.get("estimated_cost_usd", row.get("cost_usd"))
                        llm_cost_value = llm_row.get("Estimated Cost (USD)")
                        row_cost = _numeric_score(row_cost_value, 0)
                        llm_cost = _numeric_score(llm_cost_value, 0)
                        if row_cost > 0:
                            agent_cost = row_cost
                            cost_status = "ACTUAL"
                            cost_basis = row.get("cost_basis") or "Agent emitted cost telemetry"
                            cost_source = "agent_trace.estimated_cost_usd/cost_usd"
                        elif llm_cost > 0 and total_tokens > 0:
                            agent_cost = llm_cost
                            cost_status = "ACTUAL_TOKEN_DERIVED"
                            cost_basis = llm_row.get("Cost Basis") or "LLM token telemetry"
                            cost_source = "llm_trace.Estimated Cost (USD)"
                        else:
                            agent_cost = None
                            cost_status = "NOT_ATTRIBUTED"
                            cost_basis = "Per-agent cost telemetry not attributed"
                            cost_source = "No per-agent cost telemetry for this agent"
                        retry_count = row.get("retry_count", row.get("retries", 0))
                        max_retries = row.get("max_retries", "-")
                        enriched_agent_rows.append(
                            {
                                "Agent": _canonical_agent_name(agent_name),
                                "Agent Type": row.get("Agent Type") or row.get("agent_type") or _agent_ownership(agent_name, row.get("phase", "")),
                                "Phase": row.get("phase") or "-",
                                "Status": row.get("status") or "-",
                                "Duration": _format_agent_latency(duration_ms),
                                "Duration (ms)": duration_ms,
                                "Actual Agent Cost (USD)": round(agent_cost, 6) if agent_cost is not None else "-",
                                "Cost Attribution Status": cost_status,
                                "Cost Basis": cost_basis,
                                "Cost Source Variable": cost_source,
                                "Provider": llm_row.get("Provider", row.get("provider", "-")),
                                "Model": llm_row.get("Model", row.get("model", "-")),
                                "Prompt Tokens": prompt_tokens if prompt_tokens else "-",
                                "Completion Tokens": completion_tokens if completion_tokens else "-",
                                "Total Tokens": total_tokens if total_tokens else "-",
                                "Token Source": "agent_trace or llm_trace" if total_tokens else "Not attributed",
                                "Trust": "-" if _is_unknown_value(row.get("trust_score")) else row.get("trust_score"),
                                "Confidence": "-" if _is_unknown_value(row.get("confidence")) else row.get("confidence"),
                                "Retry Count": retry_count,
                                "Max Retries": max_retries,
                                "Evidence IDs": row.get("evidence_ids", row.get("evidence_id", "-")),
                                "Tool": row.get("tool") or row.get("tool_name") or "-",
                                "Receives From": row.get("Receives From") or row.get("previous_agent") or "-",
                                "Passes To": row.get("Passes To") or row.get("next_agents") or "-",
                                "Event Time": row.get("timestamp") or row.get("event_time") or "-",
                                "Source Variable": "agent_trace + llm_trace/token_metrics/cost_metrics",
                            }
                        )
                    st.caption(
                        "Cost is shown only when actual agent-level cost telemetry or LLM token telemetry exists. "
                        "AEGIS does not allocate runtime cost by duration or time share in this drilldown."
                    )
                    render_table(
                        "Agent Execution Set Behind Agent Counts",
                        enriched_agent_rows,
                    )
                else:
                    st.info("Agent-level runtime result set is not available for this run.")

        if show_drilldown("cache"):
            with st.expander("Cache reuse policy and runtime details"):
                render_table(
                    "Cache Reuse Policy And Runtime Details",
                    [
                        {
                            "Cache Metric": "Cache Status",
                            "Live Value": cache_status,
                            "Policy / Interpretation": "HIT means served from cache; STORED means this run is available for reuse; BYPASSED means cache was not used.",
                            "Decision Use": "Platform lead can explain whether the agent estate is scalable for repeat workloads.",
                            "Source Variable": "cache_lookup.status or cache_metrics.status",
                        },
                        {
                            "Cache Metric": "Hit Ratio",
                            "Live Value": f"{cache_hit_ratio}%",
                            "Policy / Interpretation": "Higher hit ratio means repeat investigations are avoiding unnecessary agent execution.",
                            "Decision Use": "Used for scalability, cost reduction, and demo repeatability.",
                            "Source Variable": "cache_lookup.cache_hit_ratio",
                        },
                        {
                            "Cache Metric": "Hits / Misses",
                            "Live Value": f"{cache_hits}/{cache_misses}",
                            "Policy / Interpretation": "Shows observed reuse versus fresh execution.",
                            "Decision Use": "Identifies whether cache policy is actually being exercised.",
                            "Source Variable": "cache_lookup.cache_hits, cache_lookup.cache_misses",
                        },
                        {
                            "Cache Metric": "Entries Stored",
                            "Live Value": cache_entries,
                            "Policy / Interpretation": "Number of reusable runtime records currently available.",
                            "Decision Use": "Indicates whether the platform is building a reusable execution memory.",
                            "Source Variable": "cache_lookup.entries",
                        },
                        {
                            "Cache Metric": "TTL / Freshness",
                            "Live Value": f"TTL: {cache_ttl} | Remaining: {cache_remaining_ttl} | Age: {cache_age}",
                            "Policy / Interpretation": "Freshness controls prevent stale governed outcomes from being reused indefinitely.",
                            "Decision Use": "Supports auditability and controlled repeat-run scalability.",
                            "Source Variable": "cache_lookup.ttl_seconds, remaining_ttl_seconds, age_seconds",
                        },
                    ],
                )

        if selected_persona in {"AI Platform Lead / AI Manager", "DORA Lead", "AI Administrator", "SRE / Platform Operations"}:
            with st.expander("Reliability defect load and recovery signals"):
                render_table(
                    "Reliability Defect Load",
                    [
                        {
                            "Defect Signal": "Failed Agents",
                            "Live Value": failed_agents,
                            "Impact": "Agent runtime failure creates operational debt and reduces autonomous completion reliability.",
                            "Recommended Action": "Open agent execution set and inspect failed/error statuses, retry count, tool, and handoff source.",
                            "Source Variable": "agent_counts.failed, agent_trace.status",
                        },
                        {
                            "Defect Signal": "Policy Exceptions",
                            "Live Value": policy_exception_label,
                            "Impact": "Policy exception means the governed route cannot be explained only by agent success; governance signal must be reviewed.",
                            "Recommended Action": "Open policy/governance exception table and verify control name, severity, rationale, and release impact.",
                            "Source Variable": "policy_as_code.failed_count, policy_as_code.critical_failed_count",
                        },
                        {
                            "Defect Signal": "OWASP Review / Failed Controls",
                            "Live Value": f"Review: {owasp_review_count} | Failed: {owasp_failed_count}",
                            "Impact": "Security review signals can create release friction even when application agents complete successfully.",
                            "Recommended Action": "Open OWASP control set and inspect review/fail findings.",
                            "Source Variable": "security_analysis.checks, failed_controls, review_controls",
                        },
                        {
                            "Defect Signal": "Retry Pressure",
                            "Live Value": total_retry_count,
                            "Impact": "Retries indicate rework or recovery behavior even if the final run completed.",
                            "Recommended Action": "Check retry_count, max_retries, retry_reason, and route-to-retry behavior.",
                            "Source Variable": "agent_trace.retry_count, agent_trace.max_retries",
                        },
                        {
                            "Defect Signal": "Release Route",
                            "Live Value": release_route_label,
                            "Impact": "Shows whether defects are absorbed, routed to review, sent for retry, blocked, or released.",
                            "Recommended Action": "Use release route as the final operational reliability decision.",
                            "Source Variable": "release_assessment.release_route",
                        },
                    ],
                )

        if show_drilldown("evidence"):
            with st.expander("Click to open evidence set behind evidence count and evidence completeness"):
                evidence_items = result.get("evidence_pack") or result.get("retrieved_chunks") or []
                if isinstance(evidence_items, dict):
                    evidence_items = list(evidence_items.values())
                if isinstance(evidence_items, list) and evidence_items:
                    evidence_rows = []
                    for index, item in enumerate(evidence_items):
                        if isinstance(item, dict):
                            source = item.get("Source") or item.get("source") or "-"
                            chunk_id = item.get("Chunk ID") or item.get("chunk_id") or item.get("id") or "-"
                            rank = item.get("Rank") or item.get("rank") or index + 1
                            title = item.get("Title") or item.get("title") or item.get("name") or "-"
                            content = item.get("Content") or item.get("content") or item.get("text") or item.get("preview") or item
                            evidence_type = item.get("Type") or item.get("type") or Path(str(source)).suffix.replace(".", "").upper() or "Evidence"
                        else:
                            source = "-"
                            chunk_id = "-"
                            rank = index + 1
                            title = "-"
                            content = item
                            evidence_type = type(item).__name__
                        evidence_rows.append(
                            {
                                "#": rank,
                                "Source": source,
                                "Chunk ID": chunk_id,
                                "Type": evidence_type,
                                "Title": title,
                                "Evidence Preview": _narrative_text(content, "-")[:360],
                            }
                        )
                    st.subheader("Evidence Set Behind Evidence Count")
                    st.dataframe(
                        _arrow_safe_dataframe(evidence_rows),
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "#": st.column_config.NumberColumn("#", width="small"),
                            "Source": st.column_config.TextColumn("Source", width="small"),
                            "Chunk ID": st.column_config.TextColumn("Chunk ID", width="medium"),
                            "Type": st.column_config.TextColumn("Type", width="small"),
                            "Title": st.column_config.TextColumn("Title", width="medium"),
                            "Evidence Preview": st.column_config.TextColumn("Evidence Preview", width="large"),
                        },
                    )
                else:
                    st.info("Evidence result set is not available for this run.")

        if show_drilldown("policy"):
            with st.expander("Click to open policy and governance set behind exceptions, HITL, and release route"):
                policy_rows = []
                controls = policy.get("controls") or policy.get("checks") or policy.get("results") or []
                if isinstance(controls, dict):
                    controls = list(controls.values())
                if isinstance(controls, list):
                    for index, item in enumerate(controls):
                        if isinstance(item, dict):
                            control_name = item.get("control") or item.get("name") or item.get("id")
                            status = item.get("status") or item.get("result")
                            rationale = item.get("rationale") or item.get("reason") or item.get("description")
                            severity = item.get("severity") or item.get("level") or "-"
                            if not any([control_name, status, rationale]) and severity:
                                control_name = f"Policy severity signal {index + 1}"
                                status = "REVIEW"
                                rationale = "Runtime emitted severity without a named policy control; treat as a policy telemetry enrichment item."
                            policy_rows.append(
                                {
                                    "Exception / Control": control_name or f"Policy signal {index + 1}",
                                    "Status": status or "-",
                                    "Severity": severity,
                                    "Decision Impact": release_route_label,
                                    "Exact Issue": rationale or f"Policy signal {index + 1} did not emit a specific rationale.",
                                    "Why It Matters": rationale or "Policy signal emitted without explanation; AEGIS highlights this as an explainability enrichment item.",
                                    "Recommended Action": item.get("recommended_action") or item.get("action") or "Review the policy signal and enrich the emitting agent with control name, status, rationale, and remediation.",
                                    "Source Variable": "policy_as_code.controls/checks/results",
                                }
                            )
                if not policy_rows or all(str(row.get("Exception / Control", "")).startswith("Policy severity signal") for row in policy_rows):
                    policy_rows = [
                        {
                            "Exception / Control": "Policy exception signal",
                            "Status": "REVIEW" if failed_policy or critical_failed else "PASS",
                            "Severity": "CRITICAL" if critical_failed else ("REVIEW" if failed_policy else "LOW"),
                            "Decision Impact": release_route_label,
                            "Exact Issue": exact_policy_issue if failed_policy or critical_failed else "No failed policy control is currently reported by policy_as_code.",
                            "Why It Matters": f"{policy_exception_label}. This affects DORA reliability because a governed release should not hide policy exceptions.",
                            "Recommended Action": "Open policy_as_code output and enrich the policy agent to emit named controls, status, rationale, and remediation.",
                            "Source Variable": "policy_as_code.failed_count, policy_as_code.critical_failed_count",
                        },
                        {
                            "Exception / Control": "Governed release route",
                            "Status": release_route_label,
                            "Severity": "Decision",
                            "Decision Impact": release_route_label,
                            "Exact Issue": exact_policy_issue if failed_policy or critical_failed else "Release route is consistent with policy_as_code counts.",
                            "Why It Matters": release_assessment["rationale"],
                            "Recommended Action": "Use the release route to decide publish, retry, HITL review, or block.",
                            "Source Variable": "release_assessment.release_route, release_assessment.rationale",
                        },
                    ]
                render_table("Policy And Governance Set Behind Exceptions", policy_rows)

        if show_drilldown("owasp"):
            with st.expander("Click to open exhaustive OWASP AI Top 10 control set"):
                st.caption("This shows the full OWASP LLM Top 10 control view. Live checks override the fallback row where the runtime emitted detailed findings.")
                render_table("OWASP AI Top 10 Control Set", owasp_control_rows)

        if show_drilldown("audit"):
            with st.expander("Click to open audit package, ledger, consistency, and artifact data"):
                audit_export = _safe_dict(result.get("artifact_export"))
                audit_ledger = _safe_dict(audit_export.get("audit_ledger"))
                audit_manifest = _safe_dict(audit_export.get("manifest"))
                audit_tests = _safe_dict(audit_export.get("test_results"))
                audit_artifact_files = audit_manifest.get("files", []) if isinstance(audit_manifest.get("files"), list) else []
                consistency_rows = _canonical_consistency_audit_rows(result)
                mismatch_rows = [row for row in consistency_rows if row.get("Status") == "MISMATCH"]
                ledger_counts = _audit_ledger_table_counts(audit_ledger, result.get("runtime_id"))
                render_table(
                    "Audit Executive Summary",
                    [
                        {"Audit Area": "Artifact Package", "Live Value": audit_export.get("status", "-"), "Source Variable": "artifact_export.status"},
                        {"Audit Area": "Audit Directory", "Live Value": audit_export.get("directory", "-"), "Source Variable": "artifact_export.directory"},
                        {"Audit Area": "ZIP Package", "Live Value": audit_export.get("zip_path", "-"), "Source Variable": "artifact_export.zip_path"},
                        {"Audit Area": "Audit Ledger", "Live Value": audit_ledger.get("status", "-"), "Source Variable": "artifact_export.audit_ledger.status"},
                        {"Audit Area": "Invariant Tests", "Live Value": f"{audit_tests.get('passed_count', 0)}/{audit_tests.get('total', 0)} passed" if audit_tests else "-", "Source Variable": "artifact_export.test_results"},
                        {"Audit Area": "Canonical Consistency", "Live Value": "PASS" if not mismatch_rows else f"{len(mismatch_rows)} mismatch(es)", "Source Variable": "ui consistency + canonical runtime audit"},
                        {"Audit Area": "Artifact Files", "Live Value": len(audit_artifact_files), "Source Variable": "artifact_export.manifest.files"},
                    ],
                )
                if ledger_counts:
                    render_table(
                        "Audit Ledger Table Counts",
                        [{"Audit Table": table, "Rows": count} for table, count in ledger_counts.items()],
                    )
                if mismatch_rows:
                    render_table("Audit Consistency Exceptions", mismatch_rows)
                if audit_artifact_files:
                    audit_inventory_rows = []
                    for index, item in enumerate(audit_artifact_files[:30], start=1):
                        if isinstance(item, dict):
                            audit_inventory_rows.append(
                                {
                                    "#": index,
                                    "Artifact Name": item.get("name") or item.get("file") or item.get("path") or f"Artifact {index}",
                                    "Type": item.get("type") or item.get("kind") or "-",
                                    "Path": item.get("path") or item.get("file") or "-",
                                    "Status": item.get("status") or "SAVED",
                                    "Size": item.get("size") or item.get("bytes") or "-",
                                    "Source Variable": "artifact_export.manifest.files",
                                }
                            )
                        else:
                            path_text = str(item)
                            audit_inventory_rows.append(
                                {
                                    "#": index,
                                    "Artifact Name": Path(path_text).name or f"Artifact {index}",
                                    "Type": Path(path_text).suffix.replace(".", "").upper() or "-",
                                    "Path": path_text,
                                    "Status": "SAVED",
                                    "Size": "-",
                                    "Source Variable": "artifact_export.manifest.files",
                                }
                            )
                    render_table("Audit Artifact Inventory", audit_inventory_rows)

        if show_drilldown("onboarding"):
            with st.expander("Application onboarding contract, canonical objects, and required telemetry"):
                render_table(
                    "Onboarding Contract Summary Behind Persona Metrics",
                    [
                        {
                            "Contract Area": "Contract Availability",
                            "Live Value": onboarding_contract_status,
                            "Why This Persona Needs It": "Confirms whether the onboarded app/agent has a formal telemetry contract.",
                            "Source Variable": "AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx",
                        },
                        {
                            "Contract Area": "Mandatory Parameters",
                            "Live Value": onboarding_mandatory,
                            "Why This Persona Needs It": "Shows the must-emit fields needed for governance, auditability, runtime traceability, and release control.",
                            "Source Variable": "Telemetry Contract.Required = Mandatory",
                        },
                        {
                            "Contract Area": "Optional Parameters",
                            "Live Value": onboarding_optional,
                            "Why This Persona Needs It": "Shows additional telemetry that improves observability, cost attribution, cache reuse, and operating diagnostics.",
                            "Source Variable": "Telemetry Contract.Required = Optional",
                        },
                        {
                            "Contract Area": "Total Parameters",
                            "Live Value": onboarding_total,
                            "Why This Persona Needs It": "Represents the full object/field inventory an application or local/server agent can emit for AEGIS ingestion.",
                            "Source Variable": "Telemetry Contract row count",
                        },
                        {
                            "Contract Area": "Object Groups",
                            "Live Value": onboarding_groups,
                            "Why This Persona Needs It": "Groups canonical objects into application, runtime, governance, audit, cost, cache, and security areas.",
                            "Source Variable": "Telemetry Contract.Category or Object / Category",
                        },
                    ],
                )
                render_table("Agent Adoption / Download Registry Behind Persona Metrics", _agent_adoption_registry_rows(result))
                render_table("Local / Server Agent Log Contract Behind Persona Metrics", _agent_telemetry_log_schema_rows())

        if show_drilldown("runtime") or show_drilldown("cache") or show_drilldown("cost") or show_drilldown("onboarding"):
            with st.expander("Click to open runtime summary behind completion, latency, cost, and release readiness"):
                render_table(
                    "Runtime Summary Behind Executive Metrics",
                    [
                        {"Metric": "Runtime Status", "Live Value": runtime_status, "Source Variable": "result.runtime_status or result.status"},
                        {"Metric": "Agent Success Rate", "Live Value": agent_success_rate, "Source Variable": "agent_counts.completed / agent_counts.executed"},
                        {"Metric": "Average Agent Time", "Live Value": avg_agent_time, "Source Variable": "agent_counts.avg_latency_ms"},
                        {"Metric": "Observed Handoffs", "Live Value": agent_counts.get("observed_handoffs", 0), "Source Variable": "agent_counts.observed_handoffs"},
                        {"Metric": "Release Allowed", "Live Value": "YES" if release_assessment["release_allowed"] else "NO", "Source Variable": "release_assessment.release_allowed"},
                        {"Metric": "OWASP Security Status", "Live Value": security_status, "Source Variable": "security_analysis.security_status or security.status"},
                        {"Metric": "OWASP Review / Failed Controls", "Live Value": f"Review: {owasp_review_count} | Failed: {owasp_failed_count}", "Source Variable": "security_analysis.checks, failed_controls, review_controls"},
                        {"Metric": "Onboarding Contract", "Live Value": f"{onboarding_contract_status}; mandatory {onboarding_mandatory}; total {onboarding_total}", "Source Variable": "AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx"},
                        {"Metric": "Audit Package", "Live Value": _safe_get(result, "artifact_export", {}).get("status", "-"), "Source Variable": "artifact_export.status"},
                    ],
                )

    def render_persona_detail_tabs(rows):
        st.markdown("#### Persona Detail Tabs")
        st.caption(
            "Each tab shows the detailed metrics, live runtime values, calculation logic, and source variables "
            "for one persona."
        )
        persona_order = []
        rows_by_persona = {}
        for row in rows:
            persona = row.get("Persona", "Persona")
            if persona not in rows_by_persona:
                persona_order.append(persona)
                rows_by_persona[persona] = []
            rows_by_persona[persona].append(
                {
                    "Metric": row.get("What They Track"),
                    "Significance": row.get("Significance of the Metric"),
                    "Live Runtime Value": row.get("Live AEGIS Metrics"),
                    "How Derived / Calculated": row.get("How the Value is Derived / Calculated"),
                    "Source Variable": row.get("From Which Variable the Value is Coming"),
                }
            )

        st.download_button(
            "Download all persona detail tabs (Excel)",
            data=_persona_tabs_to_xlsx_bytes(rows_by_persona),
            file_name="AEGIS_Persona_Detail_Tabs.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="download_all_persona_detail_tabs_xlsx",
        )

        detail_tabs = st.tabs(persona_order)
        for tab, persona in zip(detail_tabs, persona_order):
            with tab:
                render_table(f"{persona} Detailed Metrics", rows_by_persona[persona])
                if persona == "AI Agent Onboarder":
                    catalog_rows = _canonical_parameter_catalog_rows()
                    catalog_df = _arrow_safe_dataframe(catalog_rows)
                    st.markdown("#### Exhaustive Canonical Parameter Catalog")
                    st.caption(
                        "Single onboarding catalog for all mandatory, conditional, and non-mandatory canonical parameters. "
                        "It covers runtime emission and pre-release/release-gate requirements for local, server, and platform agents."
                    )
                    st.download_button(
                        "Download canonical parameter catalog (Excel)",
                        data=_dataframe_to_xlsx_bytes(catalog_df),
                        file_name="AEGIS_Canonical_Parameter_Catalog.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        key="download_aegis_canonical_parameter_catalog",
                    )
                    st.markdown(f"#### Full Parameter List ({len(catalog_rows)} canonical parameters)")
                    st.dataframe(
                        catalog_df,
                        use_container_width=True,
                        hide_index=True,
                        height=560,
                        column_config={
                            "#": st.column_config.NumberColumn("#", width="small"),
                            "Canonical Object / Parameter": st.column_config.TextColumn("Canonical Object / Parameter", width="medium"),
                            "Agent Category": st.column_config.TextColumn("Agent Category", width="small"),
                            "Data Type": st.column_config.TextColumn("Data Type", width="small"),
                            "Mandatory / Non Mandatory": st.column_config.TextColumn("Mandatory / Non Mandatory", width="small"),
                            "Runtime Classification": st.column_config.TextColumn("Runtime Classification", width="medium"),
                            "Emission Stage": st.column_config.TextColumn("Runtime / Before Release", width="medium"),
                            "Example Value": st.column_config.TextColumn("Example Value", width="medium"),
                            "Why AEGIS Requires It": st.column_config.TextColumn("Why AEGIS Requires It", width="large"),
                            "Used For": st.column_config.TextColumn("Used For", width="medium"),
                            "Expected Source": st.column_config.TextColumn("Expected Source", width="large"),
                        },
                    )
                render_persona_metric_drilldowns(persona, rows_by_persona[persona])

    add_persona_metric("AI Application Owner / Executive", "Governed release route", "Owns the application outcome: whether this specific AI application result is ready for controlled use.", release_route_label, "release_assessment.release_route")
    add_persona_metric("AI Application Owner / Executive", "Trust and confidence", "Shows whether this application's current result is reliable enough for controlled consumption.", f"Trust: {quality.get('trust_score', '-')} | Confidence: {quality.get('confidence', '-')}", "quality.trust_score, quality.confidence")
    add_persona_metric("AI Application Owner / Executive", "Cost of execution", "Connects this application run to platform value and cost visibility.", cost, "result.estimated_cost_usd or token_metrics.estimated_cost_usd")
    add_persona_metric("AI Application Owner / Executive", "Runtime completion", "Confirms whether this application investigation completed and produced a governed outcome.", runtime_status, "result.runtime_status or result.status")
    add_persona_metric("AI Application Owner / Executive", "Application audit readiness", "Shows whether the app outcome has a saved evidence package for executive/risk review.", export.get("status", "-"), "artifact_export.status")
    add_persona_metric("AI Application Owner / Executive", "Repeat-run scalability", "Shows whether the same application query can be reused from cache for faster repeat decisions.", f"{cache_mode} | Entries: {cache_entries}", "cache_lookup/cache_metrics.status, entries")

    add_persona_metric("AI Platform Lead / AI Manager", "Agent execution coverage", "Owns the cross-application agent estate: whether planned and onboarded agents are executing reliably.", f"{executed_agents}/{agent_counts.get('total', 0)} agents", "agent_counts.executed, agent_counts.total")
    add_persona_metric("AI Platform Lead / AI Manager", "Policy exceptions", "Highlights agent/platform governance backlog across AI delivery teams.", failed_policy, "policy_as_code.failed_count")
    add_persona_metric("AI Platform Lead / AI Manager", "Model quality trend point", "Gives a platform-level signal for model/agent quality health and improvement planning.", f"Trust: {quality.get('trust_score', '-')} | Confidence: {quality.get('confidence', '-')}", "quality.trust_score, quality.confidence")
    add_persona_metric("AI Platform Lead / AI Manager", "OWASP AI coverage", "Shows whether the agent platform is enforcing security checks across the runtime path.", f"Top 10 rows: {len(owasp_control_rows)} | Review: {owasp_review_count} | Failed: {owasp_failed_count}", "security_analysis.checks, aegis_owasp_control_catalog")
    add_persona_metric("AI Platform Lead / AI Manager", "Audit package health", "Shows whether the platform creates reusable evidence for leadership, risk, and audit review.", _safe_get(result, "artifact_export", {}).get("status", "-"), "artifact_export.status")
    add_persona_metric("AI Platform Lead / AI Manager", "Runtime measurability coverage", "Shows whether agents emit timing, status, and traversal data for platform operations.", f"Stages: {agent_counts.get('execution_stages', 0)} | Handoffs: {agent_counts.get('observed_handoffs', 0)} | Avg: {avg_agent_time}", "agent_counts.execution_stages, observed_handoffs, avg_latency_ms")
    add_persona_metric("AI Platform Lead / AI Manager", "Cache reuse scalability", "Shows whether the platform is reducing repeat execution through reusable runtime cache.", f"Status: {cache_status} | Hit ratio: {cache_hit_ratio}% | Hits/Misses: {cache_hits}/{cache_misses}", "cache_lookup/cache_metrics.status, cache_hit_ratio, cache_hits, cache_misses")
    add_persona_metric("AI Platform Lead / AI Manager", "Reliability defect load", "Shows operational debt caused by failed agents, failed controls, or retry/review paths.", f"Failed agents: {failed_agents} | Policy failed: {failed_policy} | OWASP failed: {owasp_failed_count}", "agent_counts.failed, policy_as_code.failed_count, security_analysis.failed_controls")
    add_persona_metric("AI Platform Lead / AI Manager", "Agent adoption visibility", "Shows which agents are registered, adopted/downloaded, or at least observed in the current runtime.", agent_adoption_summary, "agent_adoption_registry / agent_registry / adopted_agents / agent_trace")

    add_persona_metric("AI Administrator", "Operational exceptions", "Shows what needs admin action before release or audit closure.", f"Failed: {failed_policy} | Critical: {critical_failed}", "policy_as_code.failed_count, policy_as_code.critical_failed_count")
    add_persona_metric("AI Administrator", "HITL requirement", "Shows whether operational routing requires human intervention.", "YES" if release_assessment["review_required"] else "NO", "release_assessment.review_required")
    add_persona_metric("AI Administrator", "Agent failure count", "Identifies failed runtime components that need recovery.", failed_agents, "agent_counts.failed")
    add_persona_metric("AI Administrator", "Cache TTL and freshness", "Shows whether cached results are fresh enough for operational reuse.", f"TTL: {cache_ttl} | Remaining: {cache_remaining_ttl} | Age: {cache_age}", "cache_lookup.ttl_seconds, remaining_ttl_seconds, age_seconds")
    add_persona_metric("AI Administrator", "Audit ledger health", "Shows whether durable audit tables are generated for operational replay and investigation.", f"Ledger: {ledger.get('status', '-')} | Tables: {len(ledger_counts_for_persona)}", "artifact_export.audit_ledger.status, audit ledger table counts")
    add_persona_metric("AI Administrator", "Runtime invariant status", "Shows whether saved runtime checks passed after export.", invariant_value, "artifact_export.test_results")

    add_persona_metric("AI Developer / Agent Builder", "Evidence object count", "Shows whether enough evidence was retrieved and packaged for reasoning.", evidence_count, "evidence_pack or retrieved_chunks")
    add_persona_metric("AI Developer / Agent Builder", "Observed handoffs", "Shows runtime traversal and agent-to-agent movement.", agent_counts.get("observed_handoffs", 0), "agent_counts.observed_handoffs")
    add_persona_metric("AI Developer / Agent Builder", "Runtime source", "Shows whether the view is built from graph telemetry or normalized trace.", agent_counts.get("source", "-"), "agent_counts.source")
    add_persona_metric("AI Developer / Agent Builder", "OWASP AI control status", "Shows whether prompt, data, tool, and runtime security checks are clean before the agent is trusted.", f"Status: {security_status} | Score: {security_score} | Review: {owasp_review_count} | Failed: {owasp_failed_count}", "security_analysis/security.status, security_score, checks")
    add_persona_metric("AI Developer / Agent Builder", "Mandatory contract readiness", "Shows whether developers have the required variables configured for AEGIS to read and govern the agent.", f"Contract: {onboarding_contract_status} | Mandatory: {onboarding_mandatory} | Total: {onboarding_total}", "onboarding telemetry contract workbook.Required")
    add_persona_metric("AI Developer / Agent Builder", "Agent-level token and cost attribution", "Shows whether each agent can be measured for cost, tokens, and performance.", "Available in Agent Execution Set drilldown", "agent_trace + llm_trace + token_metrics")
    add_persona_metric("AI Developer / Agent Builder", "Retry and resilience instrumentation", "Shows whether retry count, max retries, errors, and fallback signals can be debugged.", "Available in Agent Execution Set drilldown", "agent_trace.retry_count, max_retries, error_code, fallback_used")
    add_persona_metric("AI Developer / Agent Builder", "Cache key diagnostics", "Shows why repeat runs do or do not reuse cached output.", _cache_miss_reason(cache, result.get("query_cache", {})), "cache_lookup.reason, query_cache.status, cache key dimensions")
    add_persona_metric("AI Developer / Agent Builder", "Local/server log contract", "Shows the exact fields a local or server agent must emit so AEGIS can ingest, govern, and audit it.", f"{len(agent_telemetry_schema_rows)} log fields", "AEGIS local/server agent telemetry schema")

    add_persona_metric("AI Agent Onboarder", "Canonical signal coverage", "Shows the canonical telemetry reference and the runtime signals observed for this execution.", f"Catalog: {canonical_catalog_count} total | Mandatory: {canonical_required_count} | Observed now: {canonical_added_count}", "Agent Canonical Parameter Contract + live runtime keys")
    add_persona_metric("AI Agent Onboarder", "Evidence payload availability", "Shows whether the agent/app emits evidence objects AEGIS can inspect.", evidence_count, "evidence_pack or retrieved_chunks")
    add_persona_metric("AI Agent Onboarder", "Runtime contract source", "Shows which telemetry source AEGIS used for certification and whether any onboarded agent is not running properly.", f"Source: {agent_counts.get('source', '-')} | Failed agents: {failed_agents} | Executed: {executed_agents}/{agent_counts.get('total', 0)}", "agent_counts.source, agent_counts.failed, agent_trace.status")
    add_persona_metric("AI Agent Onboarder", "Application onboarding contract", "Shows the required parameter inventory that an app or agent must emit before onboarding is accepted.", f"Status: {onboarding_contract_status} | Total: {onboarding_total} | Mandatory: {onboarding_mandatory} | Groups: {onboarding_groups}", "AEGIS_Business_Application_Onboarding_Telemetry_Contract.xlsx")
    add_persona_metric("AI Agent Onboarder", "Agent adoption/download tracking", "Shows whether adopted/downloaded agents can be traced to owner, version, environment, usage, and last-used timestamp.", agent_adoption_summary, "agent_adoption_registry / agent_registry / adopted_agents / agent_trace")
    add_persona_metric("AI Agent Onboarder", "OWASP onboarding gate", "Ensures new agents are checked for OWASP AI risks before they are certified.", f"Risk: {security_risk} | Review: {owasp_review_count} | Failed: {owasp_failed_count}", "security_analysis.risk_level, security_analysis.checks")
    add_persona_metric("AI Agent Onboarder", "Cost and cache contract coverage", "Shows whether onboarded apps emit cost/cache fields needed for scalability and economics.", f"Cache status: {cache_status} | Cost: {cost}", "cache_lookup/cache_metrics + token_metrics.estimated_cost_usd")
    add_persona_metric("AI Agent Onboarder", "Audit metadata contract coverage", "Shows whether app/agent emits audit IDs, artifact hashes, and lineage fields.", f"Artifact files: {len(artifact_files)} | Ledger: {ledger.get('status', '-')}", "artifact_export.manifest.files, audit_ledger.status")

    add_persona_metric("Risk / Governance Reviewer", "Governance status", "Shows the policy decision state for this recommendation.", release_assessment["governance_status"], "release_assessment.governance_status")
    add_persona_metric("Risk / Governance Reviewer", "Release rationale", "Explains why AEGIS selected the current release route.", release_assessment["rationale"], "release_assessment.rationale")
    add_persona_metric("Risk / Governance Reviewer", "Compliance exceptions", "Shows whether controls failed or need escalation.", f"Failed: {failed_policy} | Critical: {critical_failed}", "policy_as_code.failed_count, policy_as_code.critical_failed_count")
    add_persona_metric("Risk / Governance Reviewer", "OWASP AI risk posture", "Shows whether security controls should influence release, review, retry, or block.", f"Status: {security_status} | Risk: {security_risk} | Failed: {owasp_failed_count}", "security_analysis.security_status, risk_level, failed_controls")
    add_persona_metric("Risk / Governance Reviewer", "Audit consistency exceptions", "Shows whether displayed values match canonical runtime authority before presentation.", mismatch_count, "canonical consistency audit mismatch rows")
    add_persona_metric("Risk / Governance Reviewer", "Policy-to-release traceability", "Shows the chain from policy result to release route and HITL decision.", f"Route: {release_route_label} | HITL: {'YES' if release_assessment['review_required'] else 'NO'}", "release_assessment.release_route, review_required")

    add_persona_metric("DORA Lead", "Agent success rate", "Measures whether agents are completing successfully across the runtime.", agent_success_rate, "agent_counts.completed / agent_counts.executed")
    add_persona_metric("DORA Lead", "Expected-behavior status", "Shows whether completion also satisfied policy, failure, and release conditions.", expected_behavior, "runtime_status, agent_counts.failed, policy_as_code.failed_count, release_assessment.release_allowed")
    add_persona_metric("DORA Lead", "Recovery / reliability signal", "Highlights failed agents and policy exceptions that affect DORA reliability.", f"Failed agents: {failed_agents} | {policy_exception_label}", "agent_counts.failed, policy_as_code.failed_count, policy_as_code.critical_failed_count")
    add_persona_metric("DORA Lead", "Lead-time proxy", "Uses total runtime duration as a per-run lead-time proxy for agentic execution.", _format_agent_latency(agent_counts.get("latency_ms", 0)), "agent_counts.latency_ms")
    add_persona_metric("DORA Lead", "Change failure proxy", "Uses blocked/review/failed runtime signals as the agentic change-failure proxy.", f"Route: {release_route_label} | Failed agents: {failed_agents} | Policy failed: {failed_policy}", "release_assessment.release_route, agent_counts.failed, policy_as_code.failed_count")
    add_persona_metric("DORA Lead", "Cache acceleration impact", "Shows whether repeat runs reduce lead time and cost through cache.", f"Status: {cache_status} | Hit ratio: {cache_hit_ratio}% | Entries: {cache_entries}", "cache_lookup/cache_metrics")
    add_persona_metric("DORA Lead", "Deployment frequency event", "Current run contributes one governed deployment/release-readiness event when release is allowed.", "1 release-ready event" if release_assessment["release_allowed"] else "0 release-ready events", "release_assessment.release_allowed")
    add_persona_metric("DORA Lead", "MTTR / recovery proxy", "Current-run recovery view based on runtime completion, failed agents, and retry count.", f"Runtime: {runtime_status} | Failed agents: {failed_agents} | Retries: {total_retry_count}", "runtime_status, agent_counts.failed, agent_trace.retry_count")
    add_persona_metric("DORA Lead", "Task completion rate", "Current-run task completion signal for the AI agent workflow.", "100%" if task_completed else "0%", "runtime_status")
    add_persona_metric("DORA Lead", "Autonomous resolution rate", "Current-run autonomy signal: completed, release allowed, and no human review required.", "100%" if autonomous_resolution else "0%", "runtime_status, release_assessment.release_allowed, review_required")
    add_persona_metric("DORA Lead", "Human override rate", "Shows whether this run required manual intervention or review.", escalation_rate_proxy, "release_assessment.review_required")
    add_persona_metric("DORA Lead", "Retry rate", "Shows retry pressure as retries divided by executed agents for this run.", retry_rate_proxy, "agent_trace.retry_count / agent_counts.executed")
    add_persona_metric("DORA Lead", "Exception rate", "Shows failed-agent pressure as failed agents divided by executed agents.", exception_rate_proxy, "agent_counts.failed / agent_counts.executed")
    add_persona_metric("DORA Lead", "SLA compliance proxy", "Uses 30 minutes as the current-run banking demo SLA threshold for total runtime duration.", f"{sla_status} | Runtime: {total_execution_latency}", "agent_counts.latency_ms")
    add_persona_metric("DORA Lead", "Policy compliance", "Tracks whether governance/security policy checks are clean.", policy_compliance_rate, "policy_as_code.failed_count, critical_failed_count")
    add_persona_metric("DORA Lead", "Auditability rate", "Tracks whether audit package is saved and canonical consistency is clean.", auditability_rate, "artifact_export.status, canonical consistency mismatches")
    add_persona_metric("DORA Lead", "Security incident proxy", "Counts OWASP review and failed controls as AI-agent security incidents requiring attention.", security_incident_proxy, "security_analysis.checks review/fail counts")
    add_persona_metric("DORA Lead", "Cost per task", "For a single completed investigation, current-run model/runtime cost is treated as cost per task.", cost_per_task, "estimated_cost_usd or token_metrics.estimated_cost_usd")
    add_persona_metric("DORA Lead", "Agent maturity signal", "Classifies current architecture based on observed multi-agent orchestration and governance evidence.", "Level 4 - Multi-agent orchestrator with governance" if executed_agents > 1 else "Level 2/3 - Single-agent or workflow executor", "agent_counts.executed, governance/audit controls")

    add_persona_metric("DORA Member / Test Lead", "Release readiness", "Shows whether this run can be treated as release-ready from test/governance perspective.", "YES" if release_assessment["release_allowed"] else "NO", "release_assessment.release_allowed")
    add_persona_metric("DORA Member / Test Lead", "Regression/control failures", "Highlights failed critical checks that should block or delay certification.", critical_failed, "policy_as_code.critical_failed_count")
    add_persona_metric("DORA Member / Test Lead", "Evidence completeness signal", "Shows whether the release has supporting evidence for test sign-off.", evidence_count, "evidence_pack or retrieved_chunks")
    add_persona_metric("DORA Member / Test Lead", "Invariant test status", "Shows saved regression checks for runtime package quality.", invariant_value, "artifact_export.test_results")
    add_persona_metric("DORA Member / Test Lead", "OWASP test coverage", "Shows whether the release includes the OWASP AI control set.", f"Rows: {len(owasp_control_rows)} | Review: {owasp_review_count} | Failed: {owasp_failed_count}", "OWASP Top 10 control set")
    add_persona_metric("DORA Member / Test Lead", "Audit artifact readiness", "Shows whether test evidence can be packaged for sign-off.", f"Artifacts: {len(artifact_files)} | Package: {export.get('status', '-')}", "artifact_export.manifest.files, artifact_export.status")
    add_persona_metric("DORA Member / Test Lead", "First-time success rate", "Current-run proxy: release allowed with no retries, failed agents, or critical failures.", "100%" if release_assessment["release_allowed"] and total_retry_count == 0 and failed_agents == 0 and critical_failed == 0 else "REVIEW", "release_allowed, retry_count, failed_agents, critical_failed")
    add_persona_metric("DORA Member / Test Lead", "Rework rate proxy", "Uses retry, review, or critical failure signals as current-run rework indicators.", "0%" if total_retry_count == 0 and not release_assessment["review_required"] and critical_failed == 0 else "REVIEW", "agent_trace.retry_count, release_assessment.review_required, critical_failed_count")
    add_persona_metric("DORA Member / Test Lead", "Hallucination signal", "Tracks hallucination or misinformation risk from quality/security evaluation.", hallucination_signal, "quality.hallucination_score or security.misinformation")
    add_persona_metric("DORA Member / Test Lead", "RAG quality scorecard", "Combines grounding, context coverage, and evidence count for retrieval-backed agents.", rag_quality_signal, "quality.groundedness, quality.coverage, evidence_pack/retrieved_chunks")
    add_persona_metric("DORA Member / Test Lead", "Context utilization", "Shows whether the provided context/evidence was sufficiently used by the response.", context_utilization_signal, "quality.coverage")
    add_persona_metric("DORA Member / Test Lead", "Multi-agent collaboration success", "Current-run proxy based on completed agents and observed handoffs.", f"Completed: {completed_agents}/{executed_agents} | Handoffs: {agent_counts.get('observed_handoffs', 0)}", "agent_counts.completed, executed, observed_handoffs")

    add_persona_metric("Model Risk / AI Assurance", "Model assurance score", "Combines trust and confidence as the current assurance signal.", f"Trust: {quality.get('trust_score', '-')} | Confidence: {quality.get('confidence', '-')}", "quality.trust_score, quality.confidence")
    add_persona_metric("Model Risk / AI Assurance", "Governed release route", "Shows whether assurance outcome leads to release, review, retry, or block.", release_route_label, "release_assessment.release_route")
    add_persona_metric("Model Risk / AI Assurance", "Policy exception count", "Shows whether the model output violated any policy constraints.", failed_policy, "policy_as_code.failed_count")
    add_persona_metric("Model Risk / AI Assurance", "OWASP AI assurance", "Shows whether model output and tool behavior have security review or failure signals.", f"Score: {security_score} | Review: {owasp_review_count} | Failed: {owasp_failed_count}", "security_analysis.security_score, security_analysis.checks")
    add_persona_metric("Model Risk / AI Assurance", "Grounding and evidence assurance", "Shows whether model output has supporting evidence and confidence signals.", f"Evidence: {evidence_count} | Trust: {quality.get('trust_score', '-')}", "evidence_pack/retrieved_chunks, quality.trust_score")
    add_persona_metric("Model Risk / AI Assurance", "Assurance audit trail", "Shows whether assurance evidence is saved for audit/regulatory review.", f"Package: {export.get('status', '-')} | Consistency mismatches: {mismatch_count}", "artifact_export.status, canonical consistency audit")

    add_persona_metric("Audit / Regulator Viewer", "Audit evidence count", "Shows the evidence base available for independent inspection.", evidence_count, "evidence_pack or retrieved_chunks")
    add_persona_metric("Audit / Regulator Viewer", "Runtime decision record", "Shows final governed status and release eligibility.", f"Status: {runtime_status} | Release allowed: {'YES' if release_assessment['release_allowed'] else 'NO'}", "result.runtime_status, release_assessment.release_allowed")
    add_persona_metric("Audit / Regulator Viewer", "Control rationale", "Provides explainability for the final governance state.", release_assessment["rationale"], "release_assessment.rationale")
    add_persona_metric("Audit / Regulator Viewer", "Onboarding contract evidence", "Shows the formal variable contract used to prove the app/agent is governable and auditable.", f"Contract: {onboarding_contract_status} | Mandatory fields: {onboarding_mandatory} | Optional fields: {onboarding_optional}", "onboarding telemetry contract workbook")
    add_persona_metric("Audit / Regulator Viewer", "Audit ledger table coverage", "Shows whether audit tables exist for run, agent execution, evidence, decision, cache, consistency, and artifacts.", f"Tables with counts: {len(ledger_counts_for_persona)}", "artifact_export.audit_ledger table counts")
    add_persona_metric("Audit / Regulator Viewer", "Artifact inventory completeness", "Shows whether reports, JSON/CSV, evidence, and package outputs were generated.", f"Artifact files: {len(artifact_files)}", "artifact_export.manifest.files")
    add_persona_metric("Audit / Regulator Viewer", "Canonical consistency status", "Shows whether live UI, runtime state, and exported records agree.", "PASS" if mismatch_count == 0 else f"{mismatch_count} mismatch(es)", "canonical consistency audit")

    add_persona_metric("AI Product / Application Owner", "Recommendation outcome", "Shows the application-facing decision or proposed action.", recommendation_label, "release_assessment.recommendation or governance_status or release_route")
    add_persona_metric("AI Product / Application Owner", "Cost-to-value signal", "Shows the execution cost attached to this governed outcome.", cost, "result.estimated_cost_usd or token_metrics.estimated_cost_usd")
    add_persona_metric("AI Product / Application Owner", "Release route", "Shows whether the application outcome is ready to publish or needs action.", release_route_label, "release_assessment.release_route")
    add_persona_metric("AI Product / Application Owner", "Repeatability / reuse signal", "Shows whether similar future application requests can be accelerated.", f"Cache: {cache_status} | Hit ratio: {cache_hit_ratio}%", "cache_lookup/cache_metrics")
    add_persona_metric("AI Product / Application Owner", "Evidence-backed decision value", "Shows whether the recommendation is backed by traceable evidence.", f"Evidence: {evidence_count} | Audit: {export.get('status', '-')}", "evidence_pack/retrieved_chunks, artifact_export.status")

    add_persona_metric("SRE / Platform Operations", "Average agent time", "Shows runtime performance and potential bottlenecks.", avg_agent_time, "agent_counts.avg_latency_ms")
    add_persona_metric("SRE / Platform Operations", "Failed agents", "Shows operational failures requiring recovery.", failed_agents, "agent_counts.failed")
    add_persona_metric("SRE / Platform Operations", "Observed handoffs", "Shows runtime traversal volume and orchestration movement.", agent_counts.get("observed_handoffs", 0), "agent_counts.observed_handoffs")
    add_persona_metric("SRE / Platform Operations", "Cache operational health", "Shows cache status, hit/miss, TTL, and freshness for repeat workload performance.", f"Status: {cache_status} | Hits/Misses: {cache_hits}/{cache_misses} | TTL: {cache_ttl}", "cache_lookup/cache_metrics")
    add_persona_metric("SRE / Platform Operations", "Runtime recoverability", "Shows whether runtime can complete despite misses, retries, review gates, or degraded paths.", f"Status: {runtime_status} | Failed agents: {failed_agents} | Route: {release_route_label}", "runtime_status, agent_counts.failed, release_assessment.release_route")
    add_persona_metric("SRE / Platform Operations", "Audit/cache operational ledger", "Shows whether cache and runtime activity is available for operational replay.", f"Audit cache rows: {ledger_counts_for_persona.get('audit_cache_event', '-')}", "audit_ledger.audit_cache_event")

    render_persona_matrix(persona_rows)
    render_persona_detail_tabs(persona_rows)


def render_control_tower(result):

    result = _normalize_runtime_result_for_ui(result)
    st.session_state["runtime_state"] = result

    render_top_runtime_alerts(result)

    with st.container(border=True):
        render_query_overview(result)

    with st.container(border=True):
        render_executive_runtime_snapshot(result)

    with st.container(border=True):
        render_executive_positioning_panel(result)

    with st.container(border=True):
        render_enterprise_ai_control_pillars(result)

    with st.container(border=True):
        render_canonical_runtime_audit(result)

    with st.container(border=True):
        render_cache_roi_panel(result)

    with st.container(border=True):
        render_agent_execution_graph(result)

    with st.container(border=True):
        render_decision_lineage_graph(result)

    with st.container(border=True):
        render_persona_operating_model(result)

    tabs = st.tabs([
        "Six Pillar Control View",
        "DBS Value Add",
        "OWASP AI",
        "LLM Judge & Assurance",
        "AI Release Policy Gate",
        "Human Review & Release Gate",
        "Runtime Observability",
        "Operational Control Loop",
        "Alerts & Notifications",
        "Cache Acceleration",
        "Model Cost & Token Economics",
        "Evidence",
        "Risk, Governance & Decisioning",
        "Investigation",
        "Agents",
        "Retrieval",
        "Control Tower Architecture",
        "Application Onboarding Contract",
        "Missing Signals",
        "Technical Architecture",
        "AI Asset Registry",
        "Auditability",
        "Audit & Evidence Package",
    ])

    with tabs[0]:
        with st.container(border=True):
            render_six_pillar_control_view(result)

    with tabs[1]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Measurable AI", "Scalable AI", "Resilient AI", "Auditable AI"],
                "DBS Value Add connects the AEGIS control-tower capabilities to practical enterprise outcomes for banking technology, AI platform leadership, risk, and audit.",
            )
            render_dbs_value_add(result)

    with tabs[2]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Trustworthy AI", "Governable AI", "Resilient AI"],
                "OWASP AI proves that prompt, retrieval, memory, tool, and runtime security controls are being checked before the output is trusted.",
            )
            render_owasp_security(result)

    with tabs[3]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Trustworthy AI", "Governable AI", "Auditable AI", "Resilient AI"],
                "LLM Judge & Assurance explains how AEGIS validates generated output, retrieved evidence, security posture, model risk, human review, and resilience controls.",
            )
            render_llm_judge_assurance(result)

    with tabs[4]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Resilient AI", "Auditable AI"],
                "AI Release Policy Gate shows the rules AEGIS applies before output release, retry, block, or human review.",
            )
            render_ai_release_policy_gate(result)

    with tabs[5]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Resilient AI", "Auditable AI"],
                "Human Review and Release Gate shows when AEGIS blocks automated publication, requests retries, and routes the case to a reviewer queue.",
            )
            render_human_review_release_gate(result)

    with tabs[6]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Measurable AI", "Resilient AI"],
                "Runtime Observability proves execution health, agent timing, bottlenecks, skipped paths, and operational readiness.",
            )
            render_runtime_observability_summary(result)
        with st.container(border=True):
            render_latency_waterfall(result)

    with tabs[7]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Measurable AI", "Auditable AI", "Resilient AI"],
                "Operational Control Loop shows response files, HITL queue, app and agent registries, prompt registry, runtime history, policy config, API contract, and alert outputs.",
            )
            render_operational_control_loop(result)

    with tabs[8]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Resilient AI", "Governable AI"],
                "Alerts and notifications show which runtime, policy, security, or evidence conditions need escalation.",
            )
            render_monitoring_alerts(result)

    with tabs[9]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Scalable AI", "Measurable AI"],
                "Cache Acceleration proves repeatability, reuse, reduced execution time, and lower model/runtime cost over repeated runs.",
            )
            render_cache_intelligence(result)

    with tabs[10]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Measurable AI", "Scalable AI"],
                "Model Cost and Token Economics make AI usage financially measurable and scalable across applications.",
            )
            render_llm_cost_summary(result)

    with tabs[11]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Trustworthy AI", "Auditable AI"],
                "Evidence proves the final decision is grounded, traceable, reranked, and explainable to risk, audit, and technology teams.",
            )
            render_evidence(result)

    with tabs[12]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Trustworthy AI"],
                "Risk, governance, and decisioning prove that the recommendation is policy-controlled, risk-aware, and review-ready.",
            )
            render_decision_policy_path(result)
        with st.container(border=True):
            render_recommendation(result)
        with st.container(border=True):
            render_governance(result)

    with tabs[13]:
        with st.container(border=True):
            render_investigation(result)
        with st.container(border=True):
            render_customer(result)

    with tabs[14]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Measurable AI", "Resilient AI"],
                "Agents prove traversal, execution status, timing, skipped branches, repeated runs, and runtime health.",
            )
            render_agent_runtime(result)
        with st.container(border=True):
            render_planner(result)
        with st.container(border=True):
            render_tools(result)

    with tabs[15]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Trustworthy AI", "Auditable AI"],
                "Retrieval proves which sources were searched, what method was used, and what evidence was returned before decisioning.",
            )
            render_retrieval(result)

    with tabs[16]:
        with st.container(border=True):
            render_control_tower_architecture(result)

    with tabs[17]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Measurable AI", "Auditable AI"],
                "The onboarding contract defines what external AI apps must emit so AEGIS can govern, observe, and audit them consistently.",
            )
            render_app_onboarding_contract(result)

    with tabs[18]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Governable AI", "Measurable AI", "Auditable AI"],
                "Missing Signals highlights mandatory canonical fields that the external app has not emitted yet, so onboarding gaps are visible before certification.",
            )
            render_missing_runtime_signals(result)

    with tabs[19]:
        with st.container(border=True):
            render_technical_project_summary(result)

    with tabs[20]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Scalable AI", "Governable AI", "Auditable AI"],
                "The AI Asset Registry shows which apps, agents, models, prompts, tools, data assets, controls, and artifacts are governed.",
            )
            render_ai_asset_registry(result)

    with tabs[21]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Auditable AI", "Governable AI"],
                "Auditability proves canonical consistency, runtime checks, evidence records, generated artifacts, and review readiness.",
            )
            render_auditability(result)

    with tabs[22]:
        with st.container(border=True):
            render_pillar_coverage(
                ["Auditable AI", "Trustworthy AI"],
                "The audit package preserves the evidence, runtime state, reports, and export artifacts needed for independent review.",
            )
            render_investigation_artifacts(result)

    with st.container(border=True):
        render_executive_summary(result)


render_control_tower(runtime_state)
