"""Reusable AEGIS Control Tower canonical-object measurement service.

This module is deliberately UI-free. Any agentic application can pass its
runtime state or emitted runtime events here to get the same canonical Control
Tower objects that the Streamlit UI and artifacts display.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Tuple

from services1.runtime_ingestion_service import events_from_agent_trace, ingest_runtime_events


CANONICAL_SCHEMA_VERSION = "AEGIS-CONTROL-TOWER-CANONICAL-2026.08"
RELEASE_RISK_STATES = {
    "HIGH",
    "CRITICAL",
    "REVIEW",
    "REVIEW_REQUIRED",
    "INSUFFICIENT_EVIDENCE",
    "CUSTOMER_NOT_FOUND",
    "UNKNOWN",
    "-",
}
HITL_RISK_STATES = {"HIGH", "CRITICAL"}
HITL_RECOMMENDATIONS = {"ESCALATE", "REJECT", "HOLD", "REVIEW", "REVIEW_REQUIRED"}
HITL_CONTROL_FAILURE_STATES = {
    "FAIL",
    "FAILED",
    "BLOCKED",
    "NON_COMPLIANT",
    "REVIEW",
    "REVIEW_REQUIRED",
}
HITL_CONFIDENCE_FLOOR = 70.0
HITL_TRUST_FLOOR = 70.0
FINAL_RECOMMENDATIONS = {"APPROVE", "MONITOR", "ESCALATE", "REVIEW", "REJECT"}
FATAL_ERROR_CODES = {"RUNTIME_ERROR", "POLICY_BLOCKED", "CONTROL_FAILED"}
RECOVERABLE_ERROR_CODES = {"TIMEOUT", "VALIDATION_ERROR", "INSUFFICIENT_EVIDENCE"}


def safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_get(value: Any, key: str, default: Any = None) -> Any:
    return value.get(key, default) if isinstance(value, dict) else default


def safe_count(value: Any) -> int:
    if value is None:
        return 0
    try:
        return len(value)
    except TypeError:
        return 1 if value else 0


def evidence_count(runtime_state: Dict[str, Any]) -> int:
    result = safe_dict(runtime_state)
    return safe_count(result.get("evidence_pack") or result.get("retrieved_chunks") or result.get("evidence_ids"))


def numeric_score(value: Any, default: float = 0.0) -> float:
    if isinstance(value, dict):
        value = value.get("overall", value.get("score", value.get("value", default)))
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def bounded_score(value: Any, default: float = 0.0) -> float:
    return max(0.0, min(numeric_score(value, default), 100.0))


def is_unknown_value(value: Any) -> bool:
    if isinstance(value, (dict, list, tuple, set)):
        return len(value) == 0
    text = str("" if value is None else value).strip().casefold()
    return text in {"", "-", "unknown", "unkwn", "none", "null", "n/a", "nan", "<na>"}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _finding_severities(runtime_state: Dict[str, Any]) -> List[str]:
    result = safe_dict(runtime_state)
    findings = []
    findings.extend(_as_list(result.get("findings")))
    findings.extend(_as_list(result.get("policy_findings")))
    findings.extend(_as_list(safe_get(result.get("governance"), "findings")))
    findings.extend(_as_list(safe_get(result.get("compliance"), "findings")))
    severities: List[str] = []
    for finding in findings:
        if isinstance(finding, dict):
            severity = finding.get("severity") or finding.get("risk") or finding.get("risk_level")
            code = finding.get("code") or finding.get("error_code")
            if is_unknown_value(severity) and not is_unknown_value(code):
                severity = "HIGH" if str(code).upper() in FATAL_ERROR_CODES else "MEDIUM"
        else:
            text = str(finding).upper()
            severity = "CRITICAL" if "CRITICAL" in text else "HIGH" if "HIGH" in text or "FAIL" in text else "MEDIUM"
        if not is_unknown_value(severity):
            severities.append(str(severity).upper())
    return severities


def normalize_error_code(runtime_state: Dict[str, Any]) -> str:
    result = safe_dict(runtime_state)
    raw = (
        result.get("error_code")
        or safe_get(result.get("error"), "code")
        or safe_get(result.get("runtime_error"), "code")
        or safe_get(result.get("publication_gate"), "block_code")
    )
    message = str(result.get("error_message") or safe_get(result.get("error"), "message") or "").upper()
    if is_unknown_value(raw) and not message:
        return "NONE"
    text = str(raw or message).upper()
    if "TIMEOUT" in text or "TIMED_OUT" in text or "TIMED OUT" in text:
        return "TIMEOUT"
    if "VALIDATION" in text or "SCHEMA" in text or "MISSING" in text:
        return "VALIDATION_ERROR"
    if "POLICY" in text or "BLOCK" in text:
        return "POLICY_BLOCKED"
    if "CONTROL" in text or "FAILED" in text or "FAIL" in text:
        return "CONTROL_FAILED"
    if "EVIDENCE" in text or "GROUND" in text:
        return "INSUFFICIENT_EVIDENCE"
    return "RUNTIME_ERROR"


def derive_confidence(runtime_state: Dict[str, Any]) -> float:
    result = safe_dict(runtime_state)
    confidence_scores = safe_dict(result.get("confidence_scores", {}))
    candidates = [
        result.get("confidence"),
        result.get("model_confidence"),
        result.get("overall_confidence"),
        confidence_scores.get("overall_confidence"),
        confidence_scores.get("confidence"),
    ]
    for row in result.get("agent_trace", []) or []:
        if isinstance(row, dict):
            candidates.append(row.get("confidence"))
            candidates.append(row.get("model_confidence"))
    values = [bounded_score(value, 0) for value in candidates if not is_unknown_value(value)]
    return round(sum(values) / len(values), 1) if values else 0.0


def derive_control_status(runtime_state: Dict[str, Any]) -> str:
    result = safe_dict(runtime_state)
    statuses = _control_statuses(result)
    error_code = normalize_error_code(result)
    if error_code in {"POLICY_BLOCKED"}:
        return "BLOCKED"
    if error_code in {"CONTROL_FAILED", "RUNTIME_ERROR"}:
        return "FAILED"
    if any(status in {"BLOCKED"} for status in statuses):
        return "BLOCKED"
    if any(status in {"FAIL", "FAILED", "NON_COMPLIANT"} for status in statuses):
        return "FAILED"
    if any(status in {"REVIEW", "REVIEW_REQUIRED"} for status in statuses):
        return "REVIEW"
    if statuses:
        return "PASS"
    return "REVIEW"


def derive_trust_score(runtime_state: Dict[str, Any]) -> float:
    result = safe_dict(runtime_state)
    existing = result.get("trust_score") if result.get("trust_score") is not None else safe_get(result.get("enterprise_trust"), "overall")
    if not is_unknown_value(existing):
        return bounded_score(existing, 0)
    evidence_count = safe_count(result.get("evidence_pack") or result.get("retrieved_chunks") or result.get("evidence_ids"))
    evidence_score = 100.0 if evidence_count > 0 else 0.0
    control_status = derive_control_status(result)
    control_score = {"PASS": 100.0, "REVIEW": 50.0, "BLOCKED": 0.0, "FAILED": 0.0}.get(control_status, 50.0)
    confidence_score = derive_confidence(result)
    error_code = normalize_error_code(result)
    error_score = 100.0 if error_code == "NONE" else 50.0 if error_code in RECOVERABLE_ERROR_CODES else 0.0
    event_contract = result.get("canonical_runtime_event_contract")
    if isinstance(event_contract, dict) and event_contract.get("required_fields"):
        missing = safe_count(event_contract.get("missing_required_fields"))
        required = max(1, safe_count(event_contract.get("required_fields")))
        trace_score = max(0.0, 100.0 * (required - missing) / required)
    else:
        trace_score = 100.0 if result.get("runtime_id") and result.get("app_id") else 50.0
    return round(
        evidence_score * 0.30
        + control_score * 0.30
        + confidence_score * 0.20
        + error_score * 0.10
        + trace_score * 0.10,
        1,
    )


def derive_risk_level(runtime_state: Dict[str, Any]) -> str:
    result = safe_dict(runtime_state)
    error_code = normalize_error_code(result)
    control_status = derive_control_status(result)
    trust_score = derive_trust_score(result)
    confidence = derive_confidence(result)
    severities = _finding_severities(result)
    evidence_total = evidence_count(result)
    if error_code in FATAL_ERROR_CODES or control_status == "BLOCKED" or "CRITICAL" in severities:
        return "CRITICAL"
    if control_status == "FAILED" or "HIGH" in severities or trust_score < 50 or confidence < 50:
        return "HIGH"
    if error_code in RECOVERABLE_ERROR_CODES or control_status == "REVIEW" or "MEDIUM" in severities or trust_score < 70 or confidence < 70:
        return "MEDIUM"
    if evidence_total > 0 and control_status == "PASS" and trust_score >= 70 and confidence >= 70:
        return "LOW"
    return "REVIEW"


def derive_final_recommendation(runtime_state: Dict[str, Any]) -> str:
    result = safe_dict(runtime_state)
    proposed = str(result.get("proposed_recommendation") or result.get("recommendation") or "").upper()
    risk_level = derive_risk_level(result)
    control_status = derive_control_status(result)
    error_code = normalize_error_code(result)
    trust_score = derive_trust_score(result)
    confidence = derive_confidence(result)
    if error_code == "POLICY_BLOCKED":
        return "REJECT"
    if risk_level in {"CRITICAL", "HIGH"} or control_status in {"FAILED", "BLOCKED"} or error_code in FATAL_ERROR_CODES:
        return "ESCALATE"
    if risk_level == "MEDIUM":
        return "MONITOR"
    if risk_level == "LOW" and control_status == "PASS" and trust_score >= 70 and confidence >= 70:
        return "APPROVE" if proposed not in {"REJECT", "ESCALATE"} else "REVIEW"
    return proposed if proposed in FINAL_RECOMMENDATIONS else "REVIEW"


def derive_customer_health(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    result = safe_dict(runtime_state)
    existing = safe_dict(result.get("customer_health"))
    trust_score = derive_trust_score(result)
    confidence = derive_confidence(result)
    relationship = round((trust_score * 0.60) + (confidence * 0.40), 1)
    anomalies = result.get("anomalies", [])
    anomaly_count = safe_count(anomalies) if isinstance(anomalies, list) else numeric_score(safe_dict(anomalies).get("anomaly_count", safe_dict(anomalies).get("count")), 0)
    engagement = round(max(0.0, 100.0 - (anomaly_count * 5.0)), 1)
    portfolio = round((relationship + engagement) / 2.0, 1)
    risk_score = numeric_score(result.get("risk_score", existing.get("risk_score")), 0)
    risk_inverse = max(0.0, 100.0 - risk_score)
    health_score = round((relationship * 0.35) + (portfolio * 0.30) + (engagement * 0.20) + (risk_inverse * 0.15), 1)
    status = "HEALTHY" if health_score >= 80 else "WATCH" if health_score >= 60 else "REVIEW"
    return {
        **existing,
        "relationship_score": relationship,
        "engagement_score": engagement,
        "portfolio_score": portfolio,
        "risk_score": risk_score,
        "health_score": health_score,
        "overall_score": health_score,
        "status": status,
        "calculation_source": "AEGIS_DERIVED",
        "relationship_formula": "trust_score * 0.60 + confidence * 0.40",
        "engagement_formula": "max(0, 100 - anomaly_count * 5)",
        "portfolio_formula": "(relationship_score + engagement_score) / 2",
        "health_formula": "relationship 35% + portfolio 30% + engagement 20% + risk inverse 15%",
    }


def canonical_quality_scores(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Return canonical trust, confidence, grounding, coverage, and hallucination."""
    result = safe_dict(runtime_state)
    reflection = safe_dict(result.get("reflection", {}))
    enterprise_trust = safe_dict(result.get("enterprise_trust", {}))
    hallucination_results = safe_dict(result.get("hallucination_results", {}))
    evaluation_results = safe_dict(result.get("evaluation_results", {}))
    ragas_scores = safe_dict(result.get("ragas_scores", result.get("ragas", {})))
    trust_score = derive_trust_score(result)
    confidence = derive_confidence(result)
    hallucination_score = (
        hallucination_results.get("hallucination_score")
        or reflection.get("hallucination_score")
        or enterprise_trust.get("hallucination")
        or evaluation_results.get("hallucination_score")
    )
    hallucination_risk = (
        result.get("hallucination_risk")
        or hallucination_results.get("risk_level")
        or hallucination_results.get("hallucination_risk")
        or reflection.get("hallucination_risk")
        or "-"
    )
    groundedness = (
        reflection.get("groundedness_score")
        or result.get("groundedness_score")
        or ragas_scores.get("faithfulness")
        or enterprise_trust.get("grounding")
    )
    coverage = reflection.get("coverage_score") or result.get("coverage_score") or ragas_scores.get("context_recall")
    return {
        "trust_score": bounded_score(trust_score, 0),
        "confidence": bounded_score(confidence, 0),
        "hallucination_score": None if hallucination_score is None else bounded_score(hallucination_score, 0),
        "hallucination_risk": hallucination_risk,
        "groundedness": None if groundedness is None else bounded_score(groundedness, 0),
        "coverage": None if coverage is None else bounded_score(coverage, 0),
    }


def runtime_recommendation_and_risk(runtime_state: Dict[str, Any]) -> Tuple[str, str]:
    result = safe_dict(runtime_state)
    canonical = safe_dict(result.get("canonical_display"))
    if canonical.get("recommendation") and canonical.get("risk_level"):
        return str(canonical["recommendation"]).upper(), str(canonical["risk_level"]).upper()
    return derive_final_recommendation(result), derive_risk_level(result)


def canonical_compliance_status(runtime_state: Dict[str, Any]) -> str:
    result = safe_dict(runtime_state)
    value = (
        safe_get(result.get("compliance"), "compliance_status")
        or safe_get(result.get("compliance"), "status")
        or safe_get(result.get("governance_authority"), "compliance_status")
        or safe_get(result.get("recommendation_package"), "compliance_status")
        or safe_get(result.get("executive_package"), "compliance_status")
        or safe_get(result.get("decision_snapshot"), "compliance_status")
    )
    if value in (None, "", "UNKNOWN"):
        recommendation, _ = runtime_recommendation_and_risk(result)
        value = {
            "APPROVE": "COMPLIANT",
            "MONITOR": "REVIEW_REQUIRED",
            "ESCALATE": "NON_COMPLIANT",
        }.get(recommendation, "REVIEW_REQUIRED")
    return str(value).upper()


def _control_statuses(runtime_state: Dict[str, Any]) -> List[str]:
    result = safe_dict(runtime_state)
    statuses: List[str] = []
    for key in ("control_status", "governance_status", "compliance_status"):
        value = result.get(key)
        if not is_unknown_value(value):
            statuses.append(str(value).upper())
    for container_name in ("governance", "governance_authority", "compliance", "recommendation_package"):
        container = safe_dict(result.get(container_name))
        for key in ("control_status", "status", "governance_status", "compliance_status"):
            value = container.get(key)
            if not is_unknown_value(value):
                statuses.append(str(value).upper())
    for row in result.get("agent_trace", []) or []:
        if not isinstance(row, dict):
            continue
        value = row.get("control_status")
        if not is_unknown_value(value):
            statuses.append(str(value).upper())
    return statuses


def derive_hitl_required(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Derive the authoritative AEGIS human-in-the-loop routing decision."""
    result = safe_dict(runtime_state)
    recommendation, risk_level = runtime_recommendation_and_risk(result)
    quality = canonical_quality_scores(result)
    confidence = numeric_score(quality.get("confidence"), 0)
    trust_score = numeric_score(quality.get("trust_score"), 0)
    control_statuses = _control_statuses(result)

    reasons: List[Tuple[str, str]] = []
    if risk_level in HITL_RISK_STATES:
        reasons.append(("Risk", f"Risk level is {risk_level}."))
    if confidence < HITL_CONFIDENCE_FLOOR:
        reasons.append(("Confidence", f"Confidence is {confidence:.1f}, below {HITL_CONFIDENCE_FLOOR:.0f}."))
    if trust_score < HITL_TRUST_FLOOR:
        reasons.append(("Trust", f"Trust score is {trust_score:.1f}, below {HITL_TRUST_FLOOR:.0f}."))
    failed_controls = [status for status in control_statuses if status in HITL_CONTROL_FAILURE_STATES]
    if failed_controls:
        reasons.append(("Control Status", f"Control status requires review: {', '.join(sorted(set(failed_controls)))}."))
    if recommendation in HITL_RECOMMENDATIONS:
        reasons.append(("Recommendation", f"Recommendation is {recommendation}."))

    return {
        "hitl_required": bool(reasons),
        "human_review_required": bool(reasons),
        "decision_source": "AEGIS_DERIVED",
        "confidence_floor": HITL_CONFIDENCE_FLOOR,
        "trust_floor": HITL_TRUST_FLOOR,
        "reasons": reasons,
    }


def governance_release_assessment(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    result = safe_dict(runtime_state)
    recommendation, risk_level = runtime_recommendation_and_risk(result)
    compliance_status = canonical_compliance_status(result)
    evidence_total = evidence_count(result)
    quality = canonical_quality_scores(result)
    publication_gate = safe_dict(result.get("publication_gate"))
    hitl = derive_hitl_required(result)
    clean_approved_case = (
        recommendation == "APPROVE"
        and risk_level == "LOW"
        and compliance_status in {"COMPLIANT", "PASS"}
        and evidence_total > 0
    )

    reasons: List[Tuple[str, str]] = []
    if recommendation != "APPROVE" and recommendation not in HITL_RECOMMENDATIONS:
        reasons.append(("Recommendation", f"Proposed recommendation is {recommendation}, not APPROVE."))
    if risk_level in RELEASE_RISK_STATES and risk_level not in HITL_RISK_STATES and not clean_approved_case:
        reasons.append(("Risk", f"Risk authority is {risk_level}, which requires review."))
    if compliance_status not in {"COMPLIANT", "PASS"}:
        reasons.append(("Compliance", f"Compliance status is {compliance_status}."))
    if evidence_total <= 0:
        reasons.append(("Evidence", "No customer-scoped evidence objects are available."))
    if quality.get("trust_score", 0) < 50 and not clean_approved_case:
        reasons.append(("Trust", f"Trust score is {quality.get('trust_score', 0):.1f}, below the release floor."))

    gate_status = str(publication_gate.get("status") or "").upper()
    block_reason = publication_gate.get("block_reason")
    if gate_status == "BLOCKED" or (publication_gate.get("release_allowed") is False and not is_unknown_value(block_reason)):
        reasons.append(("Publication Gate", str(block_reason or "Publication gate did not allow release.")))

    for reason in hitl["reasons"]:
        if reason not in reasons:
            reasons.append(reason)

    auto_release = clean_approved_case and not reasons and not hitl["hitl_required"]
    return {
        "review_required": bool(hitl["hitl_required"] or not auto_release),
        "hitl_required": bool(hitl["hitl_required"] or not auto_release),
        "hitl_decision_source": hitl["decision_source"],
        "release_allowed": auto_release,
        "release_route": "RELEASE" if auto_release else "PENDING HITL",
        "governance_status": "PASS" if auto_release else "REVIEW",
        "rationale": "All auto-release controls passed." if auto_release else "Human review required because one or more release controls need sign-off.",
        "reasons": reasons,
    }


def canonical_display_payload(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    result = safe_dict(runtime_state)
    existing = result.get("canonical_display")
    if isinstance(existing, dict) and existing:
        return dict(existing)
    quality = canonical_quality_scores(result)
    recommendation, risk_level = runtime_recommendation_and_risk(result)
    token = safe_dict(result.get("token_metrics") or safe_get(result.get("runtime_telemetry"), "token_metrics"))
    return {
        "trust_score": quality["trust_score"],
        "confidence": quality["confidence"],
        "risk_level": risk_level,
        "recommendation": recommendation,
        "final_recommendation": recommendation,
        "control_status": derive_control_status(result),
        "error_code": normalize_error_code(result),
        "evidence_count": evidence_count(result),
        "runtime_status": str(result.get("runtime_status") or result.get("status") or "UNKNOWN").upper(),
        "estimated_cost_usd": round(numeric_score(token.get("estimated_cost_usd", result.get("estimated_cost_usd", 0)), 0), 6),
        "cost_source": "token_metrics.estimated_cost_usd",
    }


def agent_counts(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    rows = [row for row in safe_dict(runtime_state).get("agent_trace", []) or [] if isinstance(row, dict)]
    executed_statuses = {"COMPLETED", "SUCCESS", "SUCCEEDED", "FAILED", "ERROR", "SKIPPED"}
    executed = sum(1 for row in rows if str(row.get("status") or "").upper() in executed_statuses)
    latency_ms = sum(numeric_score(row.get("duration_ms") or row.get("execution_time_ms") or row.get("latency_ms"), 0) for row in rows)
    return {"total": len(rows), "executed": executed, "failed": sum(1 for row in rows if str(row.get("status") or "").upper() in {"FAILED", "ERROR"}), "latency_ms": latency_ms}


def canonical_object_audit_rows(runtime_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    recommendation, risk_level = runtime_recommendation_and_risk(runtime_state)
    quality = canonical_quality_scores(runtime_state)
    compliance_status = canonical_compliance_status(runtime_state)
    release = governance_release_assessment(runtime_state)
    counts = agent_counts(runtime_state)
    review_required = bool(release["review_required"])
    approved = recommendation == "APPROVE" and not review_required
    rows = [
        ("Recommendation", recommendation, "Terminal decision reconciliation"),
        ("Risk Level", risk_level, "Canonical risk authority"),
        ("Human Review Required", "YES" if review_required else "NO", "HITL authority"),
        ("Approved", "YES" if approved else "NO", "Derived from APPROVE and no HITL"),
        ("Compliance Status", compliance_status, "Canonical compliance status"),
        ("Governance Status", release["governance_status"], "Canonical governance status"),
        ("Release Route", release["release_route"], "Effective release assessment"),
        ("Trust Score", f"{quality['trust_score']:.1f}", "Canonical 0-100 score"),
        ("Confidence", f"{quality['confidence']:.1f}", "Canonical 0-100 score"),
        ("Grounding", "-" if quality["groundedness"] is None else f"{quality['groundedness']:.1f}", "Canonical 0-100 score"),
        ("Coverage", "-" if quality["coverage"] is None else f"{quality['coverage']:.1f}", "Canonical 0-100 score"),
        ("Evidence Objects", evidence_count(runtime_state), "Customer-scoped evidence"),
        ("Agents Executed", f"{counts['executed']}/{counts['total']}", "Canonical agent count"),
        ("Total Execution Time Ms", round(counts["latency_ms"], 1), "Observed agent runtime"),
    ]
    return [{"Object": label, "Canonical Value": value, "Authority": authority} for label, value, authority in rows]


def canonical_consistency_audit_rows(runtime_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = safe_dict(runtime_state)
    display = canonical_display_payload(result)
    compliance_status = canonical_compliance_status(result)
    release = governance_release_assessment(result)
    expected = {
        "recommendation": display["recommendation"],
        "final_recommendation": display["recommendation"],
        "decision": display["recommendation"],
        "risk_level": display["risk_level"],
        "final_recommendation": display["final_recommendation"],
        "control_status": display["control_status"],
        "error_code": display["error_code"],
        "compliance_status": compliance_status,
        "trust_score": round(numeric_score(display["trust_score"]), 1),
        "confidence": round(numeric_score(display["confidence"]), 1),
        "overall_confidence": round(numeric_score(display["confidence"]), 1),
        "evidence_count": display["evidence_count"],
        "runtime_status": display["runtime_status"],
        "estimated_cost_usd": display["estimated_cost_usd"],
        "hitl_required": bool(release["review_required"]),
        "human_review_required": bool(release["review_required"]),
    }
    containers = (
        "executive_package",
        "executive_narrative",
        "recommendation_package",
        "decision_snapshot",
        "governance",
        "governance_authority",
        "compliance",
        "runtime_health",
        "runtime_health_v2",
        "control_tower_summary",
        "runtime_telemetry",
        "confidence_scores",
        "enterprise_trust",
        "canonical_values",
    )
    rows: List[Dict[str, Any]] = []
    for container_name in containers:
        container = result.get(container_name)
        if not isinstance(container, dict):
            continue
        for field, canonical in expected.items():
            if field not in container or is_unknown_value(container.get(field)):
                continue
            observed = container.get(field)
            matches = _values_match(field, observed, canonical)
            rows.append({
                "Object": container_name,
                "Field": field,
                "Displayed Value": observed,
                "Canonical Value": canonical,
                "Status": "CONSISTENT" if matches else "MISMATCH",
            })
    return rows


def _values_match(field: str, observed: Any, canonical: Any) -> bool:
    if field in {"trust_score", "confidence", "overall_confidence"}:
        return round(numeric_score(observed), 1) == round(numeric_score(canonical), 1)
    if field == "estimated_cost_usd":
        return round(numeric_score(observed), 6) == round(numeric_score(canonical), 6)
    if field == "evidence_count":
        return safe_count(observed) == safe_count(canonical)
    if field in {"hitl_required", "human_review_required"}:
        return bool(observed) == bool(canonical)
    return str(observed).upper() == str(canonical).upper()


def measure_control_tower_objects(
    runtime_state: Dict[str, Any] | None = None,
    runtime_events: Iterable[Dict[str, Any]] | None = None,
    defaults: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build portable canonical Control Tower measurements.

    External systems may provide a full AEGIS-like runtime_state, a list of
    emitted runtime_events, or both. The return payload is stable JSON-friendly
    data suitable for dashboards, audit stores, CI checks, or GRC integration.
    """
    state = deepcopy(runtime_state) if isinstance(runtime_state, dict) else {}
    event_contract = ingest_runtime_events(runtime_events, defaults) if runtime_events is not None else events_from_agent_trace(state)
    display = canonical_display_payload(state)
    quality = canonical_quality_scores(state)
    compliance_status = canonical_compliance_status(state)
    release = governance_release_assessment(state)
    rows = canonical_object_audit_rows(state)
    consistency = canonical_consistency_audit_rows(state)
    mismatches = [row for row in consistency if row.get("Status") == "MISMATCH"]
    return {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "runtime_id": state.get("runtime_id") or safe_get(defaults, "runtime_id") or "UNKNOWN_RUNTIME",
        "app_id": state.get("app_id") or safe_get(defaults, "app_id") or "UNKNOWN_APP",
        "canonical_display": display,
        "quality": quality,
        "compliance_status": compliance_status,
        "release_assessment": release,
        "canonical_object_audit": rows,
        "canonical_consistency_audit": consistency,
        "canonical_consistency_status": "CONSISTENT" if not mismatches else "MISMATCH",
        "canonical_consistency_mismatch_count": len(mismatches),
        "runtime_event_contract": event_contract,
    }


def attach_control_tower_measurements(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of runtime_state enriched with reusable Control Tower objects."""
    state = deepcopy(runtime_state) if isinstance(runtime_state, dict) else {}
    measurements = measure_control_tower_objects(state)
    release = measurements["release_assessment"]
    state["canonical_display"] = measurements["canonical_display"]
    state["canonical_values"] = {
        **safe_dict(state.get("canonical_values")),
        **measurements["canonical_display"],
        "cost_basis": "Token telemetry / configured rate card. Execution time is not used for cost allocation.",
    }
    state["canonical_object_audit"] = measurements["canonical_object_audit"]
    state["canonical_consistency_audit"] = measurements["canonical_consistency_audit"]
    state["canonical_control_tower_measurements"] = measurements
    state["canonical_runtime_event_contract"] = measurements["runtime_event_contract"]
    state["customer_health"] = derive_customer_health(state)
    state["hitl_required"] = bool(release["hitl_required"])
    state["human_review_required"] = bool(release["hitl_required"])
    state["hitl_decision"] = "HITL_REQUIRED" if release["hitl_required"] else "AUTO_RELEASE_ALLOWED"
    state["hitl_decision_source"] = release["hitl_decision_source"]
    state["hitl_reasons"] = release["reasons"]
    state["trust_score"] = measurements["quality"]["trust_score"]
    state["confidence"] = measurements["quality"]["confidence"]
    state["risk_level"] = measurements["canonical_display"]["risk_level"]
    state["recommendation"] = measurements["canonical_display"]["final_recommendation"]
    state["final_recommendation"] = measurements["canonical_display"]["final_recommendation"]
    state["control_status"] = measurements["canonical_display"]["control_status"]
    state["error_code"] = measurements["canonical_display"]["error_code"]
    state["evidence_count"] = measurements["canonical_display"]["evidence_count"]
    state["estimated_cost_usd"] = measurements["canonical_display"]["estimated_cost_usd"]
    return state
