"""Policy-as-code evaluator for AEGIS governance controls."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


POLICY_VERSION = "AEGIS-POLICY-2026.07"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "aegis_policy.json"


DEFAULT_POLICY: Dict[str, Any] = {
    "policy_version": POLICY_VERSION,
    "trust_min_for_auto_approval": 70.0,
    "confidence_min_for_auto_approval": 60.0,
    "minimum_evidence_count": 1,
    "max_agent_execution_time_ms": 120000,
    "max_retries": 3,
    "block_on_owasp_fail": True,
    "block_on_pii": True,
    "require_hitl_for_risk_levels": ["HIGH", "CRITICAL", "REVIEW_REQUIRED", "INSUFFICIENT_EVIDENCE", "CUSTOMER_NOT_FOUND", "UNKNOWN"],
    "allowed_recommendations": ["APPROVE", "MONITOR", "ESCALATE"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _flatten_findings(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        rows = [value]
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                rows.extend(_flatten_findings(nested))
        return rows
    if isinstance(value, list):
        rows: List[Dict[str, Any]] = []
        for item in value:
            rows.extend(_flatten_findings(item))
        return rows
    return []


def _status_is_blocking(value: Any) -> bool:
    return str(value or "").strip().upper() in {"FAIL", "FAILED", "BLOCK", "BLOCKED", "CRITICAL", "HIGH"}


def _blocking_security_reasons(*payloads: Any) -> List[str]:
    reasons: List[str] = []
    for finding in _flatten_findings(list(payloads)):
        status = finding.get("status") or finding.get("verdict") or finding.get("result")
        severity = finding.get("severity") or finding.get("risk") or finding.get("risk_level")
        finding_text = json.dumps(finding, default=str).lower()
        explicit_no_security_signal = any(
            term in finding_text
            for term in (
                "no signal detected",
                "no security finding",
                "no prompt injection",
                "no jailbreak",
                "no unsafe tool",
                "not detected",
            )
        )
        if (_status_is_blocking(status) or _status_is_blocking(severity)) and any(
            term in finding_text
            for term in ("prompt injection", "jailbreak", "data exfiltration", "unsafe tool", "owasp", "security")
        ) and not explicit_no_security_signal:
            label = (
                finding.get("control")
                or finding.get("owasp_control")
                or finding.get("category")
                or finding.get("judge")
                or finding.get("name")
                or "Security finding"
            )
            detail = (
                finding.get("finding")
                or finding.get("findings")
                or finding.get("rationale")
                or finding.get("reason")
                or finding.get("description")
                or f"status={status or '-'}, severity={severity or '-'}"
            )
            reasons.append(f"{label}: {detail}")
    return reasons[:5]


def _has_blocking_security_finding(*payloads: Any) -> bool:
    return bool(_blocking_security_reasons(*payloads))


def _blocking_pii_reasons(*payloads: Any) -> List[str]:
    reasons: List[str] = []
    for finding in _flatten_findings(list(payloads)):
        status = finding.get("status") or finding.get("verdict") or finding.get("result")
        severity = finding.get("severity") or finding.get("risk") or finding.get("risk_level")
        finding_text = json.dumps(finding, default=str).lower()
        has_pii_signal = any(term in finding_text for term in ("pii leak", "pii detected", "payment card", "credit card", "aadhaar", "pan-like"))
        explicit_no_leak = any(term in finding_text for term in ("no pii", "pii clear", "no pii leakage", "not detected"))
        if has_pii_signal and not explicit_no_leak and (_status_is_blocking(status) or _status_is_blocking(severity)):
            label = finding.get("control") or finding.get("category") or finding.get("judge") or "PII finding"
            detail = finding.get("finding") or finding.get("findings") or finding.get("rationale") or finding.get("reason") or f"status={status or '-'}, severity={severity or '-'}"
            reasons.append(f"{label}: {detail}")
    return reasons[:5]


def _has_blocking_pii_finding(*payloads: Any) -> bool:
    return bool(_blocking_pii_reasons(*payloads))


def load_policy() -> Dict[str, Any]:
    configured = os.getenv("AEGIS_POLICY_CONFIG")
    path = Path(configured) if configured else CONFIG_PATH
    policy = dict(DEFAULT_POLICY)
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                policy.update(loaded)
        except Exception:
            policy["config_error"] = f"Unable to parse policy file: {path}"
    return policy


def evaluate_policy_as_code(runtime_state: Dict[str, Any], policy: Dict[str, Any] | None = None) -> Dict[str, Any]:
    policy = policy or load_policy()
    recommendation = str(runtime_state.get("recommendation") or "").upper()
    risk_level = str(runtime_state.get("risk_level") or runtime_state.get("risk_profile", {}).get("risk_level") or "UNKNOWN").upper()
    trust = _num(runtime_state.get("trust_score"))
    confidence = _num(runtime_state.get("confidence"))
    evidence_count = len(runtime_state.get("evidence_pack", []) or runtime_state.get("retrieved_chunks", []) or [])
    agent_trace = [row for row in runtime_state.get("agent_trace", []) or [] if isinstance(row, dict)]
    owasp = runtime_state.get("owasp_ai") if isinstance(runtime_state.get("owasp_ai"), dict) else {}
    security = runtime_state.get("security_analysis") if isinstance(runtime_state.get("security_analysis"), dict) else {}
    judge = runtime_state.get("llm_judge_assurance", {}) if isinstance(runtime_state.get("llm_judge_assurance"), dict) else {}

    checks: List[Dict[str, Any]] = []

    def add(policy_id: str, passed: bool, severity: str, actual: Any, expected: Any, action: str) -> None:
        checks.append({
            "policy_id": policy_id,
            "passed": bool(passed),
            "severity": severity,
            "actual": actual,
            "expected": expected,
            "action": action,
        })

    add("POLICY_TRUST_THRESHOLD", trust >= _num(policy.get("trust_min_for_auto_approval"), 70), "HIGH", trust, f">= {policy.get('trust_min_for_auto_approval')}", "Route to HITL if trust is below threshold.")
    add("POLICY_CONFIDENCE_THRESHOLD", confidence >= _num(policy.get("confidence_min_for_auto_approval"), 60), "HIGH", confidence, f">= {policy.get('confidence_min_for_auto_approval')}", "Route to HITL if confidence is below threshold.")
    add("POLICY_EVIDENCE_MINIMUM", evidence_count >= int(policy.get("minimum_evidence_count", 1)), "HIGH", evidence_count, f">= {policy.get('minimum_evidence_count')}", "Require more evidence or block publication.")
    add("POLICY_RECOMMENDATION_ALLOWED", recommendation in set(policy.get("allowed_recommendations", [])), "MEDIUM", recommendation, policy.get("allowed_recommendations"), "Normalize or review recommendation.")
    add("POLICY_RISK_HITL", risk_level not in set(policy.get("require_hitl_for_risk_levels", [])), "CRITICAL", risk_level, f"not in {policy.get('require_hitl_for_risk_levels')}", "Route to human review.")
    security_reasons = _blocking_security_reasons(owasp, security, judge)
    pii_reasons = _blocking_pii_reasons(owasp, security, judge)
    blocking_security = bool(security_reasons)
    blocking_pii = bool(pii_reasons)
    add("POLICY_OWASP_BLOCK", not (policy.get("block_on_owasp_fail") and blocking_security), "CRITICAL", "; ".join(security_reasons) if blocking_security else "no blocking finding", "no blocking OWASP/security finding", "Block release and escalate.")
    add("POLICY_PII_BLOCK", not (policy.get("block_on_pii") and blocking_pii), "CRITICAL", "; ".join(pii_reasons) if blocking_pii else "no blocking PII finding", "no PII leakage signal", "Block release and escalate.")

    slow_agents = [
        row.get("agent") or row.get("agent_name")
        for row in agent_trace
        if _num(row.get("duration_ms") or row.get("latency_ms")) > _num(policy.get("max_agent_execution_time_ms"), 120000)
    ]
    add("POLICY_AGENT_LATENCY", not slow_agents, "MEDIUM", slow_agents, f"<= {policy.get('max_agent_execution_time_ms')} ms", "Flag runtime performance review.")

    retry_breaches = [
        row.get("agent") or row.get("agent_name")
        for row in agent_trace
        if _num(row.get("retry_count")) > _num(policy.get("max_retries"), 3)
    ]
    add("POLICY_RETRY_LIMIT", not retry_breaches, "HIGH", retry_breaches, f"<= {policy.get('max_retries')} retries", "Route to HITL after retry exhaustion.")

    failed = [row for row in checks if not row["passed"]]
    critical_failed = [row for row in failed if row["severity"] == "CRITICAL"]
    release_allowed = not critical_failed and not runtime_state.get("hitl_required")
    return {
        "policy_version": policy.get("policy_version", POLICY_VERSION),
        "created_at": _now(),
        "status": "PASS" if not failed else "REVIEW" if not critical_failed else "BLOCK",
        "release_allowed": bool(release_allowed),
        "hitl_required": bool(failed or runtime_state.get("hitl_required")),
        "failed_count": len(failed),
        "critical_failed_count": len(critical_failed),
        "checks": checks,
        "policy": policy,
    }
