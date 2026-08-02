"""OWASP AI query validation for onboarded application user queries."""

from __future__ import annotations

import re
from typing import Any, Dict, List


PROMPT_INJECTION_PATTERNS = {
    "ignore_instructions": r"\b(ignore|forget|disregard)\b.{0,40}\b(previous|prior|system|developer)\b.{0,40}\b(instruction|message|prompt|rules?)\b",
    "system_prompt_exfiltration": r"\b(reveal|show|print|dump|expose)\b.{0,40}\b(system prompt|developer message|hidden instruction|policy)\b",
    "jailbreak": r"\b(jailbreak|bypass policy|bypass safety|do anything now|dan mode|developer mode)\b",
    "tool_exfiltration": r"\b(call|use|invoke)\b.{0,40}\b(unauthorized|external|shell|powershell|cmd|terminal)\b",
}
PII_PATTERNS = {
    "email_address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone_like_number": r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{10})\b",
    "india_pan_like_identifier": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "india_aadhaar_like_identifier": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
}
DATA_EXFILTRATION_PATTERNS = {
    "credential_request": r"\b(password|secret|api key|token|credential|private key)\b",
    "bulk_export": r"\b(export|dump|download|exfiltrate)\b.{0,40}\b(all|entire|database|customer data|records)\b",
}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _query_candidates(runtime_state: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for key in ("user_query", "original_query", "query", "objective"):
        value = runtime_state.get(key)
        if value not in (None, "", "-"):
            rows.append({"source": f"runtime_state.{key}", "query": str(value)})
    events = _safe_list(runtime_state.get("canonical_runtime_events"))
    events.extend(_safe_list(runtime_state.get("runtime_events")))
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            continue
        for key in ("user_query", "original_query", "query", "prompt"):
            value = event.get(key)
            if value not in (None, "", "-"):
                rows.append({"source": f"event[{index}].{key}", "query": str(value)})
    seen = set()
    unique = []
    for row in rows:
        marker = (row["source"], row["query"])
        if marker not in seen:
            seen.add(marker)
            unique.append(row)
    return unique


def _matches(patterns: Dict[str, str], text: str, category: str, severity: str) -> List[Dict[str, str]]:
    findings = []
    for code, pattern in patterns.items():
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            findings.append({
                "category": category,
                "code": code.upper(),
                "severity": severity,
                "finding": code.replace("_", " "),
            })
    return findings


def validate_user_queries(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Validate onboarded-app user queries against OWASP AI query risks."""
    state = runtime_state if isinstance(runtime_state, dict) else {}
    queries = _query_candidates(state)
    findings = []
    for row in queries:
        text = row["query"]
        row_findings = []
        row_findings.extend(_matches(PROMPT_INJECTION_PATTERNS, text, "Prompt Injection / Jailbreak", "HIGH"))
        row_findings.extend(_matches(PII_PATTERNS, text, "Sensitive Data / PII", "CRITICAL"))
        row_findings.extend(_matches(DATA_EXFILTRATION_PATTERNS, text, "Data Exfiltration", "CRITICAL"))
        for finding in row_findings:
            finding["source"] = row["source"]
            finding["query_excerpt"] = text[:180]
        findings.extend(row_findings)

    status = "PASS" if not findings else "FAIL" if any(row["severity"] == "CRITICAL" for row in findings) else "REVIEW"
    score = 100 if not findings else max(0, 100 - min(90, len(findings) * 25))
    result = {
        "status": status,
        "score": score,
        "query_count": len(queries),
        "findings": findings,
        "owasp_controls": ["LLM01 Prompt Injection", "LLM02 Sensitive Information Disclosure", "LLM06 Sensitive Information Disclosure", "LLM07 Insecure Plugin/Tool Design"],
        "rationale": "No unsafe user-query patterns detected." if not findings else f"{len(findings)} unsafe user-query finding(s) detected.",
    }
    state["query_security"] = result
    return result
