"""AEGIS RAGAS evaluation for the independent Control Tower."""

from __future__ import annotations

from datetime import datetime
import os
from typing import Any, Dict

LOCAL_ENV_FILE = __import__("pathlib").Path(__file__).resolve().parents[1] / ".env.local"


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _score(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    if 0 < number <= 1:
        number *= 100
    return round(max(0.0, min(100.0, number)), 2)


def _calculate_faithfulness(evidence_pack: list, trust_score: float) -> float:
    return round(min((trust_score * 0.70) + (min(len(evidence_pack), 20) * 1.5), 100.0), 2)


def _calculate_answer_relevancy(retrieved_chunks: list) -> float:
    return round(min(70.0 + (min(len(retrieved_chunks), 15) * 2.0), 100.0), 2)


def _calculate_context_precision(evidence_pack: list) -> float:
    return round(min(65.0 + (min(len(evidence_pack), 20) * 1.75), 100.0), 2)


def _calculate_context_recall(retrieved_chunks: list) -> float:
    return round(min(60.0 + (min(len(retrieved_chunks), 20) * 2.0), 100.0), 2)


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


def _ragas_provider_order() -> list:
    raw = _local_env_value("AEGIS_RAGAS_PROVIDER_ORDER", _local_env_value("AEGIS_LLM_PROVIDER_ORDER", "LOCAL,GROQ,DETERMINISTIC"))
    order = []
    for item in [part.strip().upper() for part in raw.split(",") if part.strip()]:
        normalized = "LOCAL" if item in {"QWEN", "QWEN_LOCAL", "LOCAL_QWEN"} else item
        if normalized in {"GROQ", "LOCAL", "DETERMINISTIC"} and normalized not in order:
            order.append(normalized)
    return order or ["LOCAL", "GROQ", "DETERMINISTIC"]


def _fallback_ragas_llm(provider: str, model: str, error: str, summary: str) -> Dict[str, Any]:
    return {
        "success": False,
        "provider": provider,
        "model": model,
        "latency_ms": 0,
        "parsed_output": {
            "executive_summary": summary,
            "quality_assessment": "LLM_UNAVAILABLE",
            "strengths": [],
            "weaknesses": [error],
            "recommended_actions": ["Check Groq/local Qwen configuration and rerun AEGIS."],
            "confidence": 0,
        },
        "error": error,
    }


def _invoke_local_ragas_llm(prompt: str, state: Dict[str, Any]) -> Dict[str, Any]:
    model = _local_env_value("AEGIS_LOCAL_RAGAS_MODEL", "QWEN_LOCAL")
    try:
        from services1.llm_runtime import invoke_reasoning_agent  # type: ignore
        response = invoke_reasoning_agent(
            agent_name="RAGAS Evaluation Agent",
            system_prompt="Enterprise RAG Quality Evaluator. Return only valid JSON.",
            user_prompt=prompt,
            temperature=0.0,
            max_tokens=int(_local_env_value("AEGIS_RAGAS_MAX_TOKENS", "700")),
            expect_json=True,
            runtime_state=state,
        )
        if isinstance(response, dict) and response.get("success"):
            response.setdefault("provider", "LOCAL")
            response.setdefault("model", _safe_dict(response.get("telemetry")).get("model", model))
            return response
        return _fallback_ragas_llm(
            "LOCAL",
            model,
            str(_safe_dict(response).get("error") or _safe_dict(response).get("content") or "Local Qwen returned unsuccessful response"),
            "RAGAS local LLM evaluation failed.",
        )
    except Exception as exc:
        return _fallback_ragas_llm("LOCAL", model, f"LOCAL_QWEN_UNAVAILABLE: {exc}", "RAGAS local LLM evaluation failed.")


def _invoke_groq_ragas_llm(prompt: str, state: Dict[str, Any]) -> Dict[str, Any]:
    groq_key = _local_env_value("GROQ_API_KEY")
    if not groq_key:
        return _fallback_ragas_llm("GROQ", "RAGAS_LLM_REQUIRED", "GROQ_API_KEY_REQUIRED_FOR_MANDATORY_RAGAS", "RAGAS Groq evaluation skipped because GROQ_API_KEY is not configured.")
    os.environ.setdefault("GROQ_API_KEY", groq_key)
    timeout_seconds = int(os.getenv("AEGIS_RAGAS_LLM_TIMEOUT_SECONDS", "20"))
    try:
        from groq import Groq
    except Exception as exc:
        return _fallback_ragas_llm("GROQ", "RAGAS_LLM_REQUIRED", f"GROQ_PACKAGE_UNAVAILABLE: {exc}", "RAGAS Groq evaluation failed because the Groq package is unavailable.")

    model = _local_env_value("AEGIS_GROQ_RAGAS_MODEL", _local_env_value("AEGIS_GROQ_JUDGE_MODEL", "llama-3.1-8b-instant"))
    start = datetime.now()
    try:
        client = Groq(api_key=groq_key, timeout=timeout_seconds)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Enterprise RAG Quality Evaluator. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=700,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        import json
        parsed = json.loads(content)
        latency_ms = int((datetime.now() - start).total_seconds() * 1000)
        return {
            "success": True,
            "provider": "GROQ",
            "model": model,
            "latency_ms": latency_ms,
            "content": content,
            "parsed_output": parsed if isinstance(parsed, dict) else {},
        }
    except Exception as exc:
        latency_ms = int((datetime.now() - start).total_seconds() * 1000)
        return {
            "success": False,
            "provider": "GROQ",
            "model": model,
            "latency_ms": latency_ms,
            "parsed_output": {
                "executive_summary": "RAGAS LLM evaluation failed.",
                "quality_assessment": "LLM_ERROR",
                "strengths": [],
                "weaknesses": [str(exc)],
                "recommended_actions": ["Review GROQ_API_KEY, network access, model name, and retry."],
                "confidence": 0,
            },
            "error": str(exc),
        }


def _invoke_ragas_llm(prompt: str, state: Dict[str, Any]) -> Dict[str, Any]:
    attempts = []
    for provider in _ragas_provider_order():
        if provider == "DETERMINISTIC":
            break
        response = _invoke_groq_ragas_llm(prompt, state) if provider == "GROQ" else _invoke_local_ragas_llm(prompt, state)
        if isinstance(response, dict) and response.get("success"):
            response["provider_attempts"] = attempts
            return response
        attempts.append({
            "provider": provider,
            "status": "FAILED",
            "error": str(_safe_dict(response).get("error") or "provider returned unsuccessful response")[:500],
        })
    result = _fallback_ragas_llm(
        "DETERMINISTIC",
        "AEGIS_DETERMINISTIC_RAGAS_FALLBACK",
        "All configured RAGAS LLM providers failed.",
        "RAGAS LLM providers failed; deterministic RAGAS scores were used for continuity.",
    )
    result["provider_attempts"] = attempts
    result["deterministic_fallback_used"] = True
    return result


def generate_ragas_scores(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Run mandatory RAGAS-style LLM evaluation with deterministic score basis."""
    state = runtime_state if isinstance(runtime_state, dict) else {}
    validated_chunks = _safe_list(state.get("validated_evidence") or state.get("retrieved_chunks"))
    evidence_pack = _safe_list(state.get("evidence_pack"))
    retrieval_judge = _safe_dict(state.get("retrieval_judge"))
    evidence_validation = _safe_dict(state.get("evidence_validation"))
    crag = _safe_dict(state.get("crag"))
    trust = state.get("trust_score")
    if isinstance(trust, dict):
        trust = trust.get("overall", 0)
    trust_value = _score(trust)

    faithfulness = _calculate_faithfulness(evidence_pack, trust_value)
    answer_relevancy = _calculate_answer_relevancy(validated_chunks)
    context_precision = _calculate_context_precision(evidence_pack)
    context_recall = _calculate_context_recall(validated_chunks)
    overall_score = round(
        faithfulness * 0.30
        + answer_relevancy * 0.25
        + context_precision * 0.20
        + context_recall * 0.15
        + _score(retrieval_judge.get("confidence")) * 0.05
        + trust_value * 0.05,
        2,
    )

    prompt = f"""
You are the Enterprise RAGAS Evaluation Agent for AEGIS Control Tower.
Evaluate the onboarded app runtime using RAGAS dimensions:
faithfulness, answer relevancy, context precision, context recall, retrieval judge,
evidence validator, CRAG, and trust score.

Return ONLY valid JSON:
{{
  "executive_summary": "",
  "quality_assessment": "",
  "strengths": [],
  "weaknesses": [],
  "recommended_actions": [],
  "confidence": 0
}}

Scores:
faithfulness={faithfulness}
answer_relevancy={answer_relevancy}
context_precision={context_precision}
context_recall={context_recall}
overall_score={overall_score}
trust_score={trust_value}
retrieval_judge_confidence={retrieval_judge.get("confidence", 0)}
evidence_validator_recommendation={evidence_validation.get("recommendation", "UNKNOWN")}
crag_status={crag.get("status", "UNKNOWN")}
validated_evidence_count={len(validated_chunks)}
evidence_pack_count={len(evidence_pack)}
"""

    ragas_llm = _invoke_ragas_llm(prompt, state)
    parsed = _safe_dict(ragas_llm.get("parsed_output"))
    if not ragas_llm.get("success"):
        status = "FAIL"
    else:
        status = "PASS" if overall_score >= 80 else "REVIEW" if overall_score >= 65 else "FAIL"
    now = datetime.now().isoformat()
    result = {
        "evaluation_id": f"RAGAS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": now,
        "status": status,
        "overall_score": overall_score,
        "faithfulness": faithfulness,
        "answer_relevancy": answer_relevancy,
        "context_precision": context_precision,
        "context_recall": context_recall,
        "confidence": _score(parsed.get("confidence")),
        "executive_summary": parsed.get("executive_summary") or "RAGAS evaluation completed.",
        "quality_assessment": parsed.get("quality_assessment") or status,
        "strengths": parsed.get("strengths") if isinstance(parsed.get("strengths"), list) else [],
        "weaknesses": parsed.get("weaknesses") if isinstance(parsed.get("weaknesses"), list) else [],
        "recommended_actions": parsed.get("recommended_actions") if isinstance(parsed.get("recommended_actions"), list) else [],
        "ragas_llm": ragas_llm,
    }

    state["ragas_scores"] = result
    state["ragas"] = {
        "overall_score": overall_score,
        "faithfulness": faithfulness,
        "answer_relevancy": answer_relevancy,
        "context_precision": context_precision,
        "context_recall": context_recall,
    }
    state["ragas_llm"] = ragas_llm
    state["ragas_success"] = bool(ragas_llm.get("success"))
    state["ragas_duration_ms"] = ragas_llm.get("latency_ms", 0)
    state["ragas_generated_at"] = now
    state.setdefault("agents", {})["ragas"] = {
        "agent_name": "RAGAS Evaluation Agent",
        "phase": "AI Evaluation",
        "status": "COMPLETED" if ragas_llm.get("success") else "FAILED",
        "provider": ragas_llm.get("provider", "UNKNOWN"),
        "model": ragas_llm.get("model", "UNKNOWN"),
        "overall_score": overall_score,
    }
    state.setdefault("agent_trace", []).append({
        "agent_name": "RAGAS Evaluation Agent",
        "phase": "AI Evaluation",
        "status": state["agents"]["ragas"]["status"],
        "confidence": result["confidence"],
        "overall_score": overall_score,
        "timestamp": now,
        "event_type": "RAGAS_EVALUATED",
    })
    return result


def evaluate_rag_quality(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    return generate_ragas_scores(runtime_state)
