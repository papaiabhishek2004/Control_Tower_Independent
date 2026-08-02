"""
============================================================
AEGIS Runtime Telemetry Service
Enterprise Runtime Observability Engine
============================================================
"""

from datetime import datetime
from typing import Dict, Any
from services1.llm_runtime import invoke_reasoning_agent


def _numeric_score(value: Any) -> float:
    if isinstance(value, dict):
        value = value.get("overall", value.get("score", value.get("value", 0)))
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


# ============================================================
# Main Service
# ============================================================

def generate_runtime_telemetry(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    try:

        trust_score = _numeric_score(runtime_state.get(
            "trust_score",
            0
        ))

        confidence = _numeric_score(runtime_state.get(
            "confidence",
            0
        ))

        token_metrics = runtime_state.get(
            "token_metrics",
            {}
        )

        runtime_health = runtime_state.get(
            "runtime_health_v2",
            {}
        )

        graph_metrics = runtime_state.get(
            "graph_metrics",
            {}
        )

        executive_snapshot = runtime_state.get(
            "executive_snapshot",
            {}
        )

        execution_timeline = runtime_state.get(
            "execution_timeline",
            []
        )

        cache_metrics = _build_cache_metrics(
            runtime_state
        )

        latency_metrics = _build_latency_metrics(
            runtime_state
        )

        cost_metrics = _build_cost_metrics(
            token_metrics
        )

        health_summary = _build_health_summary(
            runtime_health,
            trust_score,
            confidence
        )

        telemetry_score = _calculate_telemetry_score(
            trust_score,
            confidence,
            runtime_health
        )

        # ============================================================
        # ENTERPRISE RUNTIME MONITORING AGENT
        # ============================================================

        runtime_prompt = f"""
You are an Enterprise Runtime Monitoring Agent.

Review the operational health of the execution.

Return ONLY valid JSON.

{{
    "executive_summary":"",
    "runtime_health":"",
    "performance_assessment":"",
    "operational_risks":[],
    "recommended_actions":[],
    "confidence":0
}}

Telemetry Score:
{telemetry_score}

Trust Score:
{trust_score}

Confidence:
{confidence}

Runtime Health:
{runtime_health}

Latency Metrics:
{latency_metrics}

Cache Metrics:
{cache_metrics}

Cost Metrics:
{cost_metrics}

Execution Events:
{len(execution_timeline)}
"""

        runtime_llm = invoke_reasoning_agent(

            agent_name="Runtime Monitoring Agent",

            system_prompt="Enterprise Runtime Monitoring Expert",

            user_prompt=runtime_prompt,

            runtime_state=runtime_state,

            expect_json=True

        )

        if runtime_state is not None:

            runtime_state.setdefault(
                "agents",
                {}
            )

            runtime_state["agents"]["runtime_monitor"] = {

                "agent_name":
                    "Runtime Monitoring Agent",

                "phase":
                    "Runtime",

                "status":
                    "COMPLETED"
                    if runtime_llm.get("success")
                    else "FAILED",

                "model":
                    runtime_llm.get("model"),

                "provider":
                    runtime_llm.get("provider"),

                "timestamp":
                    runtime_llm.get("timestamp"),

                "confidence":
                    runtime_llm.get(
                        "parsed_output",
                        {}
                    ).get(
                        "confidence",
                        0
                    ),

                "parsed_output":
                    runtime_llm.get(
                        "parsed_output",
                        {}
                    ),

                "raw_response":
                    runtime_llm.get(
                        "raw_response",
                        ""
                    )

            }

                    # ============================================================
            # ENTERPRISE RUNTIME CONTRACT REGISTRATION
            # ============================================================

            runtime_state["runtime_telemetry"] = {

                "telemetry_score": telemetry_score,

                "generated_at": datetime.now().isoformat(),

                "execution_events": len(execution_timeline),

                "runtime_health": runtime_health,

                "health_summary": health_summary

            }

            runtime_state["runtime_metrics"] = {

                "telemetry_score": telemetry_score,

                "trust_score": trust_score,

                "confidence": confidence,

                "execution_events": len(execution_timeline)

            }

            runtime_state["runtime_statistics"] = {

                "agent_count": len(

                    runtime_state.get(

                        "agents",

                        {}

                    )

                ),

                "llm_calls": len(

                    runtime_state.get(

                        "llm_trace",

                        []

                    )

                ),

                "execution_events": len(

                    execution_timeline

                )

            }

            runtime_state["performance_metrics"] = latency_metrics

            runtime_state["latency_metrics"] = latency_metrics

            runtime_state["cache_metrics"] = cache_metrics

            runtime_state["cost_metrics"] = cost_metrics

            runtime_state["runtime_health"] = runtime_health

            runtime_state["runtime_summary"] = {

                "telemetry_score": telemetry_score,

                "trust_score": trust_score,

                "confidence": confidence,

                "overall_health": health_summary.get(

                    "overall_status",

                    "UNKNOWN"

                ),

                "health_score": health_summary.get(

                    "health_score",

                    0

                )

            }

            runtime_state["runtime_monitor"] = {

                "status": runtime_state["agents"]["runtime_monitor"]["status"],

                "generated_at": datetime.now().isoformat(),

                "telemetry_score": telemetry_score

            }

            runtime_state["runtime_monitor_summary"] = (

                runtime_llm.get(

                    "parsed_output",

                    {}

                ).get(

                    "executive_summary",

                    ""

                )

            )

            runtime_state["runtime_monitor_health"] = health_summary

            runtime_state["runtime_monitor_runtime"] = {

                "provider": runtime_llm.get(

                    "provider",

                    ""

                ),

                "model": runtime_llm.get(

                    "model",

                    ""

                ),

                "timestamp": runtime_llm.get(

                    "timestamp",

                    datetime.now().isoformat()

                )

            }

            runtime_state["runtime_monitor_trace"] = {

                "service": "Runtime Telemetry Service",

                "phase": "Runtime",

                "status": runtime_state["agents"]["runtime_monitor"]["status"],

                "timestamp": datetime.now().isoformat()

            }

            runtime_state["runtime_monitor_confidence"] = (

                runtime_llm.get(

                    "parsed_output",

                    {}

                ).get(

                    "confidence",

                    0

                )

            )

            runtime_state["runtime_monitor_success"] = runtime_llm.get(

                "success",

                False

            )

            runtime_state["runtime_monitor_duration_ms"] = runtime_llm.get(

                "latency_ms",

                0

            )

            runtime_state["runtime_monitor_generated_at"] = datetime.now().isoformat()

            runtime_state["runtime_monitor_llm"] = runtime_llm

            runtime_state.setdefault(

                "dashboard_metrics",

                {}

            )

            runtime_state["dashboard_metrics"]["runtime"] = {

                "telemetry_score": telemetry_score,

                "trust_score": trust_score,

                "confidence": confidence,

                "health": health_summary.get(

                    "overall_status",

                    "UNKNOWN"

                ),

                "execution_events": len(execution_timeline)

            }

            runtime_state["control_tower_summary"] = {

                "runtime_status": runtime_state["agents"]["runtime_monitor"]["status"],

                "telemetry_score": telemetry_score,

                "trust_score": trust_score,

                "confidence": confidence,

                "health": health_summary.get(

                    "overall_status",

                    "UNKNOWN"

                )

            }








        return {

            "telemetry_id":
                f"TEL-{datetime.now().strftime('%Y%m%d%H%M%S')}",

            "generated_at":
                datetime.now().isoformat(),

            "telemetry_score":
                telemetry_score,

            "trust_score":
                trust_score,

            "confidence":
                confidence,

            "token_metrics":
                token_metrics,

            "cost_metrics":
                cost_metrics,

            "cache_metrics":
                cache_metrics,

            "latency_metrics":
                latency_metrics,

            "runtime_health":
                runtime_health,

            "health_summary":
                health_summary,

            "graph_metrics":
                graph_metrics,

            "execution_events":
                len(execution_timeline),

            "executive_snapshot":
                executive_snapshot,

            "runtime_llm":
                runtime_llm,

            "agents":
                runtime_state.get(
                    "agents",
                    {}
                )

        }

    except Exception as ex:

        return {

            "status":
                "ERROR",

            "error":
                str(ex)

        }
# ============================================================
# Cache Metrics
# ============================================================

def _build_cache_metrics(
    runtime_state
) -> Dict[str, Any]:

    retrieval_cache = runtime_state.get(
        "retrieval_cache_hits",
        0
    )

    query_cache = runtime_state.get(
        "query_cache_hits",
        0
    )

    response_cache = runtime_state.get(
        "response_cache_hits",
        0
    )

    total_hits = (

        retrieval_cache +
        query_cache +
        response_cache

    )

    return {

        "retrieval_cache_hits":
            retrieval_cache,

        "query_cache_hits":
            query_cache,

        "response_cache_hits":
            response_cache,

        "total_cache_hits":
            total_hits

    }


# ============================================================
# Latency Metrics
# ============================================================

def _build_latency_metrics(
    runtime_state
) -> Dict[str, Any]:

    agent_trace = runtime_state.get(
        "agent_trace",
        []
    )

    durations = []

    for agent in agent_trace:

        if isinstance(agent, dict):

            durations.append(

                agent.get(
                    "duration_ms",
                    0
                )

            )

    avg_latency = 0

    if durations:

        avg_latency = round(

            sum(durations) /
            len(durations),

            2

        )

    return {

        "average_latency_ms":
            avg_latency,

        "max_latency_ms":
            max(durations)
            if durations
            else 0,

        "min_latency_ms":
            min(durations)
            if durations
            else 0

    }


# ============================================================
# Cost Metrics
# ============================================================

def _build_cost_metrics(
    token_metrics
) -> Dict[str, Any]:

    total_tokens = token_metrics.get(
        "total_tokens",
        0
    )

    estimated_cost = token_metrics.get(
        "estimated_cost_usd",
        0
    )

    return {

        "total_tokens":
            total_tokens,

        "estimated_cost_usd":
            estimated_cost,

        "cost_per_1k_tokens":
            0.005

    }


# ============================================================
# Health Summary
# ============================================================

def _build_health_summary(

    runtime_health,
    trust_score,
    confidence

) -> Dict[str, Any]:

    health_score = runtime_health.get(
        "health_score",
        0
    )

    overall = "HEALTHY"

    if health_score < 80:

        overall = "WARNING"

    if health_score < 60:

        overall = "CRITICAL"

    return {

        "overall_status":
            overall,

        "health_score":
            health_score,

        "trust_score":
            trust_score,

        "confidence":
            confidence

    }


# ============================================================
# Telemetry Score
# ============================================================

def _calculate_telemetry_score(

    trust_score,
    confidence,
    runtime_health

) -> float:

    health_score = runtime_health.get(
        "health_score",
        0
    )

    score = (

        trust_score * 0.40 +

        confidence * 0.30 +

        health_score * 0.30

    )

    return round(
        score,
        2
    )


# ============================================================
# Executive KPI View
# ============================================================

def build_kpi_snapshot(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    telemetry = generate_runtime_telemetry(
        runtime_state
    )

    return {

        "telemetry_score":
            telemetry.get(
                "telemetry_score",
                0
            ),

        "trust_score":
            telemetry.get(
                "trust_score",
                0
            ),

        "confidence":
            telemetry.get(
                "confidence",
                0
            ),

        "health_score":

            telemetry.get(
                "health_summary",
                {}
            ).get(
                "health_score",
                0
            ),

        "estimated_cost":

            telemetry.get(
                "cost_metrics",
                {}
            ).get(
                "estimated_cost_usd",
                0
            )

    }


# ============================================================
# Runtime Wrapper
# ============================================================

def collect_runtime_telemetry(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    return generate_runtime_telemetry(
        runtime_state
    )
