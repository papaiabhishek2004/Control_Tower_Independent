"""
============================================================
AEGIS Control Tower Summary Service
Enterprise Command Center Aggregation Layer
============================================================
"""

from datetime import datetime
from typing import Dict, Any


# ============================================================
# Main Service
# ============================================================

def generate_control_tower_summary(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    try:

        executive_snapshot = runtime_state.get(
            "executive_snapshot",
            {}
        )

        runtime_health = runtime_state.get(
            "runtime_health_v2",
            {}
        )

        token_metrics = runtime_state.get(
            "token_metrics",
            {}
        )

        trust_score = runtime_state.get(
            "trust_score",
            0
        )

        confidence = runtime_state.get(
            "confidence",
            0
        )

        recommendation = runtime_state.get(
            "recommendation",
            "UNKNOWN"
        )

        anomalies = runtime_state.get(
            "anomalies",
            {}
        )

        hitl_decision = runtime_state.get(
            "hitl_decision",
            {}
        )

        security_analysis = runtime_state.get(
            "security_analysis",
            {}
        )

        graph_metrics = runtime_state.get(
            "graph_metrics",
            {}
        )

        trust_evolution = runtime_state.get(
            "trust_evolution",
            {}
        )

        telemetry = runtime_state.get(
            "runtime_telemetry",
            {}
        )

        executive_narrative = runtime_state.get(
            "executive_narrative",
            {}
        )

        platform_score = _calculate_platform_score(

            trust_score,
            confidence,
            runtime_health

        )

        platform_status = _determine_status(
            platform_score
        )

        runtime_status = runtime_state.get(
            "runtime_status", runtime_state.get("status", "UNKNOWN")
        )
        current_phase = runtime_state.get("current_phase")
        if not current_phase:
            timeline = runtime_state.get("execution_timeline", [])
            current_phase = timeline[-1].get("phase") if timeline else "UNKNOWN"
        transactions = runtime_state.get("transactions")
        transaction_count = (
            len(transactions) if isinstance(transactions, list)
            else runtime_state.get("customer_runtime", {}).get("transactions")
        )
        recommendation_package = runtime_state.get("recommendation_package", {})

        return {

            "summary_id":
                f"CTS-{datetime.now().strftime('%Y%m%d%H%M%S')}",

            "generated_at":
                datetime.now().isoformat(),

            "platform_score":
                platform_score,

            "platform_status":
                platform_status,

            "operational_snapshot": {
                "runtime_status": runtime_status,
                "current_phase": current_phase,
                "transaction_count": transaction_count,
                "agent_events": len(runtime_state.get("agent_trace", [])),
                "timeline_events": len(runtime_state.get("execution_timeline", [])),
            },

            "decision_authority": {
                "mode": recommendation_package.get("decision_mode", "AUTOMATED"),
                "human_review_required": bool(
                    runtime_state.get("hitl_required")
                    or recommendation_package.get("human_review_required")
                ),
                "confidence_threshold": recommendation_package.get("confidence_threshold", 60),
                "decision_reason": recommendation_package.get("escalation_reason"),
            },

            "executive_summary":

                _build_executive_summary(

                    recommendation,
                    trust_score,
                    confidence

                ),

            "kpi_snapshot": {

                "trust_score":
                    trust_score,

                "confidence":
                    confidence,

                "recommendation":
                    recommendation,

                "health_score":

                    runtime_health.get(
                        "health_score",
                        0
                    ),

                "total_tokens":

                    token_metrics.get(
                        "total_tokens",
                        0
                    ),

                "anomaly_count":

                    anomalies.get(
                        "anomaly_count",
                        0
                    )

            },

            "executive_snapshot":
                executive_snapshot,

            "runtime_health":
                runtime_health,

            "security_analysis":
                security_analysis,

            "graph_metrics":
                graph_metrics,

            "trust_evolution":
                trust_evolution,

            "telemetry":
                telemetry,

            "hitl_decision":
                hitl_decision,

            "executive_narrative":
                executive_narrative

        }

    except Exception as ex:

        return {

            "status":
                "ERROR",

            "error":
                str(ex)

        }


# ============================================================
# Platform Score
# ============================================================

def _calculate_platform_score(

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
# Status
# ============================================================

def _determine_status(
    score
) -> str:

    if score >= 90:

        return "EXCELLENT"

    if score >= 75:

        return "HEALTHY"

    if score >= 60:

        return "WARNING"

    return "CRITICAL"


# ============================================================
# Executive Summary
# ============================================================

def _build_executive_summary(

    recommendation,
    trust_score,
    confidence

) -> str:

    return (

        f"Recommendation: {recommendation}. "

        f"Trust Score: {trust_score}%. "

        f"Confidence: {confidence}%. "

        f"Enterprise runtime completed "

        f"successfully."

    )


# ============================================================
# Dashboard Snapshot
# ============================================================

def build_dashboard_snapshot(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    summary = generate_control_tower_summary(
        runtime_state
    )

    return {

        "platform_score":
            summary.get(
                "platform_score",
                0
            ),

        "platform_status":
            summary.get(
                "platform_status",
                "UNKNOWN"
            ),

        "recommendation":

            summary.get(
                "kpi_snapshot",
                {}
            ).get(
                "recommendation",
                "UNKNOWN"
            ),

        "trust_score":

            summary.get(
                "kpi_snapshot",
                {}
            ).get(
                "trust_score",
                0
            ),

        "confidence":

            summary.get(
                "kpi_snapshot",
                {}
            ).get(
                "confidence",
                0
            )

    }


# ============================================================
# Runtime Wrapper
# ============================================================

def build_control_tower_summary(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    return generate_control_tower_summary(
        runtime_state
    )
