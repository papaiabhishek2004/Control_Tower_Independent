"""
============================================================
AEGIS Runtime Health Service
Enterprise Runtime Monitoring Layer
============================================================
"""

from datetime import datetime
from typing import Dict, Any


# ============================================================
# Main Service
# ============================================================

def generate_runtime_health(
        runtime_state: Dict[str, Any]
    ) -> Dict[str, Any]:

        """
        Enterprise Runtime Health Service V2
        """

        try:


            agent_trace = _normalize_agent_trace(
                runtime_state.get("agent_trace")
                or runtime_state.get("agent_runtime")
                or runtime_state.get("execution_trace")
                or runtime_state.get("agents")
                or []
            )

            execution_timeline = runtime_state.get(
                "execution_timeline",
                []
            )

            runtime_summary = runtime_state.get(
                "runtime_summary",
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

            total_agents = len(agent_trace)

            successful_agents = _count_successful_agents(
                agent_trace
            )

            failed_agents = max(
                0,
                total_agents - successful_agents
            )

            success_rate = round(

                (
                    successful_agents /
                    max(total_agents, 1)

                ) * 100,

                2

            )

            avg_latency_ms = _calculate_avg_latency(
                agent_trace
            )

            runtime_status = _determine_runtime_status(
                success_rate,
                failed_agents
            )

            health_score = _calculate_health_score(
                success_rate,
                avg_latency_ms
            )

            if health_score >= 90:
                health_level = "EXCELLENT"

            elif health_score >= 80:
                health_level = "GOOD"

            elif health_score >= 60:
                health_level = "WARNING"

            else:
                health_level = "CRITICAL"

            warnings = []

            if failed_agents > 0:

                warnings.append(
                    f"{failed_agents} agent(s) failed"
                )

            if avg_latency_ms > 3000:

                warnings.append(
                    "High runtime latency"
                )

            if trust_score < 70:

                warnings.append(
                    "Low Trust Score"
                )

            if confidence < 70:

                warnings.append(
                    "Low Confidence"
                )

            result = {

                "health_id":
                    f"HEALTH-{datetime.now().strftime('%Y%m%d%H%M%S')}",

                "generated_at":
                    datetime.now().isoformat(),

                "status":
                    runtime_status,

                "health_level":
                    health_level,

                "health_score":
                    health_score,

                "trust_score":
                    trust_score,

                "confidence":
                    confidence,

                "recommendation":
                    recommendation,

                "total_agents":
                    total_agents,

                "successful_agents":
                    successful_agents,

                "failed_agents":
                    failed_agents,

                "agent_success_rate":
                    success_rate,

                "avg_latency_ms":
                    avg_latency_ms,

                "timeline_events":
                    len(execution_timeline),

                "execution_status":
                    runtime_summary.get(
                        "status",
                        "COMPLETED"
                    ),

                "warnings":
                    warnings,

                "summary":{

                    "Runtime Health":
                        health_level,

                    "Agent Success":
                        success_rate,

                    "Trust":
                        trust_score,

                    "Confidence":
                        confidence,

                    "Latency":
                        avg_latency_ms

                }

            }

            runtime_state["runtime_health"] = result

            return result

        except Exception as ex:

            return {

                "status":"ERROR",

                "health_score":0,

                "error":str(ex)

            }

# ============================================================
# Successful Agents
# ============================================================

def _count_successful_agents(
    agent_trace
) -> int:

    count = 0

    for agent in agent_trace:

        if isinstance(agent, dict):

            status = str(agent.get(
                "status",
                "SUCCESS"
            )).upper()

            if status in {
                "SUCCESS",
                "COMPLETED",
                "COMPLETE",
                "PASS",
                "PASSED",
                "HEALTHY"
            }:

                count += 1

        else:

            count += 1

    return count


# ============================================================
# Agent Trace Normalization
# ============================================================

def _normalize_agent_trace(
    agent_trace
):

    if isinstance(agent_trace, list):

        return agent_trace

    if isinstance(agent_trace, dict):

        normalized = []

        for name, payload in agent_trace.items():

            if isinstance(payload, dict):

                row = payload.copy()

                row.setdefault(
                    "agent",
                    row.get("agent_name", name)
                )

                row.setdefault(
                    "status",
                    row.get("runtime_status", "COMPLETED")
                )

                normalized.append(row)

            else:

                normalized.append({
                    "agent": name,
                    "status": "COMPLETED",
                    "details": payload
                })

        return normalized

    return []


# ============================================================
# Average Latency
# ============================================================

def _calculate_avg_latency(
    agent_trace
) -> float:

    durations = []

    for agent in agent_trace:

        if isinstance(agent, dict):

            durations.append(

                agent.get(
                    "duration_ms",
                    0
                )

            )

    if not durations:

        return 0

    return round(

        sum(durations) /
        len(durations),

        2

    )


# ============================================================
# Runtime Status
# ============================================================

def _determine_runtime_status(
    success_rate,
    failed_agents
) -> str:

    if failed_agents > 0:

        return "DEGRADED"

    if success_rate >= 95:

        return "HEALTHY"

    if success_rate >= 80:

        return "WARNING"

    return "CRITICAL"


# ============================================================
# Health Score
# ============================================================

def _calculate_health_score(
    success_rate,
    avg_latency
) -> float:

    latency_score = 100

    if avg_latency > 5000:

        latency_score = 50

    elif avg_latency > 3000:

        latency_score = 70

    elif avg_latency > 1000:

        latency_score = 85

    return round(

        (
            success_rate * 0.70 +
            latency_score * 0.30
        ),

        2

    )


# ============================================================
# Runtime Wrapper
# ============================================================

def monitor_runtime_health(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    return generate_runtime_health(
        runtime_state
    )
