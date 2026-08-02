"""
============================================================
AEGIS Token Telemetry Service
Enterprise LLM Telemetry Layer
============================================================
"""

from datetime import datetime
from typing import Dict, Any



# ============================================================
# Main Service
# ============================================================

def generate_token_metrics(
        runtime_state: Dict[str, Any]
    ) -> Dict[str, Any]:

        try:

            query = runtime_state.get(
                "query",
                ""
            )

            response = runtime_state.get(
                "final_response",
                ""
            )

            retrieved_chunks = runtime_state.get(
                "retrieved_chunks",
                []
            )

            evidence_pack = runtime_state.get(
                "evidence_pack",
                []
            )

            agent_trace = runtime_state.get(
                "agent_trace",
                []
            )

            provider = runtime_state.get(
                "provider",
                "UNKNOWN"
            )

            model = runtime_state.get(
                "model",
                "UNKNOWN"
            )

            runtime_id = runtime_state.get(
                "runtime_id",
                "-"
            )

            # ----------------------------------------------------
            # Token Estimates
            # ----------------------------------------------------

            prompt_tokens = _estimate_prompt_tokens(
                query,
                retrieved_chunks
            )

            completion_tokens = _estimate_completion_tokens(
                response
            )

            embedding_tokens = _estimate_embedding_tokens(
                retrieved_chunks,
                evidence_pack
            )

            total_tokens = (

                prompt_tokens +

                completion_tokens +

                embedding_tokens

            )

            estimated_cost = _estimate_cost(
                total_tokens
            )

            token_efficiency = _calculate_efficiency(

                total_tokens,

                len(agent_trace)

            )

            status = _determine_status(
                total_tokens
            )

            avg_tokens_per_agent = round(

                total_tokens /

                max(

                    len(agent_trace),

                    1

                ),

                2

            )

            result = {

                "telemetry_id":

                    f"TOKEN-{datetime.now().strftime('%Y%m%d%H%M%S')}",

                "generated_at":

                    datetime.now().isoformat(),

                "runtime_id":

                    runtime_id,

                "provider":

                    provider,

                "model":

                    model,

                "status":

                    status,

                "prompt_tokens":

                    prompt_tokens,

                "completion_tokens":

                    completion_tokens,

                "embedding_tokens":

                    embedding_tokens,

                "total_tokens":

                    total_tokens,

                "estimated_cost_usd":

                    estimated_cost,

                "token_efficiency":

                    token_efficiency,

                "agents":

                    len(agent_trace),

                "avg_tokens_per_agent":

                    avg_tokens_per_agent,

                "summary":{

                    "Provider":

                        provider,

                    "Model":

                        model,

                    "Total Tokens":

                        total_tokens,

                    "Prompt":

                        prompt_tokens,

                    "Completion":

                        completion_tokens,

                    "Embedding":

                        embedding_tokens,

                    "Cost":

                        estimated_cost,

                    "Efficiency":

                        token_efficiency

                }

            }

            runtime_state["token_telemetry"] = result

            return result

        except Exception as ex:

            return {

                "status":"ERROR",

                "prompt_tokens":0,

                "completion_tokens":0,

                "embedding_tokens":0,

                "total_tokens":0,

                "estimated_cost_usd":0,

                "token_efficiency":0,

                "error":str(ex)

            }
# ============================================================
# Prompt Tokens
# ============================================================

def _estimate_prompt_tokens(
    query,
    retrieved_chunks
) -> int:

    query_tokens = len(
        str(query).split()
    ) * 1.3

    chunk_tokens = 0

    if isinstance(
        retrieved_chunks,
        list
    ):

        for chunk in retrieved_chunks:

            chunk_tokens += (
                len(str(chunk).split())
                * 1.3
            )

    return int(
        query_tokens +
        chunk_tokens
    )


# ============================================================
# Completion Tokens
# ============================================================

def _estimate_completion_tokens(
    response
) -> int:

    if not response:

        return 0

    return int(
        len(
            str(response).split()
        ) * 1.3
    )


# ============================================================
# Embedding Tokens
# ============================================================

def _estimate_embedding_tokens(
    retrieved_chunks,
    evidence_pack
) -> int:

    chunk_tokens = 0

    if isinstance(
        retrieved_chunks,
        list
    ):

        for chunk in retrieved_chunks:

            chunk_tokens += (
                len(str(chunk).split())
                * 1.3
            )

    evidence_tokens = 0

    if isinstance(
        evidence_pack,
        list
    ):

        for evidence in evidence_pack:

            evidence_tokens += (
                len(str(evidence).split())
                * 1.3
            )

    return int(
        chunk_tokens +
        evidence_tokens
    )


# ============================================================
# Cost Estimation
# ============================================================

def _estimate_cost(
    total_tokens
) -> float:

    # Generic Enterprise Estimate
    # Adjust later per model

    cost_per_1k_tokens = 0.005

    return round(

        (
            total_tokens / 1000
        ) * cost_per_1k_tokens,

        4

    )


# ============================================================
# Efficiency
# ============================================================

def _calculate_efficiency(
    total_tokens,
    agent_count
) -> float:

    if total_tokens <= 0:

        return 0

    if agent_count <= 0:

        agent_count = 1

    efficiency = (

        100 -

        (
            total_tokens /
            (agent_count * 100)
        )

    )

    return round(
        max(0, min(100, efficiency)),
        2
    )


# ============================================================
# Status
# ============================================================

def _determine_status(
    total_tokens
) -> str:

    if total_tokens < 5000:

        return "HEALTHY"

    if total_tokens < 15000:

        return "WARNING"

    return "CRITICAL"


# ============================================================
# Runtime Wrapper
# ============================================================

def collect_token_telemetry(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    return generate_token_metrics(
        runtime_state
    )
