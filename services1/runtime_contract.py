"""
============================================================
AEGIS AI CONTROL TOWER
Enterprise Runtime Contract
Single Source of Truth
============================================================
"""
"""
============================================================
AEGIS ENTERPRISE RUNTIME CONTRACT GUIDELINES
============================================================

PURPOSE
-------
This file defines the single source of truth for the AEGIS
Enterprise Runtime State.

Every service MUST read from and write to this contract.

No service should create arbitrary runtime keys.

============================================================
RUNTIME CONTRACT RULES
============================================================

1. Every service owns only its own runtime section.

   Example:
       Retrieval Service
           retrieval
           retrieval_summary
           retrieval_metrics
           retrieval_runtime

       Reflection Service
           reflection
           reflection_summary
           reflection_runtime

2. Never overwrite another service's runtime object.

3. Every service should populate:

       <service>

       <service>_summary

       <service>_metrics

       <service>_statistics

       <service>_health

       <service>_runtime

       <service>_trace

       <service>_confidence

       <service>_success

       <service>_duration_ms

       <service>_generated_at

       <service>_llm

4. Every service should register itself in:

       agents

       agent_trace

       llm_trace

5. Runtime objects must never be deleted.

6. Renderer should ONLY consume runtime_state.

7. Services should never directly update Streamlit UI.

8. All timestamps should use ISO format.

9. Durations should always be milliseconds.

10. Confidence scores should always be between 0 and 100.

11. Runtime should continue even if a service fails.
    Populate *_success=False and *_runtime with error details.

12. Every LLM invocation should populate:

       provider

       model

       latency_ms

       prompt_tokens

       completion_tokens

       total_tokens

       estimated_cost

       success

13. Every Agent should register:

       status

       confidence

       duration_ms

       provider

       model

       retries

       error

14. Runtime Summary is the ONLY object consumed by
    Executive Dashboard KPIs.

============================================================
END OF CONTRACT
============================================================
"""

from datetime import datetime



def create_runtime_state():

    return {

        # =====================================================
        # Runtime Metadata
        # Enterprise Runtime Lifecycle
        # =====================================================

        "runtime_id": None,

        "runtime_version": "V5",
        # =====================================================
        # Runtime Contract Metadata
        # =====================================================

        "runtime_contract": "AEGIS_ENTERPRISE_RUNTIME",

        "contract_version": "1.0",

        "schema_version": "1.0",

        "correlation_id": None,

        "session_id": None,

        "request_id": None,

        "trace_id": None,

        "runtime_name": "AEGIS Enterprise Runtime",

        "runtime_description": "Enterprise Agentic AI Investigation Runtime",

        "created_at": datetime.now().isoformat(),

        "started_at": None,

        "completed_at": None,

        "execution_time_seconds": 0.0,

        "status": "INITIALIZED",
        "current_phase": "INITIALIZATION",

        "current_agent": "",

        "completed_agents": [],

        "failed_agents": [],

        "remaining_agents": [],

        "mode": "LIVE",

        "environment": "PRODUCTION",

        "runtime_owner": "AEGIS",

        "platform": "AEGIS Control Tower",

        "execution_engine": "AEGIS Runtime Orchestrator V5",

        "runtime_health": {},

        "runtime_summary": {},

        "runtime_statistics": {},

        "runtime_metrics": {},

        "runtime_telemetry": {},

        "runtime_monitor": {},

        "runtime_monitor_summary": {},

        "runtime_monitor_llm": {},

        "runtime_configuration": {},

        "runtime_flags": {},

        "runtime_tags": [],

        "runtime_errors": [],

        "runtime_warnings": [],

        "runtime_events": [],

        "runtime_logs": [],

        "exceptions": [],

        "critical_errors": [],

        "recoverable_errors": [],

        "runtime_artifacts": [],

        # =====================================================
        # Investigation
        # =====================================================        # =====================================================
        # Investigation
        # =====================================================

        "customer_id": "",

        "investigation_id": "",

        "investigation_type": "",

        "case_id": "",

        "case_status": "OPEN",

        "analyst": "",

        "investigation_priority": "MEDIUM",

        "business_domain": "BANKING",
        "dataset_version": "",

        "knowledgebase_version": "",

        "embedding_model": "",

        "reranker_model": "",

        "llm_provider": "",

        "country": "",

        "region": "",

        "created_by": "",

        "assigned_to": "",

        "user_query": "",

        "original_query": "",

        "rewritten_query": "",

        "normalized_query": "",

        "query_language": "EN",

        "query_entities": [],

        "query_intent": {},

        "query_constraints": {},

        "query_metadata": {},

        # =====================================================
        # Query Rewrite Runtime
        # =====================================================

        "query_rewrite": {},

        "query_rewrite_summary": {},

        "query_rewrite_metrics": {},

        "query_rewrite_statistics": {},

        "query_rewrite_health": {},

        "query_rewrite_confidence": 0,

        "query_rewrite_success": False,

        "query_rewrite_duration_ms": 0,

        "query_rewrite_generated_at": None,

        "query_rewrite_llm": {},

        "query_rewrite_trace": [],

        "query_rewrite_prompt": {},

        "query_rewrite_response": {},

        "query_rewrite_validation": {},

        "query_rewrite_runtime": {},

        # =====================================================
        # Investigation Runtime
        # =====================================================

        "decision_snapshot": {},

        "investigation_summary": {},

        "investigation_metrics": {},

        "investigation_health": {},

        "investigation_statistics": {},

        "investigation_runtime": {},

        "investigation_trace": [],

        # =====================================================
        # Planner
        # =====================================================
        # =====================================================
        # Planner
        # =====================================================

        "planner": {},

        "planner_steps": [],

        "execution_plan": {},

        "planner_summary": {},

        "planner_metrics": {},

        "planner_statistics": {},

        "planner_health": {},

        "planner_runtime": {},

        "planner_trace": [],

        "planner_confidence": 0,

        "planner_success": False,

        "planner_duration_ms": 0,

        "planner_generated_at": None,

        "planner_llm": {},

        "planner_prompt": {},

        "planner_response": {},

        # =====================================================
        # Tool Router
        # =====================================================

        "routing": {},

        "selected_tools": [],

        "selected_agents": [],

        "tool_router": {},

        "tool_router_summary": {},

        "tool_router_metrics": {},

        "tool_router_statistics": {},

        "tool_router_health": {},

        "tool_router_runtime": {},

        "tool_router_trace": [],

        "tool_router_confidence": 0,

        "tool_router_success": False,

        "tool_router_duration_ms": 0,

        "tool_router_generated_at": None,

        "tool_router_llm": {},

        "tool_router_prompt": {},

        "tool_router_response": {},

        "tool_selection_reasoning": {},

        # =====================================================
        # Retrieval
        # =====================================================














        # =====================================================
        # Retrieval
        # =====================================================

        "retrieval": {

            "documents": [],

            "statistics": {},

            "metrics": {},

            "health": {},

            "timeline": []

        },

        "retrieved_chunks": [],

        "validated_chunks": [],

        "retrieval_summary": {},

        "retrieval_statistics": {},

        "retrieval_metrics": {},

        "retrieval_health": {},

        "retrieval_runtime": {},

        "retrieval_trace": [],

        "retrieval_confidence": 0,

        "retrieval_success": False,

        "retrieval_duration_ms": 0,

        "retrieval_generated_at": None,

        "retrieval_llm": {},

        "retrieval_prompt": {},

        "retrieval_response": {},

        "retrieval_timeline": [],

        # -----------------------------------------------------
        # Cross Encoder
        # -----------------------------------------------------

        "reranking": {},

        "cross_encoder": {},

        "cross_encoder_summary": {},

        "cross_encoder_metrics": {},

        "cross_encoder_statistics": {},

        "cross_encoder_health": {},

        "cross_encoder_runtime": {},

        "cross_encoder_trace": [],

        "cross_encoder_confidence": 0,

        "cross_encoder_success": False,

        "cross_encoder_duration_ms": 0,

        "cross_encoder_generated_at": None,

        "cross_encoder_llm": {},

        # -----------------------------------------------------
        # Retrieval Judge
        # -----------------------------------------------------

        "retrieval_judge": {},

        "retrieval_judge_summary": {},

        "retrieval_judge_metrics": {},

        "retrieval_judge_statistics": {},

        "retrieval_judge_health": {},

        "retrieval_judge_runtime": {},

        "retrieval_judge_trace": [],

        "retrieval_judge_confidence": 0,

        "retrieval_judge_success": False,

        "retrieval_judge_duration_ms": 0,

        "retrieval_judge_generated_at": None,

        "retrieval_judge_llm": {},

        # -----------------------------------------------------
        # CRAG
        # -----------------------------------------------------

        "crag": {},

        "crag_summary": {},

        "crag_metrics": {},

        "crag_statistics": {},

        "crag_health": {},

        "crag_runtime": {},

        "crag_trace": [],

        "crag_confidence": 0,

        "crag_success": False,

        "crag_duration_ms": 0,

        "crag_generated_at": None,

        "crag_llm": {},

        # =====================================================
        # Evidence
        # =====================================================






        # =====================================================
        # Evidence
        # =====================================================

        "evidence": {},

        "evidence_pack": [],

        "validated_evidence": [],

        "evidence_analysis": {},

        "evidence_summary": {},

        "evidence_metrics": {},

        "evidence_statistics": {},

        "evidence_health": {},

        "evidence_runtime": {},

        "evidence_trace": [],

        "evidence_confidence": 0,

        "evidence_success": False,

        "evidence_duration_ms": 0,

        "evidence_generated_at": None,

        "evidence_llm": {},

        # -----------------------------------------------------
        # Evidence Validator
        # -----------------------------------------------------

        "evidence_validation": {},

        "evidence_validation_summary": {},

        "evidence_validation_metrics": {},

        "evidence_validation_statistics": {},

        "evidence_validation_health": {},

        "evidence_validation_runtime": {},

        "evidence_validation_trace": [],

        "evidence_validation_confidence": 0,

        "evidence_validation_success": False,

        "evidence_validation_duration_ms": 0,

        "evidence_validation_generated_at": None,

        "evidence_validation_llm": {},

        # -----------------------------------------------------
        # Source Intelligence
        # -----------------------------------------------------

        "source_distribution": {},

        "knowledge_intelligence": {},

        "vector_analysis": {},

        "vector_inventory": {},

        "knowledge_health": {},

        "knowledge_summary": {},

        "knowledge_metrics": {},

        # -----------------------------------------------------
        # Citation Intelligence
        # -----------------------------------------------------

        "citations": [],

        "citation_summary": {},

        "citation_health": {},

        "citation_metrics": {},

        # =====================================================
        # Answer Generation
        # =====================================================

        "answer": {

            "text": "",

            "confidence": 0,

            "citations": [],

            "reasoning": ""

        },

        "answer_summary": {},

        "answer_metrics": {},

        "answer_statistics": {},

        "answer_health": {},

        "answer_runtime": {},

        "answer_trace": [],

        "answer_confidence": 0,

        "answer_success": False,

        "answer_duration_ms": 0,

        "answer_generated_at": None,

        "answer_llm": {},

        # =====================================================
        # Reflection
        # =====================================================






        # =====================================================
        # Enterprise AI Validation Layer
        # =====================================================

        # -----------------------------------------------------
        # Reflection
        # -----------------------------------------------------

        "reflection": {},

        "reflection_summary": {},

        "reflection_metrics": {},

        "reflection_statistics": {},

        "reflection_health": {},

        "reflection_runtime": {},

        "reflection_trace": [],

        "reflection_confidence": 0,

        "reflection_success": False,

        "reflection_duration_ms": 0,

        "reflection_generated_at": None,

        "reflection_llm": {},

        # -----------------------------------------------------
        # Grounding
        # -----------------------------------------------------

        "grounding": {},

        "grounding_summary": {},

        "grounding_metrics": {},

        "grounding_statistics": {},

        "grounding_health": {},

        "grounding_runtime": {},

        "grounding_trace": [],

        "grounding_confidence": 0,

        "grounding_success": False,

        "grounding_duration_ms": 0,

        "grounding_generated_at": None,

        "grounding_llm": {},

        # -----------------------------------------------------
        # Hallucination Detection
        # -----------------------------------------------------

        "hallucination": {},

        "hallucination_summary": {},

        "hallucination_metrics": {},

        "hallucination_statistics": {},

        "hallucination_health": {},

        "hallucination_runtime": {},

        "hallucination_trace": [],

        "hallucination_confidence": 0,

        "hallucination_success": False,

        "hallucination_duration_ms": 0,

        "hallucination_generated_at": None,

        "hallucination_llm": {},

        # -----------------------------------------------------
        # Evaluation
        # -----------------------------------------------------

        "evaluation": {},

        "evaluation_results": {},

        "evaluation_summary": {},

        "evaluation_metrics": {},

        "evaluation_statistics": {},

        "evaluation_health": {},

        "evaluation_runtime": {},

        "evaluation_trace": [],

        "evaluation_confidence": 0,

        "evaluation_success": False,

        "evaluation_duration_ms": 0,

        "evaluation_generated_at": None,

        "evaluation_llm": {},

        # -----------------------------------------------------
        # RAGAS
        # -----------------------------------------------------

        "ragas": {},

        "ragas_summary": {},

        "ragas_metrics": {},

        "ragas_statistics": {},

        "ragas_health": {},

        "ragas_runtime": {},

        "ragas_trace": [],

        "ragas_confidence": 0,

        "ragas_success": False,

        "ragas_duration_ms": 0,

        "ragas_generated_at": None,

        "ragas_llm": {},

        # -----------------------------------------------------
        # Enterprise Trust
        # -----------------------------------------------------

        "trust": {

            "score": 0,

            "confidence": 0

        },

        "trust_score": 0,

        "confidence": 0,

        "trust_summary": {},

        "trust_metrics": {},

        "trust_statistics": {},

        "trust_health": {},

        "trust_runtime": {},

        "trust_trace": [],

        "trust_success": False,

        "trust_duration_ms": 0,

        "trust_generated_at": None,

        "trust_llm": {},

        # =====================================================
        # Security & Governance
        # =====================================================
        # =====================================================
        # Enterprise Governance Layer
        # =====================================================

        # -----------------------------------------------------
        # Security
        # -----------------------------------------------------

        "security": {},

        "security_summary": {},

        "security_metrics": {},

        "security_statistics": {},

        "security_health": {},

        "security_runtime": {},

        "security_trace": [],

        "security_score": 0,

        "security_confidence": 0,

        "security_success": False,

        "security_duration_ms": 0,

        "security_generated_at": None,

        "security_llm": {},

        "failed_security_controls": [],

        "review_security_controls": [],

        "owasp_results": {},

        "owasp_compliance": 0,

        "security_recommendations": [],

        # -----------------------------------------------------
        # Governance
        # -----------------------------------------------------

        "governance": {},

        "governance_summary": {},

        "governance_metrics": {},

        "governance_statistics": {},

        "governance_health": {},

        "governance_runtime": {},

        "governance_trace": [],

        "governance_score": 0,

        "governance_confidence": 0,

        "governance_success": False,

        "governance_duration_ms": 0,

        "governance_generated_at": None,

        "governance_llm": {},

        # -----------------------------------------------------
        # Compliance
        # -----------------------------------------------------

        "compliance": {},

        "compliance_summary": {},

        "compliance_metrics": {},

        "compliance_statistics": {},

        "compliance_health": {},

        "compliance_runtime": {},

        "compliance_trace": [],

        "compliance_score": 0,

        "compliance_confidence": 0,

        "compliance_success": False,

        "compliance_duration_ms": 0,

        "compliance_generated_at": None,

        "compliance_llm": {},

        # -----------------------------------------------------
        # Audit
        # -----------------------------------------------------

        "audit": {},

        "audit_summary": {},

        "audit_metrics": {},

        "audit_statistics": {},

        "audit_health": {},

        "audit_runtime": {},

        "audit_trace": [],

        "audit_success": False,

        "audit_duration_ms": 0,

        "audit_generated_at": None,

        "audit_llm": {},

        "audit_trail": [],

        "audit_package": {},

        # -----------------------------------------------------
        # Human In The Loop
        # -----------------------------------------------------

        "hitl_required": False,

        "human_approval": {},

        "approval_history": [],

        "approval_runtime": {},

        "approval_llm": {},

        # =====================================================
        # Enterprise Runtime Monitoring
        # =====================================================


        # =====================================================
        # Enterprise Runtime Monitoring
        # =====================================================

        "execution_timeline": [],

        "investigation_timeline": [],

        "agent_trace": [],

        "runtime_health": {},

        "runtime_summary": {},

        "runtime_telemetry": {},

        "runtime_metrics": {},

        "runtime_statistics": {},

        "dashboard_metrics": {},

        "control_tower_summary": {},

        "runtime_monitor": {},

        "runtime_monitor_summary": {},

        "runtime_monitor_health": {},

        "runtime_monitor_runtime": {},

        "runtime_monitor_trace": [],

        "runtime_monitor_confidence": 0,

        "runtime_monitor_success": False,

        "runtime_monitor_duration_ms": 0,

        "runtime_monitor_generated_at": None,

        "runtime_monitor_llm": {},

        # =====================================================
        # Enterprise Agent Registry
        # =====================================================

        "agents": {},
        "agent_execution_order": [],

        "agent_dependencies": {},

        "agent_results": {},
        "agent_registry": {},

        "agent_runtime": {},

        "agent_health": {},

        "agent_statistics": {},

        "agent_metrics": {},

        "agent_summary": {},

        # =====================================================
        # Enterprise LLM Runtime
        # =====================================================

        "llm_trace": [],

        "runtime_llm": {},

        "planner_llm": {},

        "query_rewrite_llm": {},

        "tool_router_llm": {},

        "retrieval_llm": {},

        "cross_encoder_llm": {},

        "retrieval_judge_llm": {},

        "crag_llm": {},

        "evidence_llm": {},

        "evidence_validation_llm": {},

        "answer_llm": {},

        "reflection_llm": {},

        "grounding_llm": {},

        "hallucination_llm": {},

        "evaluation_llm": {},

        "ragas_llm": {},

        "trust_llm": {},

        "security_llm": {},

        "governance_llm": {},

        "compliance_llm": {},

        "audit_llm": {},

        "approval_llm": {},

        "executive_llm": {},

        "recommendation_llm": {},

        # =====================================================
        # Token Telemetry
        # =====================================================

        "token_metrics": {},

        "prompt_tokens": 0,

        "completion_tokens": 0,

        "total_tokens": 0,

        # =====================================================
        # Performance Metrics
        # =====================================================

        "performance_metrics": {},

        "latency_metrics": {},

        "throughput_metrics": {},

        "execution_metrics": {},

        # =====================================================
        # Cost Intelligence
        # =====================================================

        "cost_metrics": {},

        "estimated_cost": 0.0,

        "cost_breakdown": {},

        # =====================================================
        # API Telemetry
        # =====================================================

        "api_metrics": {},

        "api_statistics": {},

        "api_health": {},

        # =====================================================
        # Cache Intelligence
        # =====================================================

        "cache_metrics": {},

        "kv_cache": {},

        "semantic_cache": {},

        "retrieval_cache": {},

        # =====================================================
        # Memory Telemetry
        # =====================================================

        "memory_metrics": {},

        "memory_health": {},

        "memory_statistics": {},

        # =====================================================
        # Enterprise Memory
        # =====================================================







# =====================================================
        # Enterprise Memory
        # =====================================================

        "memory": {},

        # -----------------------------------------------------
        # Working Memory
        # -----------------------------------------------------

        "working_memory": {},

        "working_memory_summary": {},

        "working_memory_metrics": {},

        "working_memory_statistics": {},

        "working_memory_health": {},

        "working_memory_runtime": {},

        "working_memory_trace": [],

        # -----------------------------------------------------
        # Semantic Memory
        # -----------------------------------------------------

        "semantic_memory": {},

        "semantic_memory_summary": {},

        "semantic_memory_metrics": {},

        "semantic_memory_statistics": {},

        "semantic_memory_health": {},

        "semantic_memory_runtime": {},

        "semantic_memory_trace": [],

        # -----------------------------------------------------
        # Episodic Memory
        # -----------------------------------------------------

        "episodic_memory": {},

        "episodic_memory_summary": {},

        "episodic_memory_metrics": {},

        "episodic_memory_statistics": {},

        "episodic_memory_health": {},

        "episodic_memory_runtime": {},

        "episodic_memory_trace": [],

        # -----------------------------------------------------
        # Reflection Memory
        # -----------------------------------------------------

        "reflection_memory": {},

        "reflection_memory_summary": {},

        "reflection_memory_metrics": {},

        "reflection_memory_statistics": {},

        "reflection_memory_health": {},

        "reflection_memory_runtime": {},

        "reflection_memory_trace": [],

        # -----------------------------------------------------
        # Conversation Memory
        # -----------------------------------------------------

        "conversation_memory": {},

        "conversation_summary": {},

        "conversation_history": [],

        # -----------------------------------------------------
        # Knowledge Memory
        # -----------------------------------------------------

        "knowledge_memory": {},

        "knowledge_cache": {},

        "knowledge_graph": {},

        # -----------------------------------------------------
        # Vector Memory
        # -----------------------------------------------------

        "vector_memory": {},

        "vector_cache": {},

        "embedding_statistics": {},

        # -----------------------------------------------------
        # Memory Intelligence
        # -----------------------------------------------------

        "memory_summary": {},

        "memory_runtime": {},

        "memory_trace": [],

        "memory_confidence": 0,

        "memory_success": False,

        "memory_duration_ms": 0,

        "memory_generated_at": None,

        "memory_llm": {},

        # =====================================================
        # Executive Intelligence
        # =====================================================









        # =====================================================
        # Executive Intelligence
        # =====================================================

        "executive": {},

        # -----------------------------------------------------
        # Executive Package
        # -----------------------------------------------------

        "executive_package": {},

        "executive_summary": {},

        "executive_metrics": {},

        "executive_statistics": {},

        "executive_health": {},

        "executive_runtime": {},

        "executive_trace": [],

        "executive_confidence": 0,

        "executive_success": False,

        "executive_duration_ms": 0,

        "executive_generated_at": None,

        "executive_llm": {},

        # -----------------------------------------------------
        # Executive Narrative
        # -----------------------------------------------------

        "executive_narrative": {},

        "executive_story": {},

        "executive_brief": {},

        # -----------------------------------------------------
        # Recommendation Engine
        # -----------------------------------------------------

        "recommendation": "",

        "recommendation_package": {},

        "recommendation_summary": {},

        "recommendation_metrics": {},

        "recommendation_statistics": {},

        "recommendation_health": {},

        "recommendation_runtime": {},

        "recommendation_trace": [],

        "recommendation_confidence": 0,

        "recommendation_success": False,

        "recommendation_duration_ms": 0,

        "recommendation_generated_at": None,

        "recommendation_llm": {},

        # -----------------------------------------------------
        # Explainability
        # -----------------------------------------------------

        "technical_explanation": {},

        "business_explanation": {},

        "reasoning_chain": [],

        "decision_reasoning": {},

        # -----------------------------------------------------
        # Investigation Summary
        # -----------------------------------------------------

        "investigation_summary": {},

        "customer_summary": {},

        "risk_summary": {},

        "evidence_summary": {},

        "trust_summary": {},

        "governance_summary": {},

        "security_summary": {},

        "compliance_summary": {},

        # -----------------------------------------------------
        # Enterprise Dashboard
        # -----------------------------------------------------

        "dashboard_metrics": {},

        "executive_dashboard": {},

        "executive_kpis": {},

        "business_kpis": {},

        "platform_kpis": {},

        # -----------------------------------------------------
        # Control Tower
        # -----------------------------------------------------

        "control_tower_summary": {},

        "enterprise_health": {},

        "enterprise_statistics": {},

        "enterprise_metrics": {},

        # -----------------------------------------------------
        # Final Runtime Status
        # -----------------------------------------------------

        "final_status": "INITIALIZED",

        "final_recommendation": "",

        "final_confidence": 0,

        "final_trust_score": 0,

        "final_security_score": 0,

        "final_governance_score": 0,

        "final_compliance_score": 0,

        "final_risk_level": "",

        "runtime_footer": {},
        # =====================================================
        # Enterprise Runtime Outcome
        # =====================================================

        "overall_success": False,

        "overall_status": "INITIALIZED",

        "overall_score": 0,

        "overall_duration_ms": 0
    }
