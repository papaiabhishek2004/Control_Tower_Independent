import streamlit as st
import pandas as pd


# ============================================================
# Generic Helpers
# ============================================================

def render_table(title, data):

    st.subheader(title)

    if data is None:
        st.info("No data available.")
        return

    if isinstance(data, pd.DataFrame):

        st.dataframe(
            data,
            use_container_width=True,
            hide_index=True
        )
        return

    if isinstance(data, list):

        if len(data) == 0:
            st.info("No data available.")
            return

        st.dataframe(
            pd.DataFrame(data),
            use_container_width=True,
            hide_index=True
        )
        return

    if isinstance(data, dict):

        if len(data) == 0:
            st.info("No data available.")
            return

        st.dataframe(
            pd.DataFrame([data]),
            use_container_width=True,
            hide_index=True
        )
        return

    st.write(data)


def render_metric_row(metrics):

    cols = st.columns(len(metrics))

    for col, (title, value) in zip(cols, metrics.items()):

        col.metric(title, value)


# ============================================================
# Investigation
# ============================================================

def render_investigation(result):

    st.header("ðŸ”Ž Investigation")

    render_metric_row({

        "Customer":
            result.get("customer_id", "-"),

        "Runtime":
            result.get("runtime_id", "-"),

        "Status":
            result.get("status", "-")

    })

    st.text_area(

        "Original Query",

        value=result.get(
            "query",
            ""
        ),

        height=90,

        disabled=True

    )

    rewritten = (

        result
        .get(
            "decision_snapshot",
            {}
        )
        .get(
            "rewritten_query",
            ""
        )

    )

    st.text_area(

        "Updated Query",

        value=rewritten,

        height=90,

        disabled=True

    )

    st.divider()


# ============================================================
# Planner
# ============================================================

def render_planner(result):

    st.header("ðŸ§  Planner Intelligence inside")

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

        "Confidence":
            planner.get("confidence", 0)

    })

    goals = planner.get("goals", [])

    if goals:

        with st.expander(
            "Planner Goals",
            expanded=True
        ):

            for goal in goals:

                st.write("â€¢", goal)

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

        "Latency (ms)":
            telemetry.get(
                "latency_ms",
                0
            ),

        "LLM Confidence":
            planner_llm.get(
                "confidence",
                0
            )

    })

    st.divider()


# ============================================================
# Tool Selection
# ============================================================

def render_tools(result):

    st.header("ðŸ›  Tool Selection")

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

        selected

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

    st.header(
        "ðŸ‘¤ Customer Intelligence"
    )

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

        if profile:

            render_table(
                "Customer Profile",
                profile
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

def render_retrieval(result):

    st.header("ðŸ” Retrieval Intelligence")

    tabs = st.tabs([
        "Retrieved Chunks",
        "Statistics",
        "Knowledge",
        "Vector Inventory"
    ])

    # --------------------------------------------------------
    # Retrieved Chunks
    # --------------------------------------------------------

    with tabs[0]:

        render_table(

            "Retrieved Chunks",

            result.get(

                "retrieved_chunks",

                []

            )

        )

        st.divider()

        render_table(

            "Reranking",

            result.get(

                "reranking",

                {}

            )

        )

        st.divider()

        render_table(

            "Retrieval Judge",

            result.get(

                "retrieval_judge",

                {}

            )

        )

        st.divider()

        render_table(

            "CRAG",

            result.get(

                "crag",

                {}

            )

        )

    # --------------------------------------------------------
    # Retrieval Statistics
    # --------------------------------------------------------

    with tabs[1]:

        retrieval = result.get("retrieval", {})

        stats = retrieval.get(
            "retrieval_statistics",
            result.get(
                "retrieval_statistics",
                {}
            )
        )

        if stats:

            render_table(
                "Retrieval Statistics",
                stats
            )

        summary = retrieval.get(
            "retrieval_summary"
        )

        if summary:

            st.info(summary)

    # --------------------------------------------------------
    # Knowledge Intelligence
    # --------------------------------------------------------

    with tabs[2]:

        knowledge = result.get(
            "knowledge_intelligence",
            {}
        )

        if knowledge:

            render_table(
                "Knowledge Intelligence",
                knowledge
            )

        else:

            st.info(
                "Knowledge Intelligence not available."
            )

    # --------------------------------------------------------
    # Vector Inventory
    # --------------------------------------------------------

    with tabs[3]:


        vector = result.get(

            "vector_inventory",

            result.get(

                "retrieval",

                {}

            ).get(

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
                "Vector inventory not available."
            )

    st.divider()


# ============================================================
# Evidence Intelligence
# ============================================================

def render_evidence(result):

    st.header("ðŸ“‘ Evidence Intelligence")

    tabs = st.tabs([
        "Evidence Pack",
        "Analysis",
        "Metrics",
        "Sources"
    ])

    # --------------------------------------------------------
    # Evidence Pack
    # --------------------------------------------------------

    with tabs[0]:

        render_table(
            "Evidence Pack",
            result.get(
                "evidence_pack",
                []
            )
        )
        render_table(

            "Validated Evidence",

            result.get(

                "validated_evidence",

                []

            )

        )

        render_table(

            "Evidence Validation",

            result.get(

                "evidence_validation",

                {}

            )

        )

        render_table(

            "Retrieval Judge",

            result.get(

                "retrieval_judge",

                {}

            )

        )

        render_table(

            "CRAG",

            result.get(

                "crag",

                {}

            )

        )

    # --------------------------------------------------------
    # Evidence Analysis
    # --------------------------------------------------------

    with tabs[1]:

        analysis = result.get(
            "evidence_analysis",
            result.get(
                "evidence",
                {}
            )
        )

        if analysis:

            render_table(
                "Evidence Analysis",
                analysis
            )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------


    with tabs[2]:

        metrics = result.get(

            "evidence_metrics",

            {}

        )

        if metrics:

            render_table(

                "Evidence Metrics",

                metrics

            )

        health = result.get(

            "evidence_health",

            ""

        )

        if health:

            st.success(

                health

            )

        summary = result.get(

            "evidence_summary",

            ""

        )

        if summary:

            st.info(

                summary

            )
    # --------------------------------------------------------
    # Sources
    # --------------------------------------------------------


    with tabs[3]:

        render_table(

            "Source Distribution",

            result.get(

                "source_distribution",

                {}

            )

        )

    st.divider()
# ============================================================
# Agent Runtime Intelligence
# ============================================================

def render_agent_runtime(result):

    st.header("ðŸ¤– Agent Runtime Intelligence::::::")

    trace = result.get("agent_trace", [])

    completed = failed = running = 0

    if isinstance(trace, list):

        for row in trace:

            if not isinstance(row, dict):
                continue

            status = str(
                row.get("status", "")
            ).upper()

            if status == "COMPLETED":
                completed += 1

            elif status == "FAILED":
                failed += 1

            elif status in (
                "RUNNING",
                "IN_PROGRESS"
            ):
                running += 1

    render_metric_row({

        "Completed": completed,

        "Failed": failed,

        "Running": running,

        "Total": len(trace)

    })

    tabs = st.tabs([

        "Live Runtime",

        "Agent Trace",

        "Execution",

        "Investigation",

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

        render_table(

            "Agent Trace",

            trace

        )
        render_table(

            "Agent Registry",

            result.get(

                "agents",

                {}

            )

        )

    # --------------------------------------------------------
    # Execution Timeline
    # --------------------------------------------------------

    with tabs[2]:

        render_table(

            "Execution Timeline",

            result.get(
                "execution_timeline",
                []
            )

        )

    # --------------------------------------------------------
    # Investigation Timeline
    # --------------------------------------------------------

    with tabs[3]:

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

    with tabs[4]:

        dashboard = result.get(
            "dashboard_metrics",
            {}
        )

        if dashboard:

            render_table(

                "Dashboard Metrics",

                dashboard

            )



        runtime_health = result.get(

            "runtime_health",

            result.get(

                "runtime_health_v2",

                {}

            )

        )

        if runtime_health:

            st.subheader(
                "Runtime Health"
            )

            render_table(

                "Runtime Health",

                runtime_health

            )

    st.divider()





# ============================================================
# AI Intelligence
# ============================================================

def render_ai_intelligence(result):

    st.header("ðŸ§  AI Intelligence")


    tabs = st.tabs([

        "Reflection",

        "Enterprise Trust",

        "Security",

        "RAGAS",

        "Telemetry"



    ])
    # =======================================================
    # Reflection
    # =======================================================

    with tabs[0]:


        reflection = (
            result.get("reflection")
            or result.get("reflection_result")
            or result.get("reflection_runtime")
            or {}
        )

        if reflection:

            render_table(

                "Reflection",

                reflection

            )

            c1, c2, c3 = st.columns(3)

            c1.metric(

                "Reflection Score",

                result.get(

                    "reflection_score",

                    0

                )

            )

            c2.metric(

                "Confidence",

                result.get(

                    "reflection_confidence",

                    0

                )

            )

            c3.metric(

                "Status",

                reflection.get(

                    "status",

                    "UNKNOWN"

                )

            )

            summary = result.get(

                "reflection_summary",

                ""

            )

            if summary:

                st.success(

                    summary

                )

        else:

            st.info(

                "Reflection not available."

            )

    # =======================================================
    # Enterprise Trust
    # =======================================================

    with tabs[1]:

        trust = result.get(

            "trust_score",

            result.get(

                "enterprise_trust",

                {}

            )

        )

        render_table(

            "Enterprise Trust",

            trust

        )

        evolution = result.get(

            "trust_evolution",

            result.get(

                "enterprise_trust",

                {}

            ).get(

                "trust_evolution",

                {}

            )

        )

        if evolution:

            st.divider()

            render_table(

                "Trust Evolution",

                evolution

            )

        journey = result.get(

            "trust_journey",

            []

        )

        if journey:

            st.divider()

            render_table(

                "Trust Journey",

                journey

            )
            # =======================================================
    # Security
    # =======================================================

    with tabs[2]:

        security = result.get(

            "security",

            result.get(

                "security_analysis",

                {}

            )

        )

        if security:

            render_table(

                "Enterprise Security",

                security

            )

            c1, c2, c3 = st.columns(3)

            c1.metric(

                "Security Score",

                result.get(

                    "security_score",

                    security.get(

                        "security_score",

                        0

                    )

                )

            )

            c2.metric(

                "OWASP Compliance",

                result.get(

                    "owasp_compliance",

                    security.get(

                        "owasp_compliance",

                        0

                    )

                )

            )

            c3.metric(

                "Security Maturity",

                result.get(

                    "security_maturity",

                    security.get(

                        "security_maturity",

                        "-"

                    )

                )

            )

            st.divider()

            render_table(

                "Failed Controls",

                result.get(

                    "failed_security_controls",

                    security.get(

                        "failed_controls",

                        []

                    )

                )

            )

            render_table(

                "Review Controls",

                result.get(

                    "review_security_controls",

                    security.get(

                        "review_controls",

                        []

                    )

                )

            )

            render_table(

                "Security Findings",

                security.get(

                    "findings",

                    []

                )

            )

            render_table(

                "OWASP Assessment",

                security.get(

                    "owasp",

                    {}

                )

            )

            render_table(

                "Security Recommendations",

                security.get(

                    "recommendations",

                    []

                )

            )

        else:

            st.warning(

                "Security analysis not available."

            )
            # =======================================================
    # RAGAS
    # =======================================================

    with tabs[3]:

        ragas = result.get(

            "ragas",

            result.get(

                "ragas_scores",

                {}

            )

        )

        if ragas:

            render_table(

                "RAGAS Evaluation",

                ragas

            )

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(

                "Overall",

                ragas.get(

                    "overall_score",

                    0

                )

            )

            c2.metric(

                "Faithfulness",

                ragas.get(

                    "faithfulness",

                    0

                )

            )

            c3.metric(

                "Answer Relevancy",

                ragas.get(

                    "answer_relevancy",

                    0

                )

            )

            c4.metric(

                "Context Precision",

                ragas.get(

                    "context_precision",

                    0

                )

            )

            st.divider()

            render_table(

                "Evaluation Results",

                result.get(

                    "evaluation_results",

                    {}

                )

            )

            render_table(

                "Grounding Results",

                result.get(

                    "grounding_results",

                    {}

                )

            )

            render_table(

                "Hallucination Results",

                result.get(

                    "hallucination_results",

                    {}

                )

            )

            summary = result.get(

                "ragas_summary",

                ""

            )

            if summary:

                st.success(

                    summary

                )

        else:

            st.info(

                "RAGAS evaluation not available."

            )

    # =======================================================
    # Runtime Telemetry
    # =======================================================

    with tabs[4]:

        telemetry = result.get(

            "runtime_telemetry",

            {}

        )

        if telemetry:

            render_table(

                "Runtime Telemetry",

                telemetry

            )

        runtime_health = result.get(

            "runtime_health",

            result.get(

                "runtime_health_v2",

                {}

            )

        )

        if runtime_health:

            st.divider()

            render_table(

                "Runtime Health",

                runtime_health

            )

        runtime_summary = result.get(

            "runtime_summary",

            {}

        )

        if runtime_summary:

            st.divider()

            render_table(

                "Runtime Summary",

                runtime_summary

            )

        token = result.get(

            "token_metrics",

            {}

        )

        if token:

            st.divider()

            render_table(

                "Token Metrics",

                token

            )

        render_table(

            "Planner LLM",

            result.get(

                "planner_llm",

                {}

            )

        )

        render_table(

            "Reflection LLM",

            result.get(

                "reflection_llm",

                {}

            )

        )

        render_table(

            "Evaluation LLM",

            result.get(

                "evaluation_llm",

                {}

            )

        )

        render_table(

            "Executive LLM",

            result.get(

                "executive_llm",

                {}

            )

        )
        # =======================================================
    # Enterprise LLM Diagnostics
    # =======================================================


    st.divider()

# ============================================================
# Governance Center
# ============================================================

def render_governance(result):

    st.header("ðŸ› Governance Center")

    governance = result.get(
        "governance",
        {}
    )

    compliance = result.get(
        "compliance",
        {}
    )

    audit = result.get(
        "audit",
        {}
    )

    security = result.get(
        "security",
        result.get(
            "security_analysis",
            {}
        )
    )

    trust = result.get(
        "trust_score",
        result.get(
            "enterprise_trust",
            {}
        )
    )

    # =======================================================
    # Executive KPIs
    # =======================================================

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(

        "Decision",

        governance.get(
            "decision",
            "-"
        )

    )

    c2.metric(

        "Governance",

        governance.get(
            "governance_score",
            0
        )

    )

    c3.metric(

        "Trust",

        trust.get(
            "overall",
            trust.get(
                "overall_score",
                0
            )
        )

    )

    c4.metric(

        "Security",

        result.get(
            "security_score",
            0
        )

    )

    c5.metric(

        "Compliance",

        compliance.get(
            "overall_status",
            compliance.get(
                "status",
                "-"
            )
        )

    )

    st.divider()

    # =======================================================
    # Tabs
    # =======================================================

    tabs = st.tabs([

        "Governance",

        "Compliance",

        "Security",

        "Audit",

        "Human Approval"

    ])

    # =======================================================
    # Governance
    # =======================================================

    with tabs[0]:

        render_table(

            "Governance Decision",

            governance

        )

        render_table(

            "Decision Snapshot",

            result.get(

                "decision_snapshot",

                {}

            )

        )

        render_table(

            "Recommendation",

            result.get(

                "recommendation_package",

                {}

            )

        )

    # =======================================================
    # Compliance
    # =======================================================

    with tabs[1]:

        render_table(

            "Compliance",

            compliance

        )

        render_table(

            "Enterprise Trust",

            trust

        )

        render_table(

            "Trust Evolution",

            result.get(

                "trust_evolution",

                {}

            )

        )

        render_table(

            "Runtime Health",

            result.get(

                "runtime_health",

                result.get(

                    "runtime_health_v2",

                    {}

                )

            )

        )

    # =======================================================
    # Security
    # =======================================================

    with tabs[2]:

        render_table(

            "Security",

            security

        )

        render_table(

            "Failed Controls",

            result.get(

                "failed_security_controls",

                []

            )

        )

        render_table(

            "Review Controls",

            result.get(

                "review_security_controls",

                []

            )

        )
            # =======================================================
    # Audit
    # =======================================================

    with tabs[3]:

        render_table(

            "Audit",

            audit

        )

        render_table(

            "Audit Trail",

            audit.get(

                "audit_trail",

                []

            )

        )

        render_table(

            "Runtime Telemetry",

            result.get(

                "runtime_telemetry",

                {}

            )

        )

        render_table(

            "Agent Trace",

            result.get(

                "agent_trace",

                []

            )

        )

    # =======================================================
    # Human Approval
    # =======================================================

    with tabs[4]:

        render_table(

            "Human Approval",

            result.get(

                "human_approval",

                {}

            )

        )

        render_table(

            "Approval History",

            result.get(

                "approval_history",

                []

            )

        )

        render_table(

            "Executive Package",

            result.get(

                "executive_package",

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

        render_table(

            "Control Tower Summary",

            result.get(

                "control_tower_summary",

                {}

            )

        )

    # =======================================================
    # Governance Summary
    # =======================================================

    st.divider()

    st.subheader("Governance Summary")

    summary = {

        "Decision": governance.get(

            "decision",

            "-"

        ),

        "Governance Score": governance.get(

            "governance_score",

            0

        ),

        "Trust Score": trust.get(

            "overall",

            trust.get(

                "overall_score",

                0

            )

        ),

        "Security Score": result.get(

            "security_score",

            0

        ),

        "Compliance": compliance.get(

            "overall_status",

            compliance.get(

                "status",

                "-"

            )

        ),

        "Review Required": governance.get(

            "review_required",

            False

        )

    }

    render_table(

        "Governance Summary",

        summary

    )

    st.divider()
# ============================================================
# Banking Intelligence
# ============================================================

def render_banking(result):

    st.header("ðŸ¦ Banking Intelligence")

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

                result.get(

                    "cases",

                    {}

                ).get(

                    "case_management",

                    {}

                )

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
# Executive Intelligence
# ============================================================

def render_executive(result):

        st.header("ðŸ‘” Executive Intelligence")

        tabs = st.tabs([

            "Narrative",

            "Executive Package",

            "Recommendation",

            "Control Tower",

            "Executive Dashboard"

        ])

        # =======================================================
        # Executive Narrative
        # =======================================================

        with tabs[0]:

            narrative = result.get(

                "executive_narrative",

                {}

            )

            render_table(

                "Executive Narrative",

                narrative

            )

            summary = result.get(

                "runtime_summary",

                {}

            )

            if summary:

                st.divider()

                render_table(

                    "Runtime Summary",

                    summary

                )

        # =======================================================
        # Executive Package
        # =======================================================

        with tabs[1]:

            render_table(

                "Executive Package",

                result.get(

                    "executive_package",

                    {}

                )

            )

            render_table(

                "Decision Snapshot",

                result.get(

                    "decision_snapshot",

                    {}

                )

            )

            render_table(

                "Planner Output",

                result.get(

                    "execution_plan",

                    result.get(

                        "planner",

                        {}

                    ).get(

                        "execution_plan",

                        {}

                    )

                )

            )

        # =======================================================
        # Recommendation
        # =======================================================

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

            render_table(

                "Enterprise Recommendation",

                result.get(

                    "recommendation",

                    {}

                )

            )
        # =======================================================
        # Control Tower
        # =======================================================

        with tabs[3]:

            render_table(

                "Control Tower Summary",

                result.get(

                    "control_tower_summary",

                    {}

                )

            )

            render_table(

                "Runtime Summary",

                result.get(

                    "runtime_summary",

                    {}

                )

            )

            render_table(

                "Runtime Health",

                result.get(

                    "runtime_health",

                    result.get(

                        "runtime_health_v2",

                        {}

                    )

                )

            )

            render_table(

                "Runtime Telemetry",

                result.get(

                    "runtime_telemetry",

                    {}

                )

            )

        # =======================================================
        # Executive Dashboard
        # =======================================================

        with tabs[4]:

            runtime = result.get(

                "runtime_summary",

                {}

            )

            trust = result.get(

                "trust_score",

                {}

            )

            ragas = result.get(

                "ragas",

                {}

            )

            c1, c2, c3 = st.columns(3)

            c1.metric(

                "Recommendation",

                runtime.get(

                    "recommendation",

                    result.get(

                        "recommendation",

                        "-"

                    )

                )

            )

            c2.metric(

                "Trust Score",

                trust.get(

                    "overall",

                    trust.get(

                        "overall_score",

                        0

                    )

                )

            )

            c3.metric(

                "Confidence",

                runtime.get(

                    "confidence",

                    result.get(

                        "confidence",

                        0

                    )

                )

            )

            c1, c2, c3 = st.columns(3)

            c1.metric(

                "Security",

                result.get(

                    "security_score",

                    0

                )

            )

            c2.metric(

                "Reflection",

                result.get(

                    "reflection_score",

                    0

                )

            )

            c3.metric(

                "RAGAS",

                ragas.get(

                    "overall_score",

                    0

                )

            )

            st.divider()

            render_table(

                "Executive Package",

                result.get(

                    "executive_package",

                    {}

                )

            )

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

            render_table(

                "Control Tower Summary",

                result.get(

                    "control_tower_summary",

                    {}

                )

            )

            render_table(

                "Executive Narrative",

                result.get(

                    "executive_narrative",

                    {}

                )

            )

        st.divider()
# ============================================================
# Enterprise Runtime Summary
# ============================================================



# ============================================================
# Enterprise Runtime Summary
# ============================================================

def render_enterprise_runtime_summary(result):

    st.header("ðŸš€ Enterprise Runtime Summary")

    runtime = result.get("runtime_summary", {})
    telemetry = result.get("runtime_telemetry", {})
    health = result.get("runtime_health", {})
    trust = result.get("trust", {})
    ragas = result.get("ragas", {})
    governance = result.get("governance", {})
    compliance = result.get("compliance", {})

    agent_trace = result.get("agent_trace", [])
    llm_trace = result.get("llm_trace", [])

    # --------------------------------------------------------
    # Executive KPIs
    # --------------------------------------------------------

    c1, c2, c3, c4, c5, c6 = st.columns(6)

    c1.metric(
        "Recommendation",
        result.get(
            "final_recommendation",
            "-"
        )
    )

    c2.metric(
        "Trust",
        result.get(
            "final_trust_score",
            trust.get(
                "score",
                0
            )
        )
    )

    c3.metric(
        "Security",
        result.get(
            "final_security_score",
            result.get(
                "security_score",
                0
            )
        )
    )

    c4.metric(
        "Governance",
        result.get(
            "final_governance_score",
            governance.get(
                "governance_score",
                0
            )
        )
    )

    c5.metric(
        "Compliance",
        result.get(
            "final_compliance_score",
            compliance.get(
                "compliance_score",
                0
            )
        )
    )

    c6.metric(
        "Confidence",
        result.get(
            "final_confidence",
            result.get(
                "confidence",
                0
            )
        )
    )

    st.divider()

    tabs = st.tabs([

        "Executive",

        "Runtime",

        "Performance",

        "AI",

        "Agents",

        "Telemetry"

    ])

    # ======================================================
    # Executive
    # ======================================================

    with tabs[0]:

        render_table(
            "Executive Package",
            result.get(
                "executive_package",
                {}
            )
        )

        render_table(
            "Recommendation Package",
            result.get(
                "recommendation_package",
                {}
            )
        )

        render_table(
            "Decision Snapshot",
            result.get(
                "decision_snapshot",
                {}
            )
        )

        render_table(
            "Executive Narrative",
            result.get(
                "executive_narrative",
                {}
            )
        )

    # ======================================================
    # Runtime
    # ======================================================

    with tabs[1]:

        render_table(
            "Runtime Summary",
            runtime
        )

        render_table(
            "Runtime Health",
            health
        )

        render_table(
            "Runtime Telemetry",
            telemetry
        )

        render_table(
            "Control Tower Summary",
            result.get(
                "control_tower_summary",
                {}
            )
        )

    # ======================================================
    # Performance
    # ======================================================

    with tabs[2]:

        render_table(
            "Performance Metrics",
            result.get(
                "performance_metrics",
                {}
            )
        )

        render_table(
            "Token Metrics",
            result.get(
                "token_metrics",
                {}
            )
        )

        render_table(
            "Cost Metrics",
            result.get(
                "cost_metrics",
                {}
            )
        )

        render_table(
            "API Metrics",
            result.get(
                "api_metrics",
                {}
            )
        )

        render_table(
            "Cache Metrics",
            result.get(
                "cache_metrics",
                {}
            )
        )

    # ======================================================
    # AI
    # ======================================================

    with tabs[3]:

        render_table(
            "Reflection",
            result.get(
                "reflection",
                {}
            )
        )

        render_table(
            "RAGAS",
            ragas
        )

        render_table(
            "Grounding",
            result.get(
                "grounding",
                {}
            )
        )

        render_table(
            "Hallucination",
            result.get(
                "hallucination",
                {}
            )
        )

        render_table(
            "Evaluation",
            result.get(
                "evaluation",
                {}
            )
        )

    # ======================================================
    # Agents
    # ======================================================

    with tabs[4]:

        render_table(
            "Agent Registry",
            result.get(
                "agents",
                {}
            )
        )

        render_table(
            "Agent Execution Order",
            result.get(
                "agent_execution_order",
                []
            )
        )

        render_table(
            "Agent Trace",
            agent_trace
        )

    # ======================================================
    # Telemetry
    # ======================================================

    with tabs[5]:

        render_table(
            "LLM Trace",
            llm_trace
        )

        render_table(
            "Runtime Metrics",
            result.get(
                "runtime_metrics",
                {}
            )
        )

        render_table(
            "Runtime Statistics",
            result.get(
                "runtime_statistics",
                {}
            )
        )

        render_table(
            "Runtime Footer",
            result.get(
                "runtime_footer",
                {}
            )
        )

    st.divider()




# ============================================================
# Runtime Explorer
# ============================================================

def render_runtime_explorer(result):

    with st.expander(
        "ðŸ“¦ Runtime Explorer",
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

# =============================================================================
# CACHE INTELLIGENCE
# =============================================================================

def render_cache_intelligence(result):

    st.subheader("âš¡ Cache Intelligence")

    cache = result.get("cache", {})

    cache_summary = result.get("cache_summary", {})

    cache_metrics = result.get("cache_metrics", {})

    cache_statistics = result.get("cache_statistics", {})

    cache_health = result.get("cache_health", {})

    cache_runtime = result.get("cache_runtime", {})

    cache_decision = result.get("cache_decision", {})

    cache_savings = result.get("cache_savings", {})

    cache_trace = result.get("cache_trace", {})

    cache_llm = result.get("cache_llm", {})

    dashboard_metrics = result.get(

        "dashboard_metrics",

        {}

    ).get(

        "cache",

        {}

    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs([

        "Overview",

        "Metrics",

        "Decision",

        "Savings",

        "Runtime"

    ])

    with tab1:

        render_table(

            "Cache",

            cache

        )

        render_table(

            "Summary",

            cache_summary

        )

        render_table(

            "Health",

            cache_health

        )

    with tab2:

        render_table(

            "Metrics",

            cache_metrics

        )

        render_table(

            "Statistics",

            cache_statistics

        )

        render_table(

            "Dashboard Metrics",

            dashboard_metrics

        )

    with tab3:

        render_table(

            "Decision",

            cache_decision

        )

    with tab4:

        render_table(

            "Estimated Savings",

            cache_savings

        )

    with tab5:

        render_table(

            "Runtime",

            cache_runtime

        )

        render_table(

            "Trace",

            cache_trace

        )

        render_table(

            "LLM",

            cache_llm

        )
# ============================================================
# Control Tower
# ============================================================

def render_control_tower(result):

    render_investigation(result)
    render_enterprise_runtime_summary(result)

    render_planner(result)

    render_tools(result)

    render_customer(result)


    render_retrieval(result)

    render_evidence(result)

    render_agent_runtime(result)



    render_ai_intelligence(result)

    render_governance(result)

    render_banking(result)

    render_executive(result)

    render_runtime_explorer(result)
    render_cache_intelligence(result)
