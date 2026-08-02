"""Generic onboarding launcher for standalone AEGIS Control Tower."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from services1.agentic_app_adapters import (
    JSONL_RUNTIME_LOG_APP_ID,
    execute_onboarded_agentic_app,
)


def render_investigation_launcher():
    """Load an external app's canonical JSONL runtime log into AEGIS."""
    st.sidebar.header("External App Onboarding")

    if st.session_state.get("investigation_loaded", False):
        runtime_state = st.session_state.get("runtime_state", {})
        st.sidebar.success("Runtime Loaded")
        st.sidebar.metric("Runtime", runtime_state.get("runtime_id", "-"))
        st.sidebar.metric("App", runtime_state.get("app_id", "-"))
        st.sidebar.metric("Status", runtime_state.get("runtime_status", runtime_state.get("status", "-")))
        st.sidebar.metric("Recommendation", runtime_state.get("recommendation", "-"))
        st.sidebar.metric("Trust", runtime_state.get("trust_score", 0))
        st.sidebar.metric("Confidence", runtime_state.get("confidence", 0))
        if st.sidebar.button("Load Another Runtime", use_container_width=True):
            for key in ("runtime_state", "customer_id", "investigation_type", "analyst_instructions", "investigation_loaded"):
                st.session_state.pop(key, None)
            st.rerun()
        return

    app_id = st.sidebar.text_input(
        "External App ID",
        value=st.session_state.get("external_app_id", "EXTERNAL_AGENTIC_APP"),
    )
    runtime_owner = st.sidebar.text_input(
        "Runtime / Entity Label",
        value=st.session_state.get("runtime_owner", "APP-RUN-001"),
        help="Any label AEGIS should show for this external app run.",
    )
    user_query = st.sidebar.text_area(
        "Run Objective",
        value=st.session_state.get("run_objective", "External agentic app execution"),
        height=90,
    )
    log_path = st.sidebar.text_input(
        "Canonical JSONL Log Path",
        value=st.session_state.get("runtime_log_path", "runtime_events.jsonl"),
        help="Path to the JSONL file emitted by the external app.",
    )

    st.sidebar.caption(
        "External apps stay outside AEGIS. They emit canonical JSONL events; "
        "AEGIS ingests, measures, governs, and audits them."
    )

    if st.sidebar.button("Load Runtime Log", use_container_width=True):
        path = Path(log_path)
        if not path.exists():
            st.sidebar.error(f"Runtime log not found: {path}")
            st.stop()

        runtime_state = execute_onboarded_agentic_app(
            customer_id=runtime_owner.strip() or app_id.strip() or "EXTERNAL_APP",
            user_query=user_query,
            app_id=JSONL_RUNTIME_LOG_APP_ID,
            metadata={
                "path": str(path),
                "app_id": app_id.strip() or "EXTERNAL_AGENTIC_APP",
                "app_name": app_id.strip() or "External Agentic App",
            },
        )

        st.session_state.runtime_state = runtime_state
        st.session_state.customer_id = runtime_state.get("customer_id", runtime_owner)
        st.session_state.investigation_type = "External App Runtime"
        st.session_state.analyst_instructions = user_query
        st.session_state.external_app_id = app_id
        st.session_state.runtime_owner = runtime_owner
        st.session_state.run_objective = user_query
        st.session_state.runtime_log_path = log_path
        st.session_state.investigation_loaded = True
        st.rerun()
