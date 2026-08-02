"""Standalone AEGIS Control Tower external runtime loader."""

from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services1.agentic_app_adapters import JSONL_RUNTIME_LOG_APP_ID, execute_onboarded_agentic_app
from services1.runtime_intelligence_ui_loader import load_runtime_intelligence_ui


st.set_page_config(
    page_title="AEGIS Control Tower",
    page_icon="",
    layout="wide",
)

st.title("AEGIS Control Tower")
st.caption("Onboard external agentic applications through canonical runtime events.")

app_id = st.text_input("External App ID", value="EXTERNAL_AGENTIC_APP")
runtime_label = st.text_input("Runtime / Entity Label", value="APP-RUN-001")
objective = st.text_area("Run Objective", value="External agentic app execution", height=90)
log_path = st.text_input("Canonical JSONL Log Path", value="runtime_events.jsonl")

if st.button("Load Into Control Tower", use_container_width=True):
    path = Path(log_path)
    if not path.exists():
        st.error(f"Runtime log not found: {path}")
        st.stop()

    runtime_state = execute_onboarded_agentic_app(
        customer_id=runtime_label.strip() or app_id.strip() or "EXTERNAL_APP",
        user_query=objective,
        app_id=JSONL_RUNTIME_LOG_APP_ID,
        metadata={
            "path": str(path),
            "app_id": app_id.strip() or "EXTERNAL_AGENTIC_APP",
            "app_name": app_id.strip() or "External Agentic App",
        },
    )
    st.session_state.runtime_state = runtime_state
    st.session_state.customer_id = runtime_state.get("customer_id", runtime_label)
    st.session_state.investigation_type = "External App Runtime"
    st.session_state.analyst_instructions = objective
    st.session_state.investigation_loaded = True
    st.success("Runtime loaded into AEGIS Control Tower.")
    st.rerun()

runtime_state = st.session_state.get("runtime_state")
if isinstance(runtime_state, dict) and runtime_state:
    st.divider()
    ui = load_runtime_intelligence_ui()
    ui.render_control_tower(runtime_state)
