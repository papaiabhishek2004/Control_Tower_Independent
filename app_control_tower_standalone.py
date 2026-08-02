"""Standalone AEGIS Control Tower entrypoint.

Use this when AEGIS should behave only as the Control Tower integration tool:

    streamlit run app_control_tower_standalone.py
"""

from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services1.agentic_app_adapters import JSONL_RUNTIME_LOG_APP_ID, execute_onboarded_agentic_app


st.set_page_config(page_title="AEGIS Control Tower", page_icon="", layout="wide")

st.title("AEGIS Control Tower")
st.caption("Onboard external agentic applications through canonical runtime events.")

with st.sidebar:
    st.header("External App Runtime")
    app_id = st.text_input("External App ID", value="EXTERNAL_AGENTIC_APP")
    runtime_label = st.text_input("Runtime / Entity Label", value="APP-RUN-001")
    objective = st.text_area("Run Objective", value="External agentic app execution", height=90)
    log_path = st.text_input("Canonical JSONL Log Path", value="runtime_events.jsonl")
    load = st.button("Load Into Control Tower", use_container_width=True)

if load:
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
    st.success("Runtime loaded into AEGIS Control Tower.")

runtime_state = st.session_state.get("runtime_state")
if not isinstance(runtime_state, dict) or not runtime_state:
    st.info("Generate or provide a canonical JSONL runtime log, then load it from the sidebar.")
    st.code("python tools1\\emit_canonical_runtime_log.py --output runtime_events.jsonl --runtime-id RUN-001 --app-id EXT_APP")
    st.stop()

display = runtime_state.get("canonical_display", {})
release = runtime_state.get("canonical_control_tower_measurements", {}).get("release_assessment", {})
contract = runtime_state.get("canonical_runtime_event_contract", {})

c1, c2, c3, c4 = st.columns(4)
c1.metric("Runtime", runtime_state.get("runtime_id", "-"))
c2.metric("App", runtime_state.get("app_id", "-"))
c3.metric("Recommendation", display.get("recommendation", runtime_state.get("recommendation", "-")))
c4.metric("Release Route", release.get("release_route", "-"))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Trust", display.get("trust_score", "-"))
c2.metric("Confidence", display.get("confidence", "-"))
c3.metric("Risk", display.get("risk_level", "-"))
c4.metric("Events", contract.get("event_count", 0))

tab1, tab2, tab3, tab4 = st.tabs([
    "Canonical Display",
    "Object Audit",
    "Consistency Audit",
    "Runtime Events",
])

with tab1:
    st.json(display)
with tab2:
    st.dataframe(runtime_state.get("canonical_object_audit", []), use_container_width=True, hide_index=True)
with tab3:
    st.dataframe(runtime_state.get("canonical_consistency_audit", []), use_container_width=True, hide_index=True)
with tab4:
    st.dataframe(contract.get("events", []), use_container_width=True, hide_index=True)
