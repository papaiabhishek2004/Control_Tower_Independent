# AEGIS Canonical Parameters Reference

## Required Event Envelope Fields

| # | Field | Data Type | Example |
|---|---|---|---|
| 1 | `runtime_id` | string | `RUN-001` |
| 2 | `app_id` | string | `CLAIMS_AGENT_APP` |
| 3 | `agent_id` | string | `retriever_01` |
| 4 | `agent_name` | string | `Retriever Agent` |
| 5 | `event_type` | string/enum | `EVIDENCE_FOUND` |
| 6 | `status` | string/enum | `COMPLETED` |
| 7 | `timestamp` | ISO-8601 datetime | `2026-08-02T06:16:07Z` |

## Canonical Parameters

| # | Parameter | Data Type | Example |
|---|---|---|---|
| 1 | `agent_id` | string | `agent_customer_context_01` |
| 2 | `agent_name` | string | `Customer 360 Investigation` |
| 3 | `agent_type` | string/enum | `RETRIEVAL_AGENT` |
| 4 | `phase` | string/enum | `Evidence Retrieval` |
| 5 | `execution_order` | integer | `4` |
| 6 | `stage_id` | string | `evidence_runtime` |
| 7 | `status` | string/enum | `COMPLETED` |
| 8 | `started_at` | ISO-8601 datetime | `2026-08-02T06:16:07Z` |
| 9 | `completed_at` | ISO-8601 datetime | `2026-08-02T06:16:08Z` |
| 10 | `duration_ms` | integer | `611` |
| 11 | `retry_count` | integer | `0` |
| 12 | `max_retries` | integer | `2` |
| 13 | `retry_reason` | string | `timeout` |
| 14 | `previous_agents` | array[string] | `["Planner"]` |
| 15 | `next_agents` | array[string] | `["Evidence Packager"]` |
| 16 | `provider` | string | `OpenAI` |
| 17 | `model` | string | `gpt-4.1` |
| 18 | `model_version` | string | `2026-xx` |
| 19 | `prompt_hash` | string | `sha256:ab12...` |
| 20 | `prompt_template_id` | string | `fraud-review-v3` |
| 21 | `input_tokens` | integer | `147` |
| 22 | `output_tokens` | integer | `440` |
| 23 | `total_tokens` | integer | `587` |
| 24 | `retrieval_method` | string/enum | `Hybrid BM25 + Vector` |
| 25 | `retrieved_chunks` | array[object] | `[{"chunk_id":"TX001","rank":1,"score":0.87}]` |
| 26 | `reranked_chunks` | array[object] | `[{"chunk_id":"TX001","rank":1,"score":0.92}]` |
| 27 | `control_id` | string | `OWASP-LLM02` |
| 28 | `control_status` | string/enum | `PASS` |
| 29 | `findings` | array/string | `["No prompt injection detected"]` |
| 30 | `recommendation` | string/enum | `APPROVE` |
| 31 | `risk_level` | string/enum | `LOW` |
| 32 | `confidence` | number | `86` |
| 33 | `rationale` | string | `Evidence-backed response with policy-approved route.` |
| 34 | `error_code` | string | `TIMEOUT` |
| 35 | `error_message` | string | `API timeout` |
| 36 | `fallback_used` | boolean | `false` |
