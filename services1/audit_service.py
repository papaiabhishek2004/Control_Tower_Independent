# ============================================================
# AEGIS AI CONTROL TOWER
# AUDIT SERVICE
# ============================================================

from datetime import datetime
import pandas as pd

# ============================================================
# AGENT TRACE AUDIT
# ============================================================

def build_agent_audit(
    agent_trace
):

    if not agent_trace:

        return []

    audit_records = []

    sequence = 1

    for step in agent_trace:

        audit_records.append({

            "sequence":
                sequence,

            "event_type":
                "AGENT_EXECUTION",

            "agent":
                step.get(
                    "agent",
                    "UNKNOWN"
                ),

            "status":
                step.get(
                    "status",
                    "UNKNOWN"
                ),

            "latency_ms":
                step.get(
                    "latency_ms",
                    0
                ),

            "timestamp":
                step.get(
                    "completed_at",
                    ""
                )

        })

        sequence += 1

    return audit_records


# ============================================================
# GOVERNANCE AUDIT
# ============================================================

def build_governance_audit(
    governance
):

    if not governance:

        return []

    return [

        {

            "sequence": 999,

            "event_type":
                "GOVERNANCE",

            "decision":
                governance.get(
                    "decision",
                    "UNKNOWN"
                ),

            "review_required":
                governance.get(
                    "review_required",
                    False
                ),

            "reason":
                governance.get(
                    "reason",
                    ""
                )

        }

    ]


# ============================================================
# COMPLIANCE AUDIT
# ============================================================

def build_compliance_audit(
    compliance
):

    if not compliance:

        return []

    records = []

    controls = compliance.get(
        "controls",
        {}
    )

    seq = 2000

    for control, status in controls.items():

        records.append({

            "sequence":
                seq,

            "event_type":
                "COMPLIANCE",

            "control":
                control,

            "status":
                status

        })

        seq += 1

    return records


# ============================================================
# RETRIEVAL AUDIT
# ============================================================

def build_retrieval_audit(
    retrieved_chunks
):

    if not retrieved_chunks:

        return []

    records = []

    seq = 3000

    for chunk in retrieved_chunks:

        records.append({

            "sequence":
                seq,

            "event_type":
                "RETRIEVAL",

            "chunk_id":
                chunk.get(
                    "chunk_id",
                    ""
                ),

            "source":
                chunk.get(
                    "source",
                    ""
                ),

            "trust_score":
                chunk.get(
                    "trust_score",
                    0
                )

        })

        seq += 1

    return records


# ============================================================
# TRUST AUDIT
# ============================================================

def build_trust_audit(
    trust_score,
    recommendation
):

    return [

        {

            "sequence":
                4000,

            "event_type":
                "TRUST",

            "trust_score":
                trust_score,

            "recommendation":
                recommendation

        }

    ]


# ============================================================
# BUILD COMPLETE AUDIT TRAIL
# ============================================================

def build_audit_trail(

    agent_trace,

    governance,

    compliance,

    retrieved_chunks,

    trust_score,

    recommendation

):

    audit_records = []

    audit_records.extend(

        build_agent_audit(
            agent_trace
        )

    )

    audit_records.extend(

        build_governance_audit(
            governance
        )

    )

    audit_records.extend(

        build_compliance_audit(
            compliance
        )

    )

    audit_records.extend(

        build_retrieval_audit(
            retrieved_chunks
        )

    )

    audit_records.extend(

        build_trust_audit(

            trust_score,

            recommendation

        )

    )

    audit_records = sorted(

        audit_records,

        key=lambda x: x.get(
            "sequence",
            0
        )

    )

    for index, record in enumerate(audit_records, start=1):

        record["source_sequence"] = record.get(

            "sequence",

            index

        )

        record["sequence"] = index

    return audit_records


# ============================================================
# AUDIT METRICS
# ============================================================

def build_audit_metrics(
    audit_trail
):

    return {

        "total_records":

            len(
                audit_trail
            ),

        "agent_events":

            len(

                [

                    x

                    for x in audit_trail

                    if x.get(
                        "event_type"
                    )

                    ==

                    "AGENT_EXECUTION"

                ]

            ),

        "compliance_events":

            len(

                [

                    x

                    for x in audit_trail

                    if x.get(
                        "event_type"
                    )

                    ==

                    "COMPLIANCE"

                ]

            ),

        "retrieval_events":

            len(

                [

                    x

                    for x in audit_trail

                    if x.get(
                        "event_type"
                    )

                    ==

                    "RETRIEVAL"

                ]

            )

    }


# ============================================================
# EXECUTION REPLAY
# ============================================================

def build_execution_replay(
    audit_trail
):

    replay = []

    for record in audit_trail:

        replay.append({

            "Step":
                record.get(
                    "sequence"
                ),

            "Type":
                record.get(
                    "event_type"
                ),

            "Status":
                record.get(
                    "status",
                    "SUCCESS"
                )

        })

    return replay


# ============================================================
# EXECUTIVE AUDIT SUMMARY
# ============================================================

def build_audit_summary(
    audit_metrics
):

    return f"""
Total Audit Records:
{audit_metrics['total_records']}

Agent Events:
{audit_metrics['agent_events']}

Compliance Events:
{audit_metrics['compliance_events']}

Retrieval Events:
{audit_metrics['retrieval_events']}
"""


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

def generate_audit_package(

    runtime_state=None,

    customer_id=None,
    agent_trace=None,
    governance=None,
    compliance=None,
    retrieved_chunks=None,
    trust_score=None,
    recommendation=None,

    **kwargs

):

    # --------------------------------------------------------
    # Enterprise Compatibility Layer
    # --------------------------------------------------------

    if runtime_state is not None:

        customer_id = runtime_state.get(
            "customer_id",
            customer_id
        )

        agent_trace = runtime_state.get(
            "agent_trace",
            []
        )

        governance = runtime_state.get(
            "governance",
            {}
        )

        compliance = runtime_state.get(
            "compliance",
            {}
        )

        retrieved_chunks = runtime_state.get(
            "retrieved_chunks",
            []
        )

        trust_score = runtime_state.get(
            "trust_score",
            0
        )

        recommendation = runtime_state.get(
            "recommendation",
            "UNKNOWN"
        )

    agent_trace = agent_trace or []
    governance = governance or {}
    compliance = compliance or {}
    retrieved_chunks = retrieved_chunks or []
    trust_score = trust_score if trust_score is not None else 0
    recommendation = recommendation or "UNKNOWN"

    audit_trail = build_audit_trail(

        agent_trace,

        governance,

        compliance,

        retrieved_chunks,

        trust_score,

        recommendation

    )

    audit_metrics = build_audit_metrics(
        audit_trail
    )

    replay = build_execution_replay(
        audit_trail
    )

    summary = build_audit_summary(
        audit_metrics
    )

    return {

        "customer_id": customer_id,

        "audit_trail": audit_trail,

        "audit_metrics": audit_metrics,

        "replay": replay,

        "summary": summary,

        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    result = generate_audit_package(

        agent_trace=[

            {
                "agent":"Retriever",
                "status":"SUCCESS",
                "latency_ms":12
            },

            {
                "agent":"Trust Engine",
                "status":"SUCCESS",
                "latency_ms":8
            }

        ],

        governance={

            "decision":"APPROVE"

        },

        compliance={

            "controls":{

                "Input Validation":"PASS",

                "Prompt Protection":"PASS"

            }

        },

        retrieved_chunks=[

            {

                "chunk_id":"DOC001",

                "source":"BM25",

                "trust_score":95

            }

        ],

        trust_score=95,

        recommendation="APPROVE"

    )

    print()
    print("=" * 80)
    print("AUDIT SERVICE")
    print("=" * 80)
    print()

    print(
        result["audit_metrics"]
    )
