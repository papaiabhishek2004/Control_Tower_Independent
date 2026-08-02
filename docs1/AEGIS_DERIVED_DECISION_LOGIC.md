# AEGIS Derived Decision Logic

Purpose: reference rules for calculating Control Tower governance fields from external agent signals.

AEGIS principle: external apps emit source signals. AEGIS derives the final
governance decision fields. If the app emits a recommendation, AEGIS treats it
as `proposed_recommendation`; the final value is `final_recommendation`.

## Ownership

| Field | Owner | Notes |
|---|---|---|
| `trust_score` | AEGIS derived | External app may emit component scores; AEGIS derives final score. |
| `risk_level` | AEGIS derived | External app may emit risk indicators/findings; AEGIS derives final level. |
| `proposed_recommendation` | External emitted | Optional app-suggested action. |
| `final_recommendation` | AEGIS derived | Authoritative final recommendation. |
| `recommendation` | AEGIS derived/finalized | AEGIS sets this equal to `final_recommendation` for UI compatibility. |
| `confidence` | AEGIS derived | External app may emit model/agent confidence; AEGIS normalizes. |
| `control_status` | AEGIS derived | Derived from mandatory control checks. |
| `findings` | External emitted + AEGIS enriched | App emits findings; AEGIS adds policy/control findings. |
| `error_code` | External emitted + AEGIS normalized | App emits raw error; AEGIS maps to standard code. |
| `customer_health.relationship_score` | AEGIS derived | Derived from trust and confidence. |
| `customer_health.engagement_score` | AEGIS derived | Derived from anomaly/runtime signals. |
| `customer_health.portfolio_score` | AEGIS derived | Derived from relationship and engagement. |
| `customer_health.health_score` | AEGIS derived | Derived from relationship, portfolio, engagement, and inverse risk. |

## Input Signals

External apps should emit source signals where available:

| Signal | Type | Example |
|---|---|---|
| `evidence_ids` | list[string] | `["EVID-001"]` |
| `retrieved_chunks` | number | `4` |
| `control_status` | string | `PASS` |
| `findings` | list[object/string] | `[{"severity":"HIGH","code":"PII_EXPOSURE"}]` |
| `error_code` | string | `TIMEOUT` |
| `error_message` | string | `Tool call timed out` |
| `proposed_recommendation` | string | `APPROVE` |
| `model_confidence` | number | `82` |
| `input_tokens` | number | `900` |
| `output_tokens` | number | `220` |
| `duration_ms` | number | `1250` |

If these are not emitted, AEGIS calculates them:

| Missing Field | AEGIS Calculation |
|---|---|
| `trust_score` | Weighted score from evidence, control, confidence, error, and trace completeness. |
| `risk_level` | Derived from fatal errors, control status, finding severity, trust, confidence, and evidence. |
| `recommendation` | Set from `final_recommendation`. |
| `final_recommendation` | Derived from risk, controls, trust, confidence, errors, and optional proposal. |
| `confidence` | Average of emitted model/agent confidence values; `0` if none. |
| `control_status` | Derived from mandatory control outcomes and normalized errors. |
| `error_code` | Normalized from raw app error fields/messages; `NONE` if no error. |
| `customer_health.relationship_score` | `trust_score * 0.60 + confidence * 0.40`. |
| `customer_health.engagement_score` | `max(0, 100 - anomaly_count * 5)`. |
| `customer_health.portfolio_score` | `(relationship_score + engagement_score) / 2`. |
| `customer_health.health_score` | `relationship 35% + portfolio 30% + engagement 20% + risk inverse 15%`. |

## Trust Score

Basic formula:

```text
trust_score =
  evidence_score * 0.30 +
  control_score * 0.30 +
  confidence_score * 0.20 +
  error_score * 0.10 +
  trace_score * 0.10
```

Default component rules:

| Component | Rule |
|---|---|
| `evidence_score` | `100` if evidence exists, `60` if partial, `0` if none |
| `control_score` | `100` if all mandatory controls pass, `50` if review, `0` if failed |
| `confidence_score` | normalized `confidence` from `0-100` |
| `error_score` | `100` if no error, `50` if recoverable, `0` if fatal |
| `trace_score` | `100` if required event envelope is complete, else proportional completeness |

## Confidence

Basic rule:

```text
confidence = normalized average of emitted agent/model confidence values
```

Fallback:

```text
confidence = min(100, max(0, model_confidence))
```

If no confidence is emitted:

```text
confidence = 0
```

## Risk Level

AEGIS derives `risk_level`. External risk values are treated as indicators, not
the final authority.

Basic rule:

```text
CRITICAL = fatal error, blocked mandatory control, or critical finding
HIGH     = failed control, high-severity finding, trust_score < 50, confidence < 50
MEDIUM   = recoverable error, review control, medium finding, trust_score < 70, confidence < 70
LOW      = controls pass, evidence exists, trust_score >= 70, confidence >= 70
REVIEW   = insufficient data to classify
```

## Final Recommendation

AEGIS derives `final_recommendation`. For UI/backward compatibility, AEGIS also
sets `recommendation = final_recommendation`.

Basic rule:

```text
APPROVE  = LOW risk, controls pass, trust >= 70, confidence >= 70
MONITOR  = MEDIUM risk or minor findings
ESCALATE = HIGH/CRITICAL risk, failed mandatory control, or fatal error
REVIEW   = missing evidence, missing required envelope fields, or insufficient confidence
REJECT   = policy-prohibited output/action
```

If an app does not emit any recommendation, AEGIS still derives one using risk,
controls, trust, confidence, evidence, and error signals.

## Control Status

AEGIS derives final `control_status`.

```text
PASS   = all mandatory controls passed
REVIEW = at least one control needs review, none failed
FAILED = at least one mandatory control failed
BLOCKED = publication/release gate blocked
```

## Findings

AEGIS stores findings as:

| Field | Type | Example |
|---|---|---|
| `finding_id` | string | `FIND-001` |
| `severity` | enum | `HIGH` |
| `code` | string | `PII_EXPOSURE` |
| `message` | string | `Possible PII in response` |
| `source` | string | `external_app` or `aegis_policy` |
| `evidence_ids` | list[string] | `["EVID-001"]` |

## Error Code

AEGIS normalizes raw errors:

| Standard Code | Meaning |
|---|---|
| `NONE` | No error |
| `TIMEOUT` | Agent/tool timed out |
| `VALIDATION_ERROR` | Missing or invalid canonical field |
| `POLICY_BLOCKED` | Policy prevented release |
| `CONTROL_FAILED` | Mandatory control failed |
| `INSUFFICIENT_EVIDENCE` | Evidence missing/weak |
| `RUNTIME_ERROR` | Unhandled runtime failure |

## Executive Score Cards

AEGIS derives these score-card values after trust, confidence, risk, and controls
are normalized:

```text
relationship_score = trust_score * 0.60 + confidence * 0.40
engagement_score   = max(0, 100 - anomaly_count * 5)
portfolio_score    = (relationship_score + engagement_score) / 2
health_score       = relationship 35% + portfolio 30% + engagement 20% + risk inverse 15%
status             = HEALTHY if health_score >= 80, WATCH if >= 60, else REVIEW
```

## Output Fields Written By AEGIS

AEGIS writes these derived fields into the runtime state:

| Field | Type | Example |
|---|---|---|
| `trust_score` | number | `82.4` |
| `confidence` | number | `78.0` |
| `risk_level` | enum | `LOW` |
| `final_recommendation` | enum | `APPROVE` |
| `recommendation` | enum | `APPROVE` |
| `control_status` | enum | `PASS` |
| `error_code` | enum | `NONE` |
| `hitl_required` | boolean | `false` |
| `hitl_reasons` | list | `[]` |
| `customer_health.relationship_score` | number | `89.0` |
| `customer_health.engagement_score` | number | `100.0` |
| `customer_health.portfolio_score` | number | `94.5` |
| `customer_health.health_score` | number | `94.5` |

## HITL Link

AEGIS sets `hitl_required=true` when:

```text
risk_level in HIGH/CRITICAL
or confidence < 70
or trust_score < 70
or control_status failed/blocked/review
or recommendation in ESCALATE/REJECT/HOLD/REVIEW
or auto-release conditions are not fully met
```

Auto-release is allowed only when:

```text
final_recommendation = APPROVE
risk_level = LOW
control_status = PASS
compliance_status = COMPLIANT/PASS
evidence_count > 0
trust_score >= 70
confidence >= 70
```
