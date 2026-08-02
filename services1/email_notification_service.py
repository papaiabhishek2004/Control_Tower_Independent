"""Email notification helpers for AEGIS runtime alerts.

Configuration is intentionally environment-driven so credentials are not stored
in source code.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Dict, Iterable, List, Tuple


SMTP_ENV_KEYS = {
    "host": "AEGIS_SMTP_HOST",
    "port": "AEGIS_SMTP_PORT",
    "username": "AEGIS_SMTP_USERNAME",
    "password": "AEGIS_SMTP_PASSWORD",
    "sender": "AEGIS_ALERT_FROM",
    "recipients": "AEGIS_ALERT_TO",
    "use_tls": "AEGIS_SMTP_USE_TLS",
}


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def email_config_status() -> Dict[str, Any]:
    host = _env(SMTP_ENV_KEYS["host"])
    sender = _env(SMTP_ENV_KEYS["sender"])
    recipients = _env(SMTP_ENV_KEYS["recipients"])
    missing = [
        key
        for key, value in {
            "AEGIS_SMTP_HOST": host,
            "AEGIS_ALERT_FROM": sender,
            "AEGIS_ALERT_TO": recipients,
        }.items()
        if not value
    ]
    return {
        "configured": not missing,
        "missing": missing,
        "host": host or "-",
        "sender": sender or "-",
        "recipients": recipients or "-",
    }


def build_runtime_alerts(result: Dict[str, Any]) -> List[Dict[str, str]]:
    result = result if isinstance(result, dict) else {}
    alerts: List[Dict[str, str]] = []

    def add(severity: str, signal: str, detail: str) -> None:
        alerts.append({"Severity": severity, "Signal": signal, "Detail": detail})

    for row in result.get("owasp_critical_findings") or result.get("owasp_findings") or []:
        if isinstance(row, dict) and str(row.get("status", "")).upper() in {"REVIEW", "FAIL", "CRITICAL"}:
            add("Critical", "OWASP AI control review", row.get("findings") or row.get("reason") or "Security control requires review.")

    if result.get("customer_not_found") or result.get("explicit_error"):
        add("High", "Input / data coverage issue", str(result.get("explicit_error") or "Customer or required source data was not found."))

    trust = result.get("trust_score")
    confidence = result.get("confidence")
    try:
        if trust is not None and float(trust) < 60:
            add("High", "Trust threshold breach", f"Trust score is {float(trust):.1f}, below threshold 60.")
    except (TypeError, ValueError):
        pass
    try:
        if confidence is not None and float(confidence) < 60:
            add("Medium", "Confidence threshold breach", f"Confidence is {float(confidence):.1f}, below threshold 60.")
    except (TypeError, ValueError):
        pass

    hallucination = str(result.get("hallucination_risk") or result.get("hallucination") or "").upper()
    if hallucination in {"HIGH", "CRITICAL"}:
        add("Critical", "Hallucination risk", f"Hallucination risk is {hallucination}.")

    runtime_health = result.get("runtime_health_v2") or result.get("runtime_health") or {}
    if isinstance(runtime_health, dict):
        status = str(runtime_health.get("status") or "").upper()
        if status and status not in {"HEALTHY", "GOOD", "OK", "PASS"}:
            add("Medium", "Runtime health", f"Runtime health status is {status}.")
        for warning in runtime_health.get("warnings") or []:
            add("Medium", "Runtime warning", str(warning))

    for row in result.get("runtime_errors") or result.get("errors") or []:
        add("High", "Runtime error", str(row))

    return alerts


def build_alert_email(result: Dict[str, Any], alerts: Iterable[Dict[str, str]]) -> Tuple[str, str]:
    result = result if isinstance(result, dict) else {}
    alerts = list(alerts)
    runtime_id = result.get("runtime_id") or result.get("run_id") or "-"
    customer_id = result.get("customer_id") or result.get("customer") or "-"
    recommendation = result.get("recommendation") or "-"
    subject = f"AEGIS Alert: {len(alerts)} issue(s) for {customer_id} / {runtime_id}"
    lines = [
        "AEGIS Enterprise Control Tower Alert",
        "",
        f"Runtime ID: {runtime_id}",
        f"Customer / Entity: {customer_id}",
        f"Recommendation: {recommendation}",
        "",
        "Alert Findings:",
    ]
    if alerts:
        for idx, alert in enumerate(alerts, start=1):
            lines.append(f"{idx}. [{alert.get('Severity', '-')}] {alert.get('Signal', '-')}: {alert.get('Detail', '-')}")
    else:
        lines.append("No active threshold breach detected. This is a connectivity/test notification.")
    lines.extend([
        "",
        "Suggested action: Open AEGIS Runtime Observability and Auditability tabs for evidence, controls, and remediation detail.",
    ])
    return subject, "\n".join(lines)


def send_alert_email(subject: str, body: str) -> Dict[str, Any]:
    status = email_config_status()
    if not status["configured"]:
        return {"sent": False, "error": "Missing mail configuration: " + ", ".join(status["missing"])}

    host = _env(SMTP_ENV_KEYS["host"])
    port = int(_env(SMTP_ENV_KEYS["port"], "587"))
    username = _env(SMTP_ENV_KEYS["username"])
    password = _env(SMTP_ENV_KEYS["password"])
    sender = _env(SMTP_ENV_KEYS["sender"])
    recipients = [item.strip() for item in _env(SMTP_ENV_KEYS["recipients"]).split(",") if item.strip()]
    use_tls = _env(SMTP_ENV_KEYS["use_tls"], "true").casefold() not in {"0", "false", "no"}

    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            if use_tls:
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.send_message(message)
        return {"sent": True, "recipients": recipients}
    except Exception as exc:
        return {"sent": False, "error": str(exc)}


def dispatch_runtime_alerts(result: Dict[str, Any], *, auto_send: bool | None = None) -> Dict[str, Any]:
    """Build and optionally send runtime alert notifications.

    Auto-send is deliberately environment-gated. This lets AEGIS run safely in
    demo/offline mode while still being production-ready when SMTP and the
    explicit auto-send flag are configured.
    """
    result = result if isinstance(result, dict) else {}
    alerts = build_runtime_alerts(result)
    mail_status = email_config_status()
    subject, body = build_alert_email(result, alerts)
    if auto_send is None:
        auto_send = _env("AEGIS_ALERT_AUTO_SEND", "false").casefold() in {"1", "true", "yes"}
    dispatch = {
        "mode": "environment_gated_email",
        "auto_send_enabled": bool(auto_send),
        "smtp_configured": bool(mail_status.get("configured")),
        "dispatch_attempted": False,
        "sent": False,
        "active_alert_count": len(alerts),
        "critical_alert_count": sum(1 for row in alerts if str(row.get("Severity", "")).upper() == "CRITICAL"),
        "high_alert_count": sum(1 for row in alerts if str(row.get("Severity", "")).upper() == "HIGH"),
        "missing_configuration": mail_status.get("missing", []),
        "subject_preview": subject,
        "body_preview": body,
        "alerts": alerts,
    }
    if not alerts:
        dispatch["dispatch_status"] = "NO_ALERTS"
        dispatch["reason"] = "No notification-worthy findings detected."
        return dispatch
    if not auto_send:
        dispatch["dispatch_status"] = "READY_MANUAL_SEND"
        dispatch["reason"] = "Auto-send disabled. Streamlit can send manually when SMTP is configured."
        return dispatch
    if not mail_status.get("configured"):
        dispatch["dispatch_status"] = "NOT_CONFIGURED"
        dispatch["reason"] = "SMTP configuration missing."
        return dispatch
    send_result = send_alert_email(subject, body)
    dispatch["dispatch_attempted"] = True
    dispatch["sent"] = bool(send_result.get("sent"))
    dispatch["dispatch_status"] = "SENT" if send_result.get("sent") else "FAILED"
    dispatch["send_result"] = send_result
    return dispatch
