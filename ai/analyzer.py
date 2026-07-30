"""
analyzer.py — The single integration point between AlertMind and the LLM backend.
Runs guardrails first, then calls OpenAI; falls back to deterministic
rule-based analysis if no key is set or the call fails.
"""

import json
import os

import streamlit as st
from openai import OpenAI

from guardrails import run_guardrails
from prompts import SYSTEM_PROMPT, build_user_message
from utils import severity_from_level

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
FALLBACK_NOTE = " (fallback — AI analysis unavailable)"


def get_openai_client():
    """
    Returns an OpenAI client if an API key is available.
    Looks in Streamlit secrets, environment variables,
    and session state. Returns None if no key is found.
    """

    api_key = None

    # Try Streamlit secrets safely
    try:
        api_key = st.secrets.get("OPENAI_API_KEY")
    except Exception:
        pass

    # Environment variable fallback
    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")

    # Session state fallback
    if not api_key:
        api_key = st.session_state.get("openai_key")

    if not api_key:
        return None

    return OpenAI(api_key=api_key)



def rule_based_fallback(parsed: dict, sev: str) -> dict:
    return {
        "summary": f"Rule {parsed['rule_id']} fired on {parsed['agent_name']} "
                   f"({parsed['agent_ip']}) at severity level {parsed['level']}. "
                   f"{parsed['description']}{FALLBACK_NOTE}",
        "mitre": parsed["mitre_ids"] or [],
        "tactics": parsed["mitre_tactics"] or ["N/A"],
        "investigation_steps": [
            f"Pull the last 24h of activity from agent '{parsed['agent_name']}' ({parsed['agent_ip']})",
            "Check for related alerts from the same source IP / user in the alert window",
            "Correlate rule ID against recent threat intel / IOC feeds",
            "Review authentication and process-execution logs around the timestamp",
        ],
        "response_actions": [
            "Isolate the affected host if lateral movement indicators are present" if sev in ("high", "critical") else "Continue monitoring — no immediate isolation required",
            "Escalate to Tier 2 if severity is high/critical" if sev in ("high", "critical") else "Log for trend analysis",
            "Document findings in the case management system",
        ],
        "severity": sev,
        "guardrail_warnings": [],
    }


def analyze_alert(raw_text: str, parsed: dict) -> dict:
    """Full pipeline: guardrails -> (OpenAI | fallback) -> normalized result dict."""
    sev_fallback = severity_from_level(parsed["level"])
    report = run_guardrails(raw_text, parsed)

    client = get_openai_client()
    if client is None:
        result = rule_based_fallback(parsed, sev_fallback)
        result["guardrail_warnings"] = report.warnings
        return result

    try:
        response = client.chat.completions.create(
            model=MODEL,
            response_format={"type": "json_object"},
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_message(report.sanitized_raw)},
            ],
        )
        ai_result = json.loads(response.choices[0].message.content)

        result = {
            "summary": ai_result.get("summary", "No summary returned."),
            "mitre": ai_result.get("mitre") or parsed["mitre_ids"] or [],
            "tactics": ai_result.get("tactics") or parsed["mitre_tactics"] or ["N/A"],
            "investigation_steps": ai_result.get("investigation_steps", []),
            "response_actions": ai_result.get("response_actions", []),
            "severity": ai_result.get("severity", sev_fallback),
            "guardrail_warnings": report.warnings,
        }
        return result

    except Exception as e:
        st.warning(f"OpenAI analysis failed ({e}) — showing rule-based fallback instead.")
        result = rule_based_fallback(parsed, sev_fallback)
        result["guardrail_warnings"] = report.warnings
        return result
