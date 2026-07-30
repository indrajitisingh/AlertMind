"""
guardrails.py — Pre-LLM safety checks for AlertMind.

Everything here runs BEFORE an alert is sent to OpenAI:
  1. Size limit          — reject absurdly large payloads
  2. Schema check         — make sure it actually looks like a Wazuh alert
  3. Sensitive-data redaction — strip obvious secrets before they leave the box
  4. Prompt-injection scan — flag alerts that contain LLM-directed instructions
"""

import copy
import re
from dataclasses import dataclass, field

MAX_ALERT_CHARS = 50_000

# Keys whose values get redacted before the alert is sent to the LLM.
SENSITIVE_KEY_PATTERNS = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "authorization", "auth_header", "credit_card", "ssn",
    "private_key", "session_id", "cookie",
)

# Phrases that suggest the alert content is trying to steer the model
# rather than just describing an event. Detection only — we don't try to
# be clever and "fix" the text, we flag it and let the analyst know.
INJECTION_PATTERNS = (
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (all |any )?(previous|prior|above)",
    r"you are now (a|an)\b",
    r"new system prompt",
    r"</?system>",
    r"act as (a|an)\b.{0,30}(admin|root|developer)",
    r"reveal (your|the) (system prompt|instructions)",
    r"jailbreak",
)
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


@dataclass
class GuardrailReport:
    ok: bool = True
    warnings: list = field(default_factory=list)
    sanitized_raw: dict = None


def check_size(raw_text: str) -> tuple:
    if len(raw_text) > MAX_ALERT_CHARS:
        return False, f"Alert is {len(raw_text):,} characters, exceeding the {MAX_ALERT_CHARS:,}-char limit."
    return True, None


def check_schema(parsed: dict) -> tuple:
    issues = []
    if not parsed.get("raw", {}).get("rule"):
        issues.append("Alert is missing a 'rule' object — this may not be a valid Wazuh alert.")
    if not parsed.get("description") or parsed["description"] == "No description provided":
        issues.append("Rule description is empty.")
    if parsed.get("agent_name") == "unknown-host":
        issues.append("No agent/host information found in the alert.")
    return (len(issues) == 0), issues


def scan_for_injection(raw_text: str) -> list:
    matches = sorted(set(m.group(0) for m in _INJECTION_RE.finditer(raw_text)))
    return matches


def redact_sensitive(raw: dict) -> dict:
    """Deep-copy the alert and replace any value whose key looks sensitive
    with a redaction marker. Applied to the payload sent to the LLM only —
    the original alert stays intact for display in the UI."""
    sanitized = copy.deepcopy(raw)

    def _redact(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    _redact(v)
                elif isinstance(k, str) and any(p in k.lower() for p in SENSITIVE_KEY_PATTERNS):
                    obj[k] = "[REDACTED]"
        elif isinstance(obj, list):
            for item in obj:
                _redact(item)

    _redact(sanitized)
    return sanitized


def run_guardrails(raw_text: str, parsed: dict) -> GuardrailReport:
    """Run all checks and return a single report. Nothing here hard-blocks
    analysis by default (a SOC tool shouldn't silently drop a real alert) —
    instead, issues are surfaced as warnings in the UI, and the payload sent
    to the LLM is always the redacted/sanitized version."""
    report = GuardrailReport()

    size_ok, size_msg = check_size(raw_text)
    if not size_ok:
        report.ok = False
        report.warnings.append(size_msg)

    schema_ok, schema_issues = check_schema(parsed)
    if not schema_ok:
        report.warnings.extend(schema_issues)

    injection_hits = scan_for_injection(raw_text)
    if injection_hits:
        report.warnings.append(
            "Possible prompt-injection content detected in the alert payload: "
            + "; ".join(f"'{h}'" for h in injection_hits)
        )

    report.sanitized_raw = redact_sensitive(parsed["raw"])
    return report
