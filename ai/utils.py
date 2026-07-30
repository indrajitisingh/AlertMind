"""
utils.py — Wazuh alert parsing, severity mapping, IOC extraction, MITRE enrichment.
No Streamlit or OpenAI imports here — keep this module pure/testable.
"""

import json
import re
from datetime import datetime

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------
def severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# Wazuh alert parsing
# --------------------------------------------------------------------------
def parse_wazuh_alert(raw_text: str) -> dict:
    """Parse a Wazuh JSON alert string into the fields the UI needs.
    Raises json.JSONDecodeError on invalid JSON — caller handles that.
    """
    data = json.loads(raw_text)
# Handle Wazuh Threat Hunting exports
    if "_source" in data:
        data = data["_source"]

    rule = data.get("rule", {})
    agent = data.get("agent", {})
    return {
        "raw": data,
        "rule_id": rule.get("id", "N/A"),
        "description": rule.get("description", "No description provided"),
        "level": rule.get("level", 0),
        "mitre_ids": rule.get("mitre", {}).get("id", []),
        "mitre_tactics": rule.get("mitre", {}).get("tactic", []),
        "agent_name": agent.get("name", "unknown-host"),
        "agent_ip": agent.get("ip", "N/A"),
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "full_log": data.get("full_log", ""),
    }


# --------------------------------------------------------------------------
# MITRE ATT&CK enrichment
# --------------------------------------------------------------------------
# Small local lookup table so common technique IDs get human-readable names
# without an external API call. Extend as needed, or swap for the full
# MITRE ATT&CK STIX bundle if you want complete coverage.
MITRE_TECHNIQUES = {
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1078": ("Defense Evasion / Persistence", "Valid Accounts"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1053": ("Execution / Persistence", "Scheduled Task/Job"),
    "T1055": ("Defense Evasion / Privilege Escalation", "Process Injection"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1548": ("Privilege Escalation / Defense Evasion", "Abuse Elevation Control Mechanism"),
    "T1003": ("Credential Access", "OS Credential Dumping"),
    "T1566": ("Initial Access", "Phishing"),
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1204": ("Execution", "User Execution"),
    "T1082": ("Discovery", "System Information Discovery"),
}


def enrich_mitre(technique_ids: list) -> list:
    """Map raw MITRE technique IDs to {id, tactic, name}. Unknown IDs are
    returned with a generic placeholder so the UI never breaks."""
    enriched = []
    for tid in technique_ids or []:
        tactic, name = MITRE_TECHNIQUES.get(tid, ("Unmapped", "Unknown technique"))
        enriched.append({"id": tid, "tactic": tactic, "name": name})
    return enriched


# --------------------------------------------------------------------------
# IOC extraction
# --------------------------------------------------------------------------
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _walk(obj, callback, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk(v, callback, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, callback, path)
    else:
        callback(path, obj)


def extract_iocs(raw: dict) -> dict:
    """Recursively scan a parsed alert for IPs, hashes, domains, users, and
    process names. Field-name heuristics are used for users/processes since
    those aren't uniquely identifiable by value pattern alone."""
    iocs = {"ips": set(), "users": set(), "processes": set(), "hashes": set(), "domains": set()}

    def cb(path, value):
        if not isinstance(value, str) or not value.strip():
            return
        v = value.strip()
        key = path.lower()

        if _IP_RE.match(v):
            iocs["ips"].add(v)
        elif _HASH_RE.match(v):
            iocs["hashes"].add(v)
        elif _DOMAIN_RE.match(v) and not v.replace(".", "").isdigit():
            iocs["domains"].add(v)
        elif any(k in key for k in ("user", "account")) and len(v) < 100:
            iocs["users"].add(v)
        elif any(k in key for k in ("process", "image", "cmd", "command")) and len(v) < 300:
            iocs["processes"].add(v)

    _walk(raw, cb)
    return {k: sorted(v) for k, v in iocs.items()}
