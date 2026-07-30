"""
AlertMind — AI-Assisted SOC Alert Triage Dashboard
app.py is the orchestrator only: parsing, guardrails, analysis, styling, and
data retrieval all live in their own modules.
"""

import json
from datetime import datetime, timezone

import streamlit as st

from analyzer import analyze_alert, get_openai_client, MODEL
from opensearch_client import OpenSearchClient, OpenSearchError, USING_DEFAULT_CREDS as OS_DEFAULT_CREDS
from styles import inject_css, severity_color, badge_html
from utils import parse_wazuh_alert, extract_iocs, enrich_mitre

st.set_page_config(page_title="AlertMind", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = []
if "result" not in st.session_state:
    st.session_state.result = None
if "alert_input" not in st.session_state:
    st.session_state.alert_input = ""

result = st.session_state.result
header_accent = severity_color(result["severity"]) if result else None
inject_css(header_accent=header_accent)


def opensearch_status() -> bool:
    """Best-effort connectivity check — never raises, just reports."""
    try:
        return OpenSearchClient().is_reachable()
    except OpenSearchError:
        return False


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ AlertMind")
    st.caption(" AI-Assisted SOC Alert Triage")
    st.divider()

    has_key = get_openai_client() is not None
    os_ok = opensearch_status()

    st.markdown("**System Status**")
    st.markdown(f"{'🟢' if has_key else '🔴'} AI Engine ({MODEL}) — {'Ready' if has_key else 'No API key'}")
    st.markdown(f"{'🟢' if os_ok else '🔴'} OpenSearch — {'Connected' if os_ok else 'Unreachable'}")

    if not has_key:
        with st.expander("🔑 Set OpenAI API key"):
            key_input = st.text_input("API key", type="password", label_visibility="collapsed", placeholder="sk-...")
            if st.button("Save key", use_container_width=True):
                st.session_state["openai_key"] = key_input
                st.rerun()
        st.caption("Or set OPENAI_API_KEY as an env var / in .streamlit/secrets.toml")

    if not os_ok:
        st.caption("Set OPENSEARCH_URL / OPENSEARCH_USER / OPENSEARCH_PASSWORD as env vars to enable live alert fetch.")
    elif OS_DEFAULT_CREDS:
        st.caption("⚠️ Using default demo OpenSearch credentials — fine for a private repo, rotate before going public.")
    st.divider()

    st.markdown("**Capabilities**")
    st.markdown("- Live alert fetch from OpenSearch\n- AI triage & summarization\n- MITRE ATT&CK mapping\n- IOC extraction\n- Guided investigation\n- Incident response actions")
    st.divider()

    st.markdown("**Session**")
    st.metric("Alerts analyzed", len(st.session_state.history))
    if st.session_state.history:
        with st.expander("Recent alerts"):
            for h in reversed(st.session_state.history[-5:]):
                st.markdown(f"{badge_html(h['severity'])} &nbsp; `{h['rule_id']}` — {h['agent_name']}", unsafe_allow_html=True)

    st.divider()
    st.caption("AlertMind · v1.3.0")

# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown("""
<div class="app-header">
    <div>
        <h1>🛡️ AlertMind</h1>
        <p>AI-assisted Wazuh alert triage & incident response</p>
    </div>
</div>
""", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Top metrics
# --------------------------------------------------------------------------
today = datetime.now(timezone.utc).date()
today_count = sum(1 for h in st.session_state.history if h.get("_ts") and h["_ts"].date() == today)
critical_count = sum(1 for h in st.session_state.history if h["severity"] == "critical")
high_count = sum(1 for h in st.session_state.history if h["severity"] == "high")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Today's Alerts", today_count)
m2.metric("Critical", critical_count)
m3.metric("High", high_count)
m4.metric("AI Status", "Online" if get_openai_client() else "Fallback mode")

st.divider()

# --------------------------------------------------------------------------
# Input — live fetch from OpenSearch, or manual paste
# --------------------------------------------------------------------------
st.subheader("📥 Wazuh Alert Input")

mode = st.radio(
    "Input mode",
    ["🔌 Fetch from OpenSearch", "📋 Paste Manually"],
    horizontal=True,
    label_visibility="collapsed",
)

if mode == "🔌 Fetch from OpenSearch":
    fc1, fc2 = st.columns([1, 4])
    with fc1:
        if st.button("🔄 Fetch Latest Alert", use_container_width=True):
            try:
                alert = OpenSearchClient().get_latest_alert()
                if alert:
                    st.session_state.alert_input = json.dumps(alert, indent=2)
                    st.rerun()
                else:
                    st.info(f"No alerts found in the OpenSearch index.")
            except OpenSearchError as e:
                st.error(str(e))

alert_text = st.text_area(
    "Wazuh alert JSON",
    height=220,
    placeholder='{"rule": {"id": "5710", "level": 10, "description": "..."}, "agent": {...}}',
    label_visibility="collapsed",
    value=st.session_state.alert_input,
)

c1, c2 = st.columns([1, 5])
with c1:
    analyze_clicked = st.button("🔍 Analyze Alert", use_container_width=True, type="primary")
with c2:
    if st.button("🗑️ Clear"):
        st.session_state.result = None
        st.session_state.alert_input = ""
        st.rerun()

if analyze_clicked:
    if not alert_text.strip():
        st.warning("Please fetch or paste a Wazuh alert first.")
    else:
        try:
            with st.spinner("Parsing and analyzing alert..."):
                parsed = parse_wazuh_alert(alert_text)
                ai_result = analyze_alert(alert_text, parsed)
                ai_result.update({
                    "rule_id": parsed["rule_id"],
                    "agent_name": parsed["agent_name"],
                    "raw": parsed["raw"],
                    "iocs": extract_iocs(parsed["raw"]),
                    "mitre_enriched": enrich_mitre(ai_result["mitre"]),
                    "_ts": datetime.now(timezone.utc),
                })
            st.session_state.result = ai_result
            st.session_state.history.append(ai_result)
            st.success("Analysis complete.")
            st.rerun()
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON — could not parse alert: {e}")
        except KeyError as e:
            st.error(f"Alert is missing an expected field ({e}). Is this a valid Wazuh alert?")
        except Exception as e:
            st.error(f"Unexpected error while analyzing this alert: {e}")

st.divider()

# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------
result = st.session_state.result

if result:
    if result.get("guardrail_warnings"):
        warn_items = "".join(f"<li>{w}</li>" for w in result["guardrail_warnings"])
        st.markdown(f'<div class="warning-block"><b>⚠️ Guardrail notices</b><ul>{warn_items}</ul></div>', unsafe_allow_html=True)

    top1, top2, top3 = st.columns(3)
    top1.metric("Rule ID", result["rule_id"])
    top2.metric("Affected Host", result["agent_name"])
    with top3:
        st.markdown("**Severity**")
        st.markdown(badge_html(result["severity"]), unsafe_allow_html=True)
    st.divider()

col1, col2 = st.columns(2)

with col1:
    if result:
        sev_c = severity_color(result["severity"])
        st.markdown(
            f'<div class="card" style="border-left:3px solid {sev_c};"><h4>📝 AI Summary</h4><p>{result["summary"]}</p></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="card empty"><h4>📝 AI Summary</h4><p>Waiting for analysis...</p></div>', unsafe_allow_html=True)

    if result:
        if result["mitre_enriched"]:
            rows = "".join(
                f'<li><b>{m["id"]}</b> — {m["name"]} <span style="color:#8ea0bd;">({m["tactic"]})</span></li>'
                for m in result["mitre_enriched"]
            )
        else:
            rows = "<li>No MITRE techniques mapped for this alert.</li>"
        st.markdown(f'<div class="card"><h4>🛡️ MITRE ATT&CK</h4><ul>{rows}</ul></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="card empty"><h4>🛡️ MITRE ATT&CK</h4><p>Waiting for analysis...</p></div>', unsafe_allow_html=True)

    if result:
        iocs = result["iocs"]
        chip_groups = ""
        labels = {"ips": "IP Addresses", "users": "Users", "processes": "Processes", "hashes": "Hashes", "domains": "Domains"}
        for key, label in labels.items():
            values = iocs.get(key, [])
            if values:
                chips = "".join(f'<span class="ioc-chip">{v}</span>' for v in values)
                chip_groups += f"<p style='margin-bottom:4px;'><b>{label}</b></p><div style='margin-bottom:10px;'>{chips}</div>"
        if not chip_groups:
            chip_groups = "<p>No IOCs detected in this alert.</p>"
        st.markdown(f'<div class="card"><h4>📌 Extracted IOCs</h4>{chip_groups}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="card empty"><h4>📌 Extracted IOCs</h4><p>Waiting for analysis...</p></div>', unsafe_allow_html=True)

with col2:
    if result:
        steps_list = "".join(f"<li>{s}</li>" for s in result["investigation_steps"]) or "<li>No steps returned.</li>"
        st.markdown(f'<div class="card"><h4>🔎 Investigation Steps</h4><ul>{steps_list}</ul></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="card empty"><h4>🔎 Investigation Steps</h4><p>Waiting for analysis...</p></div>', unsafe_allow_html=True)

    if result:
        sev_c = severity_color(result["severity"])
        actions_list = "".join(f"<li>{a}</li>" for a in result["response_actions"]) or "<li>No actions returned.</li>"
        st.markdown(
            f'<div class="card" style="border-left:3px solid {sev_c};"><h4>🚨 Incident Response</h4><ul>{actions_list}</ul></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="card empty"><h4>🚨 Incident Response</h4><p>Waiting for analysis...</p></div>', unsafe_allow_html=True)

if result:
    with st.expander("📄 Raw Alert JSON"):
        st.markdown(f'<div class="raw-block">{json.dumps(result["raw"], indent=2)}</div>', unsafe_allow_html=True)

st.markdown('<div class="footer">AlertMind · v1.3.0 &nbsp;|&nbsp; AI-Powered Security Operations Assistant</div>', unsafe_allow_html=True)
