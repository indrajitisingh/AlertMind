"""
styles.py — CSS and severity-to-color helpers, kept out of app.py.
"""

import streamlit as st

SEVERITY_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#4ade80",
    "unknown": "#94a3b8",
}


def severity_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev, SEVERITY_COLORS["unknown"])


def badge_html(sev: str) -> str:
    return f'<span class="badge badge-{sev if sev in SEVERITY_COLORS else "unknown"}">{sev.upper()}</span>'


CSS = """
:root {
    --bg: #0b1220;
    --panel: #131b2c;
    --panel-border: #223049;
    --text-dim: #8ea0bd;
    --accent: #3aa0ff;
}

.stApp { background-color: var(--bg); }
.block-container { padding-top: 1.2rem; max-width: 1400px; }

.app-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-left: 4px solid var(--header-accent, var(--accent));
    border-radius: 10px;
    margin-bottom: 18px;
}
.app-header h1 { font-size: 1.35rem; margin: 0; color: #e6edf7; }
.app-header p { margin: 0; color: var(--text-dim); font-size: 0.85rem; }

.card {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 14px;
    height: 100%;
}
.card h4 {
    margin: 0 0 10px 0;
    font-size: 0.95rem;
    color: #cbd6e6;
    border-bottom: 1px solid var(--panel-border);
    padding-bottom: 8px;
}
.card p, .card li { color: #b9c4d6; font-size: 0.88rem; line-height: 1.5; }
.card.empty p { color: #5a6a85; font-style: italic; }

.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.3px;
}
.badge-critical { background: #451a1a; color: #f87171; border: 1px solid #7f1d1d; }
.badge-high     { background: #47270f; color: #fb923c; border: 1px solid #7c2d12; }
.badge-medium   { background: #453e0f; color: #facc15; border: 1px solid #713f12; }
.badge-low      { background: #0f3a2e; color: #4ade80; border: 1px solid #14532d; }
.badge-unknown  { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }

.ioc-chip {
    display: inline-block;
    background: #0a0f1a;
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 2px 8px;
    margin: 2px 4px 2px 0;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.76rem;
    color: #9fb3d1;
}

.raw-block {
    background: #0a0f1a;
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    padding: 10px 12px;
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 0.78rem;
    color: #9fb3d1;
    overflow-x: auto;
}

.warning-block {
    background: #2a1a0f;
    border: 1px solid #7c2d12;
    border-radius: 8px;
    padding: 10px 14px;
    color: #fdba74;
    font-size: 0.82rem;
    margin-bottom: 14px;
}

.footer {
    text-align: center;
    color: #4a5a75;
    margin-top: 36px;
    font-size: 0.78rem;
    padding-bottom: 10px;
}

section[data-testid="stSidebar"] { background-color: var(--panel); border-right: 1px solid var(--panel-border); }
"""


def inject_css(header_accent: str = None):
    accent_override = f":root {{ --header-accent: {header_accent}; }}" if header_accent else ""
    st.markdown(f"<style>{CSS}\n{accent_override}</style>", unsafe_allow_html=True)
