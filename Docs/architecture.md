# AlertMind System Architecture

## Overview

AlertMind is a lab-based SOC platform that centralizes endpoint telemetry, performs rule-based threat detection, and provides a foundation for **future** AI-assisted alert analysis. The current implementation uses **Sysmon** and the **Wazuh Agent** on a Windows endpoint to generate and forward telemetry to a **Wazuh Manager** hosted on Ubuntu Server, with monitoring and triage performed through the **Wazuh Dashboard**.

## Architecture Principles

The AlertMind architecture is designed around a centralized SOC model that separates endpoint telemetry collection, event processing, detection engineering, and analyst visibility. This modular approach enables independent enhancement of detection content and future AI capabilities without impacting the core monitoring infrastructure.

**Scope note:** AI-assisted alert analysis is **not implemented in the current phase** and is documented as a planned enhancement.

---

## High-Level Architecture

```text
+-------------------------------------------------------------------+
|                         Windows 10 Endpoint                        |
|-------------------------------------------------------------------|
|  - Sysmon                                                          |
|  - Wazuh Agent                                                     |
|                                                                     |
|  Generates endpoint telemetry and forwards security events to Wazuh |
+-----------------------------------+--------------------------------+
                                    |
                                    | Event forwarding (agent -> manager)
                                    v
+-------------------------------------------------------------------+
|                        Ubuntu Server (SOC Platform)                 |
|-------------------------------------------------------------------|
|  Wazuh Manager                                                     |
|  - Log collection & normalization                                  |
|  - Rule evaluation / detection engine                              |
|  - Alert generation (severity)                                     |
|  - MITRE ATT&CK technique mapping (where applicable)               |
|                                                                     |
|  Wazuh Dashboard                                                   |
|  - Security monitoring / alert triage                              |
|  - Threat hunting views                                            |
+-----------------------------------+--------------------------------+
                                    |
                                    | Alerts / findings (display)
                                    v
+-------------------------------------------------------------------+
|              AlertMind AI Analysis Module (Planned)                |
|-------------------------------------------------------------------|
|  - Alert parsing                                                   |
|  - Investigation summarization                                     |
|  - Detection explanation                                           |
|  - Response recommendations                                        |
+-------------------------------------------------------------------+
```

---

## Architecture Components

### 1) Endpoint Layer (Telemetry Source)

**Platform**
- Windows 10

**Components**
- Sysmon
- Wazuh Agent

**Responsibilities**
- Capture endpoint telemetry (e.g., process, network, and system activity via Sysmon).
- Forward events through the Wazuh Agent to the Wazuh Manager for centralized processing.

**Status**
- **Completed / Operational** (endpoint monitoring and Sysmon ingestion are functioning in the lab).

---

### 2) SOC Platform Layer (Collection & Visibility)

**Platform**
- Ubuntu Server

**Components**
- Wazuh Manager
- Wazuh Dashboard

**Responsibilities**
- Ingest and process endpoint events received from agents.
- Apply built-in and custom rules to generate security alerts.
- Provide analyst-facing monitoring and threat hunting views via the Wazuh Dashboard.

**Status**
- **Completed / Operational** (manager and dashboard are functioning in the lab).

---

### 3) Detection Layer (Rules & Classification)

**Components**
- Built-in Wazuh detection rules
- Custom detection rules
- MITRE ATT&CK mapping

**Responsibilities**
- Evaluate processed events against detection logic.
- Generate alerts with severity levels based on rule matches.
- Map alerts/techniques to MITRE ATT&CK where supported by the detection content.

**Status**
- **In Development** (custom detection engineering and validation are ongoing).

---

### 4) AI Analysis Layer (Planned Enhancement)

**Planned Technologies**
- Python
- Streamlit
- Large Language Model (LLM)

**Planned Responsibilities**
- Parse Wazuh alerts and present analyst-friendly context.
- Provide investigation summaries and explain rule triggers/detection outcomes.
- Recommend response actions to support triage and investigation.

**Status**
- **Planned / Future Phase** (not currently implemented).

---

## Event Processing Workflow

```text
User / Host Activity
        |
        v
Windows 10 Endpoint (Sysmon)
        |
        v
Wazuh Agent (collects & forwards)
        |
        v
Wazuh Manager (ingest -> normalize/process -> evaluate rules)
        |
        v
Alert generated (severity + optional MITRE mapping)
        |
        v
Wazuh Dashboard (monitoring, triage, hunting)
        |
        v
AlertMind AI Analysis Module (Planned)
```

---

## Technology Stack

| Layer | Technology |
|------|------------|
| Virtualization | VMware Workstation |
| Operating Systems | Windows 10 (endpoint), Ubuntu Server (SOC platform) |
| Endpoint Telemetry | Sysmon |
| Endpoint Collection/Forwarding | Wazuh Agent |
| Central Platform (SIEM/SOC tooling) | Wazuh Manager, Wazuh Dashboard |
| Detection Engineering | Wazuh built-in rules, custom rules |
| Technique Classification | MITRE ATT&CK framework |
| Development (planned AI module) | Python |
| UI (planned AI module) | Streamlit |
| LLM (planned AI module) | Large Language Model (LLM) |

---

## Implementation Status (as of current phase)

| Component | Status |
|-----------|--------|
| Virtual lab environment | ✅ Completed |
| Windows endpoint (agent-based monitoring) | ✅ Operational |
| Sysmon telemetry | ✅ Operational |
| Wazuh Agent | ✅ Operational |
| Wazuh Manager | ✅ Operational |
| Wazuh Dashboard | ✅ Operational |
| Custom detection rule development & validation | 🔄 In Development |
| AlertMind AI Analysis Module | 📋 Planned |

---

## Roadmap (Non-Implemented Enhancements)

### Phase 2 — Detection Engineering Completion
- Complete custom detection rule development.
- Validate and tune detection logic using Windows endpoint telemetry.
- Expand MITRE ATT&CK technique coverage through additional detection content.

### Phase 3 — AI Analysis Module Integration
- Build the AlertMind AI Analysis Module (Python + Streamlit).
- Integrate AI-assisted alert interpretation based on Wazuh alert outputs.
- Generate investigation summaries and response recommendations for analyst use.
