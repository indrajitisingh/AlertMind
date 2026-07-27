# AlertMind — Weekly Progress Log

## Week 1 — Lab Environment & Architecture Setup

**Objective:** Establish the virtual SOC lab environment and prepare the project structure.

- Created the AlertMind GitHub repository and organized the project directories.
- Designed the initial architecture for the SOC monitoring environment.
- Deployed two virtual machines using VMware Workstation:
  - Ubuntu Server (Wazuh Manager & Dashboard)
  - Windows 10 (Monitored Endpoint)
- Configured networking between both virtual machines to enable secure communication.
- Verified connectivity between the Ubuntu server and Windows endpoint.

**Outcome:**
The virtual lab environment was successfully deployed and prepared for SOC infrastructure installation.

---

## Week 2 — SOC Infrastructure Deployment

**Objective:** Deploy the SOC monitoring stack and validate endpoint telemetry.

- Installed and configured Wazuh Manager and Wazuh Dashboard on Ubuntu.
- Installed and enrolled the Wazuh Agent on the Windows endpoint.
- Installed Sysmon to collect Windows security events.
- Verified successful communication between the Windows endpoint and the Wazuh Manager.
- Confirmed security events were successfully displayed in the Wazuh Threat Hunting dashboard.
- Captured project screenshots for documentation.

**Outcome:**
The SOC monitoring infrastructure is fully operational with successful log collection and endpoint monitoring.

---

## Current Status

| Component | Status |
|----------|--------|
| VMware Lab Environment | ✅ Operational |
| Ubuntu Server | ✅ Running |
| Wazuh Manager | ✅ Operational |
| Wazuh Dashboard | ✅ Operational |
| Windows Endpoint | ✅ Connected |
| Wazuh Agent | ✅ Reporting |
| Sysmon | ✅ Collecting Events |
| Threat Hunting Dashboard | ✅ Receiving Events |
| Documentation | ✅ Phase 1 Completed |

---

## Next Phase

- Develop custom detection rules.
- Validate detection events using generated telemetry.
- Begin implementation of the AI-assisted SOC analysis module.

---


# 📅 Week 3 Progress Log

## 🎯 Objective
Enhance the AlertMind SOC platform by implementing MITRE ATT&CK mapping, developing a dedicated MITRE dashboard, and preparing the environment for the AI-powered SOC Assistant.

---

## ✅ Tasks Completed

### 1. MITRE ATT&CK Rule Verification
- Reviewed `local_rules.xml`.
- Verified that custom Wazuh detection rules contain valid MITRE ATT&CK mappings.
- Confirmed MITRE IDs for custom detection rules.

### 2. MITRE Field Validation
- Verified that Wazuh successfully indexed:
  - `rule.mitre.id`
  - `rule.mitre.tactic`
  - `rule.mitre.technique`

### 3. MITRE ATT&CK Dashboard Development
Developed a dedicated MITRE ATT&CK Dashboard containing:
- Top MITRE ATT&CK Techniques
- Top MITRE ATT&CK Tactics
- Total MITRE Alerts
- MITRE Alerts Over Time

### 4. Documentation
- Captured implementation screenshots.
- Organized dashboard evidence for GitHub and the final report.

### 5. AI Assistant Environment Setup
- Created a Python virtual environment.
- Installed Streamlit successfully.
- Prepared the development environment for the AlertMind AI Assistant.

---

## 📈 Progress Summary

Completed:
- Wazuh SIEM Deployment
- Windows Sysmon Integration
- Custom Detection Rules
- Daily SOC Dashboard
- MITRE ATT&CK Dashboard
- Streamlit Environment Setup

Upcoming:
- AI Assistant Development
- Guardrails
- Prompt Library
- Incident Response Playbooks
- Atomic Red Team Validation
