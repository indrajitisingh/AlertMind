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
