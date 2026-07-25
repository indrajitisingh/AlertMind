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
Develop, implement, and validate custom Wazuh detection rules for the AlertMind SIEM project to detect suspicious Windows command-line activities.

---

## ✅ Tasks Completed

- Developed and implemented **10 custom detection rules** in Wazuh.
- Updated the **local_rules.xml** configuration file with custom detection logic.
- Restarted the Wazuh Manager to apply the new rule configuration.
- Successfully tested all custom rules using Windows command-line activities.
- Verified alert generation for:
  - whoami
  - ipconfig
  - hostname
  - netstat
  - cmd.exe
  - powershell.exe
  - certutil.exe
  - nslookup
  - ping
  - net localgroup
- Confirmed successful alert generation in the Wazuh Dashboard.
- Captured screenshots for documentation and GitHub repository.

---

## 🔍 Challenges Faced

- Initial issues with custom rule syntax and alert triggering.
- Rule IDs and field matching required multiple revisions.
- Fine-tuned rule conditions to eliminate false positives and ensure successful detection.

---

## 💡 Key Learnings

- Understood the workflow of developing custom Wazuh detection rules.
- Learned how Sysmon logs are processed and correlated by Wazuh.
- Gained practical experience in Windows attack detection and alert validation.
- Improved knowledge of SIEM rule tuning and event analysis.

---

## 📊 Current Status

🟢 **Completed**

All planned custom detection rules have been successfully implemented, validated, and documented for the AlertMind project.

---

## 🚀 Plan for Week 4

- Develop the **Daily SOC Briefing Dashboard**.
- Create visualizations for:
  - Total Alerts
  - Top Triggered Rules
  - Top Agents
  - Alerts Over Time
- Organize project documentation and GitHub repository.
- Prepare dashboard screenshots for the final report.
