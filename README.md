# 🛡️ AlertMind

## AI-Assisted Security Operations Centre (SOC) Alert Triage Platform

AlertMind is an AI-assisted Security Operations Centre (SOC) alert triage platform that combines **Wazuh SIEM** with **OpenAI GPT-4o-mini** to help analysts move from **"alert received"** to **"informed decision"** faster.

Unlike autonomous security systems, AlertMind never performs detection or response on its own. Wazuh remains the detection engine, while AlertMind provides structured AI-assisted analysis to support human analysts during investigation and incident response.

> 🎓 **Capstone Project**  
> **IIT Roorkee × Futurense**  
> PG Certificate in AI & GenAI-Powered Cybersecurity

**Team Brain Bytes**

- Indrajit Singh
- Jay Goyal
- Vansh Gupta

---

# 📚 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [AI Processing Pipeline](#ai-processing-pipeline)
- [Features](#features)
- [Custom Detection Rules](#custom-detection-rules)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Dashboard](#dashboard)
- [Guardrails & Responsible AI](#guardrails--responsible-ai)
- [Incident Response Playbook](#incident-response-playbook)
- [Workflow Efficiency](#workflow-efficiency-mttd--mttr)
- [Future Improvements](#future-improvements)
- [Disclaimer](#disclaimer)
- [Team](#team)

---

# Overview

A SOC analyst's biggest challenge is rarely **detecting** an attack—it's understanding what the alert means and deciding what to do next.

AlertMind addresses this challenge by transforming raw Wazuh alerts into structured security intelligence.

For every alert, AlertMind provides:

- 🧠 AI-generated executive summary
- 🎯 MITRE ATT&CK mapping
- 📊 Severity assessment
- 🔍 IOC extraction
- 🧭 Investigation guidance
- 🚨 Incident response recommendations

The analyst reviews these recommendations before taking any action.

> **AlertMind is a decision-support tool—not an autonomous SOC analyst.**

---

# Architecture

https://github.com/indrajitisingh/AlertMind/blob/main/screenshot/AlertMind_architecture.jpeg

The platform consists of:

| Component | Purpose |
|------------|----------|
| Wazuh Agent | Collects endpoint telemetry |
| Wazuh Manager | Applies detection rules |
| OpenSearch | Stores and indexes alerts |
| AlertMind | Retrieves alerts and performs AI-assisted analysis |
| OpenAI GPT-4o-mini | Generates structured security insights |
| SOC Analyst | Reviews AI recommendations and performs incident response |

---

# AI Processing Pipeline
https://github.com/indrajitisingh/AlertMind/blob/main/screenshot/AlertMind_AI_Pipeline.jpeg


Before an alert reaches the AI model, AlertMind performs multiple validation steps:

- Schema validation
- Payload sanitization
- Prompt injection detection
- Sensitive field redaction
- Input size validation

Only validated alerts are submitted to the language model.

---

# Features

- 🔴 Live alert retrieval from OpenSearch
- 📋 Manual JSON alert analysis
- 🧠 AI-generated executive summaries
- 🎯 MITRE ATT&CK mapping
- 📊 Severity classification
- 🔍 IOC extraction
- 🧭 Investigation guidance
- 🚨 Incident response recommendations
- 📘 Incident Response Playbook integration
- 🛡️ Guardrails engine for secure AI interaction

---

# Custom Detection Rules

AlertMind includes thirteen custom Wazuh rules covering system enumeration, network discovery, and suspicious command execution.

| Rule ID | Command | Description |
|----------|----------|-------------|
|100101|whoami|User Information Discovery|
|100102|ipconfig|Network Configuration Discovery|
|100103|hostname|System Information Discovery|
|100107|net localgroup|Local Group Discovery|
|100108|netstat|Network Connections Discovery|
|100109|ping|Network Discovery|
|100110|PowerShell|PowerShell Execution|
|100111|cmd|Command Prompt Execution|
|100112|certutil|CertUtil (LOLBin Abuse)|
|100113|nslookup|DNS Lookup|

Each rule is mapped to MITRE ATT&CK techniques and corresponding response procedures.

---

# Technology Stack

| Layer | Technology |
|---------|------------|
| Endpoint | Windows 10/11, Sysmon, Wazuh Agent |
| Detection | Wazuh Manager, Wazuh API |
| Storage | OpenSearch |
| Application | Python, Streamlit |
| AI | OpenAI GPT-4o-mini |

---

# Project Structure

```text
AlertMind/
│
├── docs/
│   ├── AlertMind_Architecture.pdf
│   ├── AlertMind_AI_Pipeline.pdf
│   └── IR_Playbook.docx
│
├── screenshots/
│   ├── dashboard.png
│   └── ai_analysis.png
│
├── app.py
├── analyzer.py
├── guardrails.py
├── opensearch_client.py
├── prompts.py
├── styles.py
├── utils.py
├── wazuh_api.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Getting Started

## Prerequisites

- Python 3.10+
- Wazuh Manager
- OpenSearch
- Windows endpoint with Wazuh Agent
- OpenAI API Key (GPT-4o-mini)

## Installation

```bash
git clone https://github.com/<your-username>/AlertMind.git

cd AlertMind

python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt

streamlit run app.py
```

Configure your Wazuh API credentials and OpenAI API key before running the application.

---

# Dashboard

## Alert Dashboard

https://github.com/indrajitisingh/AlertMind/blob/main/screenshot/AlertMind_HomePage.png

## AI Analysis

https://github.com/indrajitisingh/AlertMind/blob/main/screenshot/Alert_Analysis.png

The dashboard provides:

- Live alert retrieval
- Alert summaries
- MITRE ATT&CK mapping
- IOC extraction
- Investigation guidance
- Incident response recommendations

---

# Guardrails & Responsible AI

AlertMind follows a **Human-in-the-Loop** design.

- Wazuh performs all detection.
- AI never replaces the analyst.
- Every alert is validated before AI analysis.
- Prompt injection detection protects the model.
- Sensitive information is sanitized.
- AI outputs structured JSON.
- No automatic containment or remediation.

---

# Incident Response Playbook

AlertMind includes a dedicated Incident Response Playbook covering:

- System Enumeration
- Network Discovery
- Suspicious Command Execution

Each playbook follows a seven-stage response lifecycle:

1. Overview
2. Detection
3. Analysis
4. Containment
5. Eradication
6. Recovery
7. Lessons Learned

📄 **Location**

```text
docs/IR_Playbook.docx
```

---

# Workflow Efficiency (MTTD / MTTR)

| Metric | Traditional Workflow | With AlertMind |
|---------|---------------------|----------------|
| MTTD | Near real-time | Near real-time |
| MTTR | ~4–6 minutes | ~1–1.5 minutes |

These measurements were collected in a controlled laboratory environment and are intended to illustrate workflow improvements rather than serve as formal benchmark results.

---

# Future Improvements

- Expand detection rule coverage
- Background alert polling
- Automatic JWT refresh
- Analyst audit logging
- Additional Guardrails security controls

---

# Disclaimer

AlertMind is an educational capstone project developed for academic purposes.

It is **not** a production-ready security platform.

AI-generated recommendations are advisory only and should always be reviewed and validated by a qualified security analyst before any response action is taken.

---

# Team

Developed by **Team Brain Bytes** as part of the **IIT Roorkee × Futurense PG Certificate Programme in AI & GenAI-Powered Cybersecurity.**

| Member | Contribution |
|----------|--------------|
| **Indrajit Singh** | Platform architecture, Wazuh & OpenSearch integration, Streamlit dashboard development |
| **Jay Goyal** | Detection rule engineering, testing, Incident Response Playbook |
| **Vansh Gupta** | AI integration, Guardrails, documentation |

---

## ⭐ If you found this project useful or interesting, consider giving it a star!
