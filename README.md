# 🛡️ SOC Log Analyzer
![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange)
![License](https://img.shields.io/badge/License-MIT-green)

An automated **Security Operations Center (SOC) Log Analysis and Threat Detection Platform** designed to analyze security logs, identify suspicious activities, detect common attack patterns, calculate risk levels, and generate actionable security alerts.

The system processes authentication, web server, and firewall logs through a rule-based detection engine, correlates security events, assigns severity levels, maps detected techniques to the **MITRE ATT&CK framework**, and presents security insights through a SOC-style dashboard and REST API.

Built with **Python**, a modular **security detection engine**, **FastAPI REST backend**, **SQLite event storage**, **MITRE ATT&CK mapping**, and a modern **SOC cybersecurity dashboard** for security monitoring and incident triage.

---

## 🚀 Key Features

- ⚡ **Security Log Analysis:** Parses authentication, web server, and firewall logs to extract meaningful security events.

- 🔍 **Multi-Format Log Parsing:** Supports different log structures and converts raw log entries into a normalized event format.

- 🔴 **Brute-Force Detection:** Identifies repeated failed authentication attempts from suspicious source IP addresses.

- 🌐 **Port Scan Detection:** Detects abnormal connection attempts across multiple ports from a single source.

- 💉 **SQL Injection Detection:** Identifies common SQL injection patterns in web requests and parameters.

- 🧬 **XSS Detection:** Detects suspicious cross-site scripting payloads in HTTP requests.

- 📂 **Path Traversal Detection:** Identifies directory traversal attempts such as `../` and suspicious file access patterns.

- 🚨 **Threat Alert Generation:** Generates structured alerts containing attack type, source IP, severity, timestamp, and evidence.

- 📊 **Risk Scoring:** Calculates a risk score based on attack patterns, frequency, severity, and correlated events.

- 🎯 **MITRE ATT&CK Mapping:** Maps detected attack techniques to relevant MITRE ATT&CK technique IDs.

- 🔗 **Event Correlation:** Correlates multiple related log events to identify larger attack patterns.

- 📈 **SOC Dashboard:** Provides a centralized view of events, threats, severity levels, suspicious IPs, and security alerts.

- 💻 **REST API:** Provides programmatic access to log analysis, detection results, alerts, and system statistics.

- 📄 **Security Reports:** Generates structured JSON and CSV reports for further investigation and analysis.


---
---

## 🧠 System Architecture & Data Flow

```mermaid
flowchart TD

    A[🔐 Security Log Sources] --> B[📥 Log Ingestion]

    A1[Linux Authentication Logs] --> B
    A2[Web Server Logs] --> B
    A3[Firewall Logs] --> B

    B --> C[🔍 Log Parser]

    C --> D[🧹 Log Normalization]

    D --> E[🧠 Detection Engine]

    E --> F1[🔴 Brute Force Detection]
    E --> F2[🌐 Port Scan Detection]
    E --> F3[💉 SQL Injection Detection]
    E --> F4[🧬 XSS Detection]
    E --> F5[📂 Path Traversal Detection]

    F1 --> G[📊 Risk Scoring Engine]
    F2 --> G
    F3 --> G
    F4 --> G
    F5 --> G

    G --> H[🎯 MITRE ATT&CK Mapping]

    H --> I[🚨 Alert Generator]

    I --> J1[💻 REST API]
    I --> J2[📈 SOC Dashboard]
    I --> J3[📄 Security Reports]

---

## ⚙️ How It Works

The SOC Log Analyzer follows a multi-stage security analysis pipeline:

### 1. 📥 Log Ingestion

The system accepts security events from different sources such as Linux authentication logs, web server logs, and firewall logs.

### 2. 🔍 Log Parsing

Raw log entries are parsed to extract important security information including:

- Timestamp
- Source IP address
- Destination IP address
- Username
- Port
- HTTP method
- Requested URL
- Status code
- Event type

### 3. 🧹 Log Normalization

Different log formats are converted into a common event structure so that the detection engine can analyze them consistently.

### 4. 🧠 Threat Detection

The detection engine examines normalized events and searches for suspicious patterns such as repeated authentication failures, abnormal port activity, and malicious web requests.

### 5. 📊 Risk Scoring

Each detected event is assigned a risk score based on factors such as attack type, frequency, severity, and related events.

### 6. 🎯 MITRE ATT&CK Mapping

Detected attack behaviors are mapped to relevant **MITRE ATT&CK techniques** to provide additional context for security analysts.

### 7. 🚨 Alert Generation

When suspicious activity is detected, the system generates a structured security alert containing the source, detection type, severity, risk score, evidence, and MITRE ATT&CK mapping.

### 8. 📈 Security Dashboard

The processed results are presented through a SOC-style dashboard where analysts can monitor security events, investigate alerts, and review threat activity.

### 9. 🔌 REST API

The FastAPI backend exposes analysis and alert data through REST endpoints, allowing other applications to interact with the detection system.

---

## 🔐 Detection Capabilities

The detection engine analyzes security events and identifies common attack patterns and suspicious behaviors.

| Detection | Description | Severity |
|---|---|---|
| 🔴 SSH Brute Force | Detects repeated failed authentication attempts from the same source IP. | HIGH |
| 🌐 Port Scanning | Identifies a source IP attempting connections across multiple ports. | HIGH |
| 💉 SQL Injection | Detects common SQL injection patterns in HTTP requests and parameters. | CRITICAL |
| 🧬 Cross-Site Scripting (XSS) | Identifies suspicious JavaScript and script injection payloads. | HIGH |
| 📂 Path Traversal | Detects attempts to access files outside the intended web directory. | HIGH |
| 🔎 Suspicious URL Access | Identifies requests targeting sensitive or commonly attacked endpoints. | MEDIUM |
| 🔐 Suspicious Authentication | Detects unusual authentication activity and repeated login failures. | MEDIUM |
| 🚨 Event Correlation | Correlates multiple related events to identify larger attack patterns. | HIGH |

### 🔴 SSH Brute Force

The system tracks failed authentication attempts by source IP and identifies repeated failures within a defined time window.

Example:

```text
192.168.1.50 → Failed Login
192.168.1.50 → Failed Login
192.168.1.50 → Failed Login
192.168.1.50 → Failed Login
192.168.1.50 → Failed Login

Detection: SSH Brute Force
Severity: HIGH

