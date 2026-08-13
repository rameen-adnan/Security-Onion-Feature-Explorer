# Security Onion Feature Explorer

> Security Onion Comprehensive Feature Exploration

## Objective

The objective of this project is to systematically explore, evaluate, and document the full feature set of the Security Onion platform. The project focuses on enterprise security monitoring, threat hunting, log management, incident response, and automation while producing practical documentation.

---

# Lab Environment

| Component     | Details                   |
|---------------|---------------------------|
| Platform      | Security Onion 3.2.0      |
| Deployment    | Evaluation                |
| Hypervisor    | Oracle VirtualBox         |
| Host OS       | Windows 11                |
| Test VM       | Kali Linux and Windows VM |
| Documentation | Markdown (GitHub)         |

---

# Project Coverage

The project covers the following Security Onion capabilities and workflows:

### 1. Deployment & Architecture

* Security Onion 3.2.0 Evaluation deployment
* VirtualBox network configuration
* Security Onion node architecture
* Service health verification
* Sample PCAP and network traffic ingestion

### 2. Visibility & Data Ingestion

* Zeek network metadata and protocol logs
* Suricata alerts and EVE JSON
* Zeek vs. Suricata comparison
* Elastic Fleet agent management
* Wazuh integration research and Evaluation Mode limitations
* Osquery live host inspection

### 3. Detections & Alerting

* Security Onion Detections interface
* Suricata detection rules
* Sigma detection rules
* Detection rule analysis
* Alert tuning through Overrides
* Custom Suricata detection rules
* Controlled validation of custom alerts

### 4. Threat Hunting & Analysis

* SOC Dashboard customization
* Hunt searches and filtering
* Alert-to-event pivoting
* Zeek connection, DNS, and HTTP investigation
* PCAP extraction and packet-level analysis
* CyberChef Base64 decoding

### 5. Incident Response & Automation

* Guided Analysis Playbooks
* Case creation and evidence management
* Observables and event linking
* Investigation documentation and case closure
* Security Onion API research
* Internal Elasticsearch automation
* Enterprise features including Onion AI and Manager of Managers (MoM)

---

## Project Workflow

The features were explored through an end-to-end SOC investigation workflow:

**Deploy → Generate Traffic → Detect → Hunt → Pivot → Analyze PCAP → Investigate → Document → Close**

The resulting documentation provides both quick-reference instructions and detailed investigation findings for future Security Onion users.

# Documentation

Detailed documentation is available in the `docs` directory.

| Document                   | Description                                                        |
|----------------------------|--------------------------------------------------------------------|
| Architecture-Setup.md      | Deployment notes, architecture, configuration, and lessons learned |
| Cheat-Sheet.md             | Quick reference guide for common Security Onion tasks              |
| API-Automation-Snippets.md | API examples and automation scripts                                |
| Feature-Explorers-Guide.md | Comprehensive Security Onion feature exploration and findings      |

---

# References

- Security Onion Documentation - https://docs.securityonion.net/en/2.4/
- Security Onion GitHub Repository - https://github.com/Security-Onion-Solutions/securityonion/
- Security Onion Blog - https://blog.securityonion.net/

---

