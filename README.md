# Threat Intelligence & Detection Engineering Repository

## Overview
This directory serves as a centralized hub for **Threat Intelligence Analysis** and **Detection Engineering**. It contains detailed reports on modern malware families and cloud-native threats, reconstructed from technical analysis and real-world observations.

The goal of this repository is to bridge the gap between **threat research** and **actionable defense** by providing:
1.  **Technical Deep Dives:** Detailed breakdowns of attack chains (Initial Access to Impact).
2.  **Simulated Logs:** Standardized CSV-formatted logs showing how these threats look in a SIEM.
3.  **Sigma Rules:** Generic detection logic (YAML) that can be converted to Splunk, Sentinel, or Elastic.

---

## Directory Structure

### ☁️ [Cloud_Threats](./Cloud_Threats/)
Focuses on modern attacks targeting Cloud Infrastructure, Containers, and Serverless environments.
*   **[Denonia_Analysis.md](./Cloud_Threats/Denonia_Analysis.md):** Analysis of the first malware specifically targeting AWS Lambda.
*   **[Kinsing_Analysis.md](./Cloud_Threats/Kinsing_Analysis.md):** Cryptojacking and lateral movement in Kubernetes/Docker.
*   **[SCARLETEEL_Analysis.md](./Cloud_Threats/SCARLETEEL_Analysis.md):** Sophisticated AWS credential theft and Fargate compromise.
*   **[Siloscape_Analysis.md](./Cloud_Threats/Siloscape_Analysis.md):** Windows Container escape targeting Kubernetes clusters.
*   **[TeamTNT_AWS_Analysis.md](./Cloud_Threats/TeamTNT_AWS_Analysis.md):** Cloud-native botnets and credential exfiltration.

### 💻 [Endpoint_Threats](./Endpoint_Threats/)
Focuses on traditional Windows malware, including Stealers, Loaders, and Ransomware.
*   **[LockBit_Analysis.md](./Endpoint_Threats/LockBit_Analysis.md):** Deep dive into the LockBit 3.0 (Black) RaaS operation.
*   **[AgentTesla_Analysis.md](./Endpoint_Threats/AgentTesla_Analysis.md):** Analysis of the pervasive .NET-based info-stealer.
*   **[Emotet_Analysis.md](./Endpoint_Threats/Emotet_Analysis.md):** Reconstructing the infamous modular banking trojan.
*   **[RedLine_Analysis.md](./Endpoint_Threats/RedLine_Analysis.md):** Detailed breakdown of the RedLine Stealer infection chain.
*   **[njRAT_Analysis.md](./Endpoint_Threats/njRAT_Analysis.md):** Analysis of the Bladabindi Remote Access Trojan.
*   **[IcedID_Analysis.md](./Endpoint_Threats/IcedID_Analysis.md):** BokBot analysis focusing on credential theft.

---

## Reporting Standards
Each report follows a strict structure to ensure consistency across the intelligence lifecycle:
1.  **Quick Look:** High-level attribution and target metadata.
2.  **Threat at a Glance:** Mapping of TTPs to the **MITRE ATT&CK** framework.
3.  **Technical Analysis:** Step-by-step breakdown of the "Attack Journey."
4.  **IOCs & IOAs:** Tables of technical indicators and behavioral patterns.
5.  **Simulated Logs:** CSV data using the standard RevSock AI header.
6.  **Sigma Rules:** Validated detection logic for SIEM integration.

## Usage
These reports can be used for:
*   **SOC Training:** Understanding what a specific attack looks like in raw logs.
*   **Detection Engineering:** Implementing the provided Sigma rules in your environment.
*   **Threat Hunting:** Using the IOCs and IOAs to search for historical compromises.

---
*Created by Nihal Pirjade as part of the RevSock AI Internship.*
