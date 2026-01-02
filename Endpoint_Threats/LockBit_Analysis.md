# LockBit 3.0 (LockBit Black) Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: LockBit 3.0 Ransomware Analysis

Author: Nihal

Date: January 2, 2026

## High-Level Summary

LockBit 3.0, also known as "LockBit Black," is one of the most prolific Ransomware-as-a-Service (RaaS) operations. It is known for its high speed of encryption, sophisticated anti-debugging techniques, and a robust affiliate program. LockBit 3.0 often employs "Double Exposure" or "Triple Exposure" tactics: encrypting data, stealing sensitive files to threaten a leak, and sometimes launching DDoS attacks to pressure victims into paying.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | LockBit 3.0 (LockBit Black)                                           |
| Attribution        | LockBit Gang (RaaS Model)                                             |
| Target Assets      | Windows Endpoints, Windows Servers, Linux/ESXi Hosts                  |
| Primary Objective  | Financial Extortion (Ransomware)                                      |
| Propagation Vector | RDP Compromise, Phishing, Exploiting Vulnerabilities (e.g., CitrixBleed)|
| Targeted Platforms | Windows, Linux, VMware ESXi                                           |

## Threat at a Glance: Key ATT&CK TTPs

*   **T1486 (Data Encrypted for Impact):** High-speed multi-threaded encryption of files using a unique extension (e.g., `HLJkNskS`).
*   **T1490 (Inhibit System Recovery):** Deletes Volume Shadow Copies and disables Windows Error Recovery to prevent restoration.
*   **T1070.001 (Indicator Removal: Clear Windows Event Logs):** Uses built-in tools like `wevtutil` to clear security, system, and application logs.
*   **T1562.001 (Impair Defenses: Disable or Modify Tools):** Disables Windows Defender and other EDR/AV solutions using specialized scripts or kernel drivers.
*   **T1083 (File and Directory Discovery):** Scans local drives and network shares for sensitive data to exfiltrate before encryption.

## LockBit 3.0 Deep Dive: Technical Analysis

### Initial Access & Lateral Movement
Affiliates typically gain access via compromised RDP credentials or VPN accounts. They use tools like **Advanced IP Scanner** and **AdFind** for reconnaissance and **PsExec** or **Cobalt Strike** for lateral movement across the domain.

### Anti-Forensics and Evasion
LockBit 3.0 is highly evasive. It checks for debuggers and sandbox environments. Before encrypting, it often executes a command to clear event logs to hide its tracks:
`wevtutil cl system && wevtutil cl security && wevtutil cl application`

### Encryption and Ransom
The ransomware uses a customized encryption algorithm. It drops a ransom note (often named `[RandomString].README.txt`) in every folder it encrypts. The note contains instructions on how to access the LockBit leak site via the Tor browser.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Infiltration**
    Attacker logs in via a compromised VPN account (no MFA).

2.  **Reconnaissance**
    Uses `net view` and `nltest` to map the Active Directory environment and identify domain controllers.

3.  **Data Exfiltration**
    Uses **Rclone** or **MegaSync** to upload sensitive documents to cloud storage (Steal-before-Encrypt).

4.  **Preparation**
    Disables AV/EDR and deletes backup shadows: `vssadmin delete shadows /all /quiet`.

5.  **Encryption**
    Deploys the LockBit 3.0 binary via Group Policy Object (GPO). Files are renamed and a ransom note is displayed as the desktop wallpaper.

## Actionable Detections and Threat Hunting

### Hunting for Shadow Copy Deletion
Monitoring for the execution of `vssadmin.exe` with the `delete shadows` argument is a high-fidelity alert for ransomware.

### Sigma Rule (Windows/Endpoint)
Detects the common anti-forensic command used by LockBit to clear Windows Event Logs.

```yaml
title: LockBit Anti-Forensic Event Log Clearing
id: 99aabbcc-1122-3344-5566-778899001122
status: stable
description: Detects the clearing of Windows Event Logs using wevtutil, a common technique used by LockBit to evade detection and forensic analysis.
author: Nihal
date: 2026-01-02
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains:
      - ' cl '
      - 'clear-log'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **File Hash** | `d6e87...` (SHA256)                               | LockBit 3.0 Executable      |
| **Extension** | `.HLJkNskS` (Example)                             | Randomized per victim       |
| **File Name** | `README.txt`                                      | Ransom Note                 |
| **Registry**  | `HKCU\Control Panel\Desktop\Wallpaper`            | Points to ransom image      |
| **Tool**      | `rclone.exe`                                      | Used for exfiltration       |

## Platform Things

### Event Logs (Windows Security Simulation)

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2026-01-02 12:00:01,DC-01,Administrator,4512,C:\Windows\System32\vssadmin.exe,"vssadmin delete shadows /all /quiet",-,-,-,-,-,-,-
2026-01-02 12:00:05,DC-01,Administrator,4520,C:\Windows\System32\wevtutil.exe,"wevtutil cl system",-,-,-,-,-,-,-
2026-01-02 12:01:00,DC-01,Administrator,4600,C:\Users\Public\lb3.exe,"C:\Users\Public\lb3.exe -pass [KEY]",-,-,-,-,-,-,d6e87c1234567890abcdef1234567890abcd
```

### Sigma Rules(2)

**Log Event:**
```text
2026-01-02 12:00:01,DC-01,Administrator,4512,C:\Windows\System32\vssadmin.exe,"vssadmin delete shadows /all /quiet",-,-,-,-,-,-,-
```

```yaml
title: Volume Shadow Copy Deletion via Vssadmin
id: ffedccba-1122-3344-5566-778899001122
status: high
description: Detects the deletion of Volume Shadow Copies, which prevents the recovery of files after a ransomware attack.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  condition: selection
level: high
```

**Log Event:**
```text
2026-01-02 12:01:00,DC-01,Administrator,4600,C:\Users\Public\lb3.exe,"C:\Users\Public\lb3.exe -pass [KEY]",-,-,-,-,-,-,d6e87c1234567890abcdef1234567890abcd
```

```yaml
title: LockBit 3.0 Execution with Password
id: 11223344-aabb-ccdd-eeff-001122334455
status: critical
description: Detects the execution of LockBit 3.0 which often requires a specific -pass flag to decrypt the main payload in memory.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' -pass '
  condition: selection
level: critical
```
