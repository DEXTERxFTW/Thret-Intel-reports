# Agent Tesla Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: Agent Tesla (RAT / Infostealer)

Author: Nihal

Date: December 23, 2025

## High-Level Summary

Agent Tesla is an advanced .NET-based Remote Access Trojan (RAT) and information stealer that has been active since 2014. Unlike widespread banking trojans, Agent Tesla is often sold as a legitimate "monitoring tool" but is widely used by cybercriminals for Business Email Compromise (BEC) and credential harvesting. It is notorious for its flexibility in exfiltration methods, supporting SMTP (email), FTP, HTTP, and Telegram bots to send stolen data back to the attacker.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | Agent Tesla                                                           |
| Attribution        | Malware-as-a-Service (MaaS)                                           |
| File Type          | PE32 Executable (.NET)                                                |
| C2 Infrastructure  | SMTP (Email), FTP, Telegram API, HTTP Panel                           |
| Propagation Vector | Phishing Emails (Malicious Attachments: .zip, .cab, Office docs)      |
| Targeted OS        | Windows (XP through Windows 11)                                       |

## Threat at a Glance: Key ATT&CK TTPs Observed

*   **T1055.012 (Process Injection: Process Hollowing):** Agent Tesla typically decrypts its payload and injects itself into legitimate system processes like `RegAsm.exe`, `CasPol.exe`, or `vbc.exe` to evade antivirus detection.
*   **T1048.003 (Exfiltration Over Alternative Protocol):** It frequently uses SMTP (sending emails to the attacker) or the Telegram API for C2 communication, blending in with normal traffic.
*   **T1555 (Credentials from Password Stores):** Aggressively harvests credentials from browsers, mail clients (Outlook, Thunderbird), and VPN clients.
*   **T1056.001 (Keylogging):** Installs a keyboard hook to capture keystrokes in real-time.
*   **T1112 (Modify Registry):** Disables security features (like Task Manager or CMD) and establishes persistence.

## Agent Tesla Deep Dive: Technical Analysis

### Payload Characteristics
The initial payload is almost always a highly obfuscated .NET executable packed with crypters. Upon execution, it performs a "check-in" and then hollows out a legitimate Microsoft .NET binary (e.g., `RegAsm.exe`) to run its malicious code from memory.

### Command and Control (C2) Architecture
Agent Tesla is unique in its C2 diversity. It does not always require a dedicated server.
*   **SMTP:** The most common method. The malware logs into a compromised email account (e.g., Gmail, Zoho, Outlook) and sends emails containing stolen data to the attacker.
*   **Telegram:** It sends data as messages to a private Telegram channel using a bot token.

### Persistence and Artifacts
*   **Registry:** Creates a Run key in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
*   **Startup Folder:** Drops a shortcut or copy of itself in the user's Startup directory.
*   **Scheduled Task:** Occasionally creates a task to run at logon.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Delivery**
    The victim receives a phishing email disguised as a "Shipping Invoice" or "Purchase Order" with a `.zip` or `.iso` attachment.

2.  **Execution & Unpacking**
    The user opens the attachment and runs the executable. The malware performs an "Anti-Analysis" check (looking for Sandboxes/VMs).

3.  **Process Hollowing (Evasion)**
    The malware spawns a legitimate process (e.g., `RegAsm.exe`) in a suspended state, unmaps its memory, writes the malicious payload into it, and resumes the thread. To the user and some AVs, it just looks like `RegAsm.exe` is running.

4.  **Harvesting**
    The injected process scans for `web.config` files, browser cookies, and stored passwords. It starts the keylogger.

5.  **Exfiltration**
    It packages the stolen data (screenshots, keystrokes, passwords) and sends it out via SMTP (Port 587) or HTTPS (Telegram API).

## Actionable Detections and Threat Hunting

### Hunting for Suspicious Child Processes
Hunting for `RegAsm.exe`, `CasPol.exe`, or `vbc.exe` running as a child of `explorer.exe` or `cmd.exe` (instead of their normal parent, the .NET runtime or an installer) is a high-fidelity indicator.

### Sigma Rule
Detects the common behavior of Agent Tesla injecting into `RegAsm.exe` and making network connections.

```yaml
title: Suspicious RegAsm Network Connection
id: 5f6a7b8c-9d0e-4123-4567-890123abcdef
status: stable
description: Detects the legitimate .NET tool RegAsm.exe initiating a network connection, a common indicator of process injection by Agent Tesla.
author: Nihal
date: 2025-12-23
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    image|endswith: '\RegAsm.exe'
    initiated: true
  condition: selection
falsepositives:
  - Very rare legitimate use cases (usually developers).
level: high
tags:
  - attack.defense_evasion
  - attack.t1055
```

### YARA Rule
Targets the unique strings often found in Agent Tesla's configuration or exfiltration logic.

```java
rule RAT_AgentTesla {
    meta:
        description = "Detects Agent Tesla RAT"
        author = "Nihal"
        date = "2025-12-23"
    strings:
        $s1 = "smtp" ascii wide
        $s2 = "screen" ascii wide
        $s3 = "GetClipboard" ascii wide
        $s4 = "TelegramToken" ascii wide
        $x1 = "Password" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        4 of ($s*)
}
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **Domain**    | `api.telegram.org`                                | C2 (Exfiltration)           |
| **IP Address**| `142.250.183.109` (Gmail SMTP)                    | Exfiltration via SMTP       |
| **Port**      | `587` (SMTP), `443` (HTTPS)                       | Exfiltration Ports          |
| **Process**   | `RegAsm.exe` (Running from User Profile)          | Injected Process            |
| **File Name** | `Invoice_INV0023.exe`                             | Payload Name                |
| **Hash**      | `b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7`                | Payload Hash (Simulated)    |

## Indicators of Attack (IOAs)

*   **Legitimate Binary Network Activity:** `RegAsm.exe` or `CasPol.exe` connecting to the internet (especially mail servers).
*   **SMTP Traffic from User Workstation:** Endpoints sending traffic on port 587 or 25 directly, rather than through the corporate Exchange server.
*   **Suspicious Telegram Traffic:** High volume of HTTPS traffic to `api.telegram.org` from a non-browser process.

## Platform Things

### Event Logs

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-23 09:10:05,WORKSTATION-HR,hr_user,4100,C:\Users\hr_user\Downloads\Invoice_INV0023.exe,"C:\Users\hr_user\Downloads\Invoice_INV0023.exe",-,-,-,-,-,-,b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7
2025-12-23 09:10:08,WORKSTATION-HR,hr_user,4100,C:\Users\hr_user\Downloads\Invoice_INV0023.exe,-,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,-,-,-,-,-,-
2025-12-23 09:10:10,WORKSTATION-HR,hr_user,5200,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,"RegAsm.exe",-,-,-,142.250.183.109,587,TCP,-
2025-12-23 09:10:15,WORKSTATION-HR,hr_user,5200,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,-,-,HKCU\Software\Microsoft\Windows\CurrentVersion\Run\JavaUpdater,C:\Users\hr_user\Downloads\Invoice_INV0023.exe,-,-,-,-
```

### Sigma Rules(3)

**Log Event:**
```text
2025-12-23 09:10:08,WORKSTATION-HR,hr_user,4100,C:\Users\hr_user\Downloads\Invoice_INV0023.exe,-,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,-,-,-,-,-,-
```

```yaml
title: Suspicious Process Spawning RegAsm
id: 2c3d4e5f-6a7b-4890-1234-567890abcdef
status: stable
description: Detects a suspicious executable (like one in Downloads) spawning RegAsm.exe, which is often used for process hollowing by Agent Tesla.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|endswith: '\RegAsm.exe'
  filter_legit:
    parentimage|contains:
      - 'Program Files'
      - 'Windows\System32'
  condition: selection and not filter_legit
level: high
```

**Log Event:**
```text
2025-12-23 09:10:10,WORKSTATION-HR,hr_user,5200,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,"RegAsm.exe",-,-,-,142.250.183.109,587,TCP,-
```

```yaml
title: RegAsm Initiating SMTP Connection
id: 3d4e5f6a-7b8c-4901-2345-678901abcdef
status: critical
description: Detects the RegAsm process initiating a connection on SMTP ports (587, 25, 465), indicating data exfiltration via email.
author: Nihal
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    image|endswith: '\RegAsm.exe'
    destinationport:
      - 587
      - 25
      - 465
  condition: selection
level: critical
```

**Log Event:**
```text
2025-12-23 09:10:15,WORKSTATION-HR,hr_user,5200,C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe,-,-,HKCU\Software\Microsoft\Windows\CurrentVersion\Run\JavaUpdater,C:\Users\hr_user\Downloads\Invoice_INV0023.exe,-,-,-,-
```

```yaml
title: Registry Persistence by RegAsm
id: 4e5f6a7b-8c9d-4012-3456-789012abcdef
status: high
description: Detects a RegAsm process creating a Run key in the registry for persistence.
author: Nihal
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    image|endswith: '\RegAsm.exe'
    targetobject|contains: 'Run'
  condition: selection
level: high
```
