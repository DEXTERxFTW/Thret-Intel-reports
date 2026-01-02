# njRAT Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: njRAT ("Bladabindi", "Njw0rm")

Author: Nihal Pirjade

Date: December 4, 2025

## High-Level Summary

njRAT, also known as Bladabindi, is a prevalent Remote Access Trojan (RAT) built on the Microsoft .NET framework. It is widely accessible in the cybercrime underground, making it a common tool for script kiddies and sophisticated actors alike. The malware grants attackers complete control over the victim's machine, enabling capabilities such as keylogging, webcam and microphone surveillance, screenshot capture, and file exfiltration. It is notorious for its aggressive propagation methods, including spreading via infected USB drives and masquerading as legitimate software or game cracks.

## Quick Look

| Attribute          | Details                                                     |
| :----------------- | :---------------------------------------------------------- |
| Threat Family      | njRAT / Bladabindi                                          |
| Attribution        | Broad usage (Cybercrime, Script Kiddies, APTs)              |
| File Type          | PE32 Executable (.NET)                                      |
| C2 Infrastructure  | TCP Port 5552 (Default); Dynamic DNS (e.g., DuckDNS, No-IP) |
| Propagation Vector | Malicious Gaming Cracks, USB Drives, Phishing               |
| Targeted OS        | Windows (XP through Windows 11)                             |

## Threat at a Glance: Key ATT&CK TTPs Observed

*   **T1547.001 (Registry Run Keys):** Ensures persistence by adding entries to `HKCU\...\Run`, pointing to a binary hidden in `%APPDATA%`.
*   **T1036.005 (Masquerading):** Copies itself to `%APPDATA%` or `%TEMP%` using names like `server.exe`, `svchost.exe`, or `Tr.exe`.
*   **T1562.004 (Impair Defenses: Firewall):** Uses `netsh` to add itself to the firewall allowed list.
*   **T1056.001 (Keylogging):** Captures keystrokes and saves them to a distinct log format (often `[kl]`).
*   **T1091 (Replication through Removable Media):** Copies itself to connected USB drives (e.g., `U.exe`).
*   **T1123 (Audio Capture) & T1125 (Video Capture):** Capable of remote surveillance.

## njRAT Deep Dive: Technical Analysis

### Payload Characteristics
njRAT is written in **C#/.NET**, making it dependent on the .NET Framework. Its binaries are often obfuscated to bypass static signature detection. The payload typically arrives as a dropper or is embedded within another executable (e.g., a cracked game).

### Command and Control (C2) Architecture
The malware communicates using a raw TCP connection, defaulting to port **5552**. It uses a custom delimiter-based protocol (often using `[kl]` or `|` as separators) to send data and receive commands. C2 domains are frequently hosted on Dynamic DNS services like DuckDNS or No-IP.

### Persistence and Artifacts
*   **File System:** Copies itself to `%APPDATA%` or `%TEMP%`, often renaming to `server.exe`, `svchost.exe`, or `md.exe`.
*   **Registry:** Creates a value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to ensure execution on reboot.
*   **Mutex:** Generates a mutex (e.g., `njRAT_Mutex_<random>`) to prevent multiple instances.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Execution**
    The user executes a malicious file, often disguised as a game crack (`GameCrack.exe`) or downloaded via social engineering.

2.  **Installation & Persistence**
    The malware copies itself to a hidden directory in `%APPDATA%` (e.g., `\Bladabindi\server.exe`) and creates a Registry Run key for persistence.

3.  **Defense Evasion**
    It executes `netsh` commands to add itself to the Windows Firewall allowed list, ensuring C2 traffic is not blocked.

4.  **C2 & Surveillance**
    The RAT initiates an outbound TCP connection to the C2 server (e.g., `njrat.dynamic-dns.net` on port 5552) and begins transmitting victim info, keylogs, or surveillance streams.

## Actionable Detections and Threat Hunting

### Hunting for AppData Execution
Monitoring for processes spawning from `%APPDATA%` or `%TEMP%` that subsequently initiate network connections or modify the registry is a high-fidelity indicator of RAT activity.

## Indicators of Compromise (IOCs)

| Type                  | Indicator                                    | Context                     |
| :-------------------- | :------------------------------------------- | :-------------------------- |
| **Files**             | `server.exe` (in AppData/Roaming/Bladabindi) | Main njRAT payload          |
| **Registry Key**      | `HKCU\...\Run\Bladabindi`                    | Persistence mechanism       |
| **IP Address/Domain** | `njrat.dynamic-dns.net`                      | C2 server                   |
| **Port**              | `5552`, `1177`, `1604` (TCP)                 | Default C2 ports            |
| **Mutex**             | `njRAT_Mutex_<random_string>`                | Prevents multiple instances |

## Indicators of Attack (IOAs)

*   **Suspicious Process Creation:** Executables running from `Downloads` or `Temp` directory that then self-copy and modify system configurations.
*   **Registry Modification:** Addition of new entries to `HKCU\...\Run` that point to executables in `AppData` or `Temp`.
*   **Firewall Rule Modification:** `netsh.exe` being executed with parameters to add an allowed program.
*   **Outbound Connections to Non-Standard Ports:** Connections initiated by processes in `AppData` to known njRAT C2 ports.

## Priority Recommendations

1.  **Endpoint Restrictions:** Restrict execution of binaries from user-writable directories like `%APPDATA%` and `%TEMP%` using AppLocker or SRP.
2.  **Network Filtering:** Block outbound connections to common Dynamic DNS domains and non-standard ports (5552, 1177).
3.  **USB Hygiene:** Disable AutoRun and scan removable media to prevent propagation via USB.

## Platform Things - 

### Event Logs - 

```text
eventdate,hostname,user,process_id,image,commandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-04 10:00:00,DESKTOP-NJRAT-01,user,4520,C:\Users\user\Downloads\GameCrack.exe,"C:\Users\user\Downloads\GameCrack.exe",-,-,-,-,-,-,e87b23a098123456789abcdef1234567
2025-12-04 10:00:05,DESKTOP-NJRAT-01,user,4520,C:\Users\user\Downloads\GameCrack.exe,-,C:\Users\user\AppData\Roaming\Bladabindi\server.exe,-,-,-,-,-,-
2025-12-04 10:00:10,DESKTOP-NJRAT-01,user,3100,C:\Windows\System32\reg.exe,"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Bladabindi /t REG_SZ /d C:\Users\user\AppData\Roaming\Bladabindi\server.exe /f",-,HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Bladabindi,C:\Users\user\AppData\Roaming\Bladabindi\server.exe,-,-,-,-
2025-12-04 10:00:15,DESKTOP-NJRAT-01,user,3100,C:\Windows\System32\netsh.exe,"netsh firewall add allowedprogram C:\Users\user\AppData\Roaming\Bladabindi\server.exe Bladabindi ENABLE",-,-,-,-,-,-,-
2025-12-04 10:00:20,DESKTOP-NJRAT-01,user,5600,C:\Users\user\AppData\Roaming\Bladabindi\server.exe,-,-,-,-,njrat.dynamic-dns.net,5552,TCP,-
2025-12-04 10:01:00,DESKTOP-NJRAT-01,user,5600,C:\Windows\System32\cmd.exe,"cmd.exe /c systeminfo",-,-,-,-,-,-,-
```

### Sigma Rules(5) - 

```yaml
title: njRAT Self-Copy to AppData
id: c3d4e5f6-7a8b-49c0-1d2e-3f4g5h6i7j8k
status: stable
description: Detects the creation of an executable in a suspicious AppData subdirectory, a common behavior of njRAT during its installation phase.
author: Nihal
logsource:
  category: file_event
  product: windows
detection:
  selection:
    targetfilename|contains:
      - 'Roaming'
      - 'Temp'
    targetfilename|contains: '.exe'
    image|contains: '.exe' # The installer/dropper
  condition: selection
falsepositives:
  - Legitimate software installers (high FP rate, needs tuning with specific folder names like 'Bladabindi' or random strings).
level: medium
```

```yaml
title: njRAT Registry Persistence
id: a1b2c3d4-e5f6-4789-0123-456789abcdef
status: stable
description: Detects registry run key modifications often associated with njRAT.
author: Nihal
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    targetobject|contains: 'Run'
    details|contains:
      - 'Roaming'
      - 'server.exe'
      - 'Bladabindi'
  condition: selection
falsepositives:
  - Legitimate applications starting from AppData (e.g., Discord, Slack) - whitelisting required.
level: high
```

```yaml
title: njRAT Firewall Rule Addition
id: b2c3d4e5-f6g7-4890-1234-567890abcdef
status: stable
description: Detects `netsh` commands used to add firewall exceptions for binaries located in AppData, a technique used by njRAT.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|contains: 'netsh.exe'
    commandline|contains|all:
      - 'firewall'
      - 'add'
      - 'allowedprogram'
      - 'Roaming'
  condition: selection
falsepositives:
  - Some legitimate software installers.
level: high
```

```yaml
title: Suspicious Mutex Creation (Generic RAT)
id: c3d4e5f6-g7h8-4901-2345-678901abcdef
status: experimental
description: Detects the creation of mutexes with patterns often used by .NET RATs like njRAT (often short, random, or specific 6-character strings).
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    commandline|contains: 'Mutex'
  condition: selection
level: low
```

```yaml
title: njRAT C2 Network Beacon
id: d4e5f6g7-h8i9-4012-3456-789012abcdef
status: stable
description: Detects outbound network connections from a binary located in AppData to non-standard ports often used by RATs.
author: Nihal
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    image|contains: 'Roaming'
    destinationport:
      - 5552
      - 1177
    protocol: tcp
    initiated: true
  condition: selection
falsepositives:
  - Custom internal applications (unlikely on these specific ports).
level: critical
```