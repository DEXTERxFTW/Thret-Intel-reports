# RedLine Stealer Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: RedLine Stealer ("RedLine")

Author: Nihal

Date: December 5, 2025

## High-Level Summary

RedLine Stealer is a prominent Malware-as-a-Service (MaaS) infostealer that first appeared in early 2020. It is designed to harvest sensitive information from infected systems, including credentials, credit card data, cryptocurrency wallets, and browser cookies. Due to its low cost and availability on underground forums, it is widely used by various threat actors, ranging from low-level cybercriminals to sophisticated groups. It is often distributed via phishing campaigns, malicious ads (malvertising), and cracked software.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | RedLine / RedLine Stealer                                             |
| Attribution        | MaaS (Used by multiple actors)                                        |
| File Type          | PE32 Executable (.NET)                                                |
| C2 Infrastructure  | SOAP/XML over TCP (Ports vary, often high ports like 19084, 45678)    |
| Propagation Vector | Phishing, Malvertising (Google Ads), YouTube scams, Cracked Games     |
| Targeted OS        | Windows (Windows 7 through Windows 11)                                |

## Threat at a Glance: Key ATT&CK TTPs Observed

*   **T1555.003 (Credentials from Web Browsers):** RedLine targets Chromium and Gecko-based browsers to extract saved login credentials, cookies, and autofill data.
*   **T1005 (Data from Local System):** It collects system information, installed software lists, and hardware details.
*   **T1056.001 (Keylogging):** While primarily a stealer, some variants include keylogging modules to capture real-time inputs.
*   **T1082 (System Information Discovery):** Gathers detailed system reconnaissance data (IP, Country, OS version, Hardware ID).
*   **T1027 (Obfuscated Files or Information):** Payloads are often packed or obfuscated to evade static analysis.

## RedLine Deep Dive: Technical Analysis

### Payload Characteristics
RedLine is typically written in **C#/.NET**. The primary payload usually arrives packed or loaded via a dropper (e.g., a fake game installer). Upon execution, it performs a check to ensure it's not running in a sandbox (though anti-analysis features vary by builder version).

### Command and Control (C2) Architecture
RedLine uses a **SOAP-based** protocol (WCF - Windows Communication Foundation) over TCP for C2 communication. It establishes a connection to the C2 server (Controller) to receive a configuration ("Settings") and then exfiltrates gathered data.

*   **Communication:** The malware sends data in XML format.
*   **Ports:** Frequently uses high TCP ports (e.g., 80, 443, but often random high ports like 34567, 19084).

### Reconnaissance and Propagation
RedLine does not typically self-propagate like a worm. It relies on the initial infection vector (Phishing/Dropper). Once running, it immediately enumerates the system:
*   **System Info:** Username, MachineName, Display resolution, Installed Browsers.
*   **Wallet Check:** Scans specifically for cryptocurrency wallet directories (MetaMask, Exodus, etc.).

### Persistence and Artifacts
*   **Files:** Often drops payloads in `%APPDATA%` or `%TEMP%`.
*   **Service:** Unlike Ransomware or RATs, RedLine is often a "smash and grab" operation and may not always establish persistence. However, if configured, it may add a Scheduled Task or Registry Run key.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Execution**
    The victim downloads and runs a malicious file, often disguised as "PhotoShop Crack.exe" or "CryptoBot.exe".

2.  **Evasion**
    The malware unpacks itself in memory. It may check for debuggers or analysis tools (e.g., checking for `Wireshark` or `Process Hacker`).

3.  **Initialization (C2 Handshake)**
    RedLine connects to its C2 server (e.g., `192.168.1.50:45678`) via WCF/NET.TCP. It requests the configuration settings (what to steal, where to grab it from).

4.  **Data Harvesting**
    It iterates through target directories:
    *   **Browsers:** extracting `Login Data`, `Cookies`, `Web Data` (SQLite databases).
    *   **Wallets:** searching for `wallet.dat` or extension folders.
    *   **Files:** Grabbing files matching specific extensions (e.g., `.txt`, `.doc`) if configured.

5.  **Exfiltration**
    The stolen data is aggregated and sent back to the C2 server.

6.  **Cleanup (Optional)**
    Depending on configuration, the malware may delete itself (`cmd.exe /c del ...`) after the task is complete.

## Actionable Detections and Threat Hunting

### Hunting for Suspicious .NET Connections
Hunting for unsigned .NET binaries initiating outbound TCP connections to non-standard ports is a strong indicator.

### Sigma Rule
This rule detects the behavior of accessing browser credential stores from a non-browser process.

```yaml
title: RedLine Stealer Browser DB Access
id: 542200dc-5dc5-43e0-bc0a-1235fcbfb470
status: stable
description: |
  Detects a suspicious process accessing web browser 'Login Data' or 'Cookies' files, 
  which is a core behavior of RedLine and other infostealers.
author: Nihal
date: 2025-12-05
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
logsource:
  category: file_event
  product: windows
detection:
  selection:
    targetfilename|contains:
      - 'Login Data'
      - 'Cookies'
  filter:
    image|contains:
      - 'chrome.exe'
      - 'firefox.exe'
      - 'msedge.exe'
      - 'opera.exe'
  condition: selection and not filter
falsepositives:
  - Legitimate password manager applications (rarely access raw DB files directly like this)
level: high
tags:
  - attack.credential_access
  - attack.t1555.003
```

### YARA Rule
Targets specific strings associated with RedLine's XML/SOAP configuration and C2 communication.

```java
rule Infostealer_RedLine {
    meta:
        description = "Detects RedLine Stealer payloads based on WCF/SOAP strings"
        author = "Nihal"
        date = "2025-12-05"
        reference = "Analysis Report RedLine"
    strings:
        $s1 = "http://tempuri.org/" ascii wide
        $s2 = "EntityKey" ascii wide
        $s3 = "IRemoteEndpoint" ascii wide
        $xml1 = "<Capability>" ascii wide
        $xml2 = "<Authorization>" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        3 of ($s*) and 1 of ($xml*)
}
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **Domain**    | `files-upload-storage.com`                        | Staging/Download URL        |
| **IP Address**| `185.215.113.45`                                  | C2 Server                   |
| **Port**      | `19084`, `45231` (TCP)                            | C2 Ports                    |
| **File Name** | `PhotoShop_Portable.exe`                          | Dropper Name                |
| **Hash**      | `a1b2c3d4e5f678901234567890abcdef`                | Payload Hash (Simulated)    |

## Indicators of Attack (IOAs)

*   **Non-Browser Process Accessing Credentials:** A process other than Chrome/Edge reading `Login Data` or `Cookies`.
*   **Rapid File Enumeration:** A process quickly opening and reading files in `%APPDATA%` related to Crypto Wallets (e.g., `Exodus`, `Metamask`).
*   **High Port Traffic:** Outbound TCP traffic to high, ephemeral ports from a newly downloaded executable.

## Priority Recommendations

1.  **Endpoint Detection:** Enable rules to detect processes accessing browser credential stores (`sqlite3` DBs).
2.  **Network Filtering:** Block connections to known malicious IPs and monitor for SOAP/XML traffic on non-standard ports.
3.  **User Awareness:** Educate users on the risks of downloading cracked software or opening suspicious email attachments.

## Platform Things

### Event Logs

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-05 14:00:05,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,"C:\Users\user\Downloads\PhotoShop_Crack.exe",-,-,-,-,-,-,a1b2c3d4e5f678901234567890abcdef
2025-12-05 14:00:10,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data,-,-,-,-,-,-
2025-12-05 14:00:12,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,C:\Users\user\AppData\Roaming\Exodus\exodus.wallet\wallet.seco,-,-,-,-,-,-
2025-12-05 14:00:15,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,-,-,-,185.215.113.45,19084,TCP,-
2025-12-05 14:00:20,DESKTOP-RED-01,user,3200,C:\Windows\System32\cmd.exe,"cmd.exe /c del C:\Users\user\Downloads\PhotoShop_Crack.exe",-,-,-,-,-,-,-
```

### Sigma Rules(4)

**Log Event:**
```text
2025-12-05 14:00:10,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data,-,-,-,-,-,-
```

```yaml
title: RedLine Stealer Chrome Access
id: e5f6a7b8-c9d0-41e2-9345-678901abcdef
status: stable
description: Detects RedLine accessing Chrome Login Data.
author: Nihal
logsource:
  category: file_event
  product: windows
detection:
  selection:
    targetfilename|contains: 'Login Data'
  filter:
    image|contains: 'chrome.exe'
  condition: selection and not filter
level: high
```

**Log Event:**
```text
2025-12-05 14:00:12,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,C:\Users\user\AppData\Roaming\Exodus\exodus.wallet\wallet.seco,-,-,-,-,-,-
```

```yaml
title: RedLine Stealer Wallet Access
id: f6a7b8c9-d0e1-42f3-0456-789012abcdef
status: stable
description: Detects access to common cryptocurrency wallet files.
author: Nihal
logsource:
  category: file_event
  product: windows
detection:
  selection:
    targetfilename|contains:
      - 'exodus.wallet'
  condition: selection
level: high
```

**Log Event:**
```text
2025-12-05 14:00:15,DESKTOP-RED-01,user,3200,C:\Users\user\Downloads\PhotoShop_Crack.exe,-,-,-,-,185.215.113.45,19084,TCP,-
```

```yaml
title: Suspicious SOAP/XML Traffic
id: 0a1b2c3d-4e5f-6789-1234-567890abcdef
status: experimental
description: Detects network connections associated with RedLine's WCF protocol on high ports (Suricata/Network based logic applied to process events).
author: Nihal
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    destinationport|gte: 10000
    protocol: tcp
    image|contains: '.exe'
  condition: selection
level: medium
```

**Log Event:**
```text
2025-12-05 14:00:20,DESKTOP-RED-01,user,3200,C:\Windows\System32\cmd.exe,"cmd.exe /c del C:\Users\user\Downloads\PhotoShop_Crack.exe",-,-,-,-,-,-,-
```

```yaml
title: RedLine Self-Deletion
id: 1b2c3d4e-5f6g-7890-2345-678901abcdef
status: stable
description: Detects the self-deletion command often used by RedLine after execution.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    commandline|contains|all:
      - 'cmd.exe'
      - '/c'
      - 'del'
    commandline|contains: '.exe'
  condition: selection
level: medium
```