# IcedID Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: IcedID ("BokBot")

Author: Nihal

Date: December 22, 2025

## High-Level Summary

IcedID, also known as BokBot, is a sophisticated banking trojan and malware loader that targets financial information. First observed in 2017, it has evolved from a simple banking trojan into a modular threat capable of acting as a foothold for other malware, including ransomware (e.g., Egregor, Conti). It is primarily distributed via malspam campaigns (often using stolen email threads) and utilizes advanced web injection techniques to steal credentials from online banking sessions.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | IcedID / BokBot                                                       |
| Attribution        | Financially Motivated Cybercrime (Lunar Spider)                       |
| File Type          | PE32 DLL / EXE (Often packed)                                         |
| C2 Infrastructure  | HTTPS/SSL over 443, 8080; Local Proxy for traffic interception        |
| Propagation Vector | Malspam (Office Docs with Macros), Drive-by Downloads                 |
| Targeted OS        | Windows (Windows 10, Server 2016+)                                    |
## Event Logs

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-05 09:30:15,WORKSTATION-FIN-02,finance_user,2045,C:\Program Files\Microsoft Office\Office16\WINWORD.EXE,"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" /n "C:\Users\finance_user\Downloads\document_copy.doc",-,-,-,-,-,-,a1b2c3d4e5f678901234567890abcdef
2025-12-05 09:30:20,WORKSTATION-FIN-02,finance_user,4099,C:\Windows\System32\rundll32.exe,"rundll32.exe" C:\Users\finance_user\AppData\Local\Temp\license.dat,PluginInit,C:\Program Files\Microsoft Office\Office16\WINWORD.EXE,-,-,-,-,-,-
2025-12-05 09:30:25,WORKSTATION-FIN-02,finance_user,5100,C:\Windows\System32\schtasks.exe,"schtasks.exe" /create /tn "UpdateHelper" /tr "rundll32.exe C:\Users\finance_user\AppData\Local\Temp\license.dat,PluginInit" /sc onlogon,C:\Windows\System32\rundll32.exe,-,-,-,-,-,-
2025-12-05 09:31:00,WORKSTATION-FIN-02,finance_user,1055,C:\Windows\System32\svchost.exe,-,-,-,-,45.147.229.15,443,TCP,-
```

## Threat at a Glance: Key ATT&CK TTPs Observed

*   **T1055 (Process Injection):** IcedID injects itself into legitimate processes (often `svchost.exe` or web browsers) to hide and hook API calls.
*   **T1185 (Browser Session Hijacking):** It acts as a local proxy, intercepting and modifying web traffic to perform web injects (stealing 2FA/Login data).
*   **T1027 (Obfuscated Files or Information):** The main config and modules are often gzip-compressed and encrypted (steganography in PNG files is also common).
*   **T1566.001 (Spearphishing Attachment):** Initial access is typically via Word documents containing malicious macros.
*   **T1053.005 (Scheduled Task):** Establishes persistence by creating a scheduled task to run on logon.

## IcedID Deep Dive: Technical Analysis

### Payload Characteristics
The IcedID payload is modular. The core bot ("loader") is responsible for establishing C2 and downloading additional modules (e.g., VNC module, Web Inject module). Recent variants have moved away from banking solely to being a generic loader for ransomware operations.

### Command and Control (C2) Architecture
IcedID uses HTTPS for C2 communication, often blending in with legitimate traffic. It identifies the victim machine using a generated "Bot ID" derived from hardware information.
*   **Protocol:** SSL/TLS (often with self-signed certificates in earlier versions).
*   **Traffic:** It proxies browser traffic through a local port (listening on localhost) to capture banking data.

### Reconnaissance and Propagation
Once active, IcedID profiles the system (domain trust, network info). It creates a "fingerprint" of the victim and sends it to the C2. It does not typically self-propagate via SMB exploit (like WannaCry) but may use stolen credentials for lateral movement.

### Persistence and Artifacts
*   **Files:** Often stores its binary in `%APPDATA%` or `%LOCALAPPDATA%` with a random filename (e.g., `license.dat` or a random DLL name).
*   **Scheduled Task:** Creates a task to execute the DLL via `rundll32.exe` at logon.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Delivery**
    The user receives an email with a password-protected zip or a link to a compromised site hosting a Word document.

2.  **Execution**
    The user opens the document and enables macros. The macro executes `cmd.exe` or `wmic` to download the initial payload (often a DLL or a GZIP/PNG file).

3.  **Installation**
    The payload is saved to `%Temp%` or `%AppData%`. `rundll32.exe` is used to execute the malicious DLL export (often named `PluginInit` or `DllRegisterServer`).

4.  **Persistence**
    A scheduled task is created to ensure the malware survives reboots.

5.  **Injection & Hooking**
    IcedID injects into `svchost.exe` and hooks browser processes to intercept traffic.

6.  **Exfiltration**
    Credentials and system info are sent to the C2. If the victim visits a targeted banking site, the web inject module captures the session.

## Actionable Detections and Threat Hunting

### Hunting for Rundll32 with No Arguments
Hunting for `rundll32.exe` processes spawned by Office applications or running with unusual command lines (e.g., executing a DAT file) is high yield.

### Sigma Rule
Detects the common IcedID behavior of an Office application spawning `rundll32.exe` to load a DLL.

```yaml
title: Office Spawning Rundll32
id: 7e8a9d1b-3f4c-4e5a-8d2b-1a9c3e4f5a6b
status: stable
description: Detects Microsoft Office applications spawning rundll32.exe, a common technique used by IcedID and other loaders to execute malicious DLLs.
author: Nihal
date: 2025-12-05
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    parentimage|contains:
      - 'WINWORD.EXE'
      - 'EXCEL.EXE'
  filter:
    image|contains: 'rundll32.exe'
  condition: selection and filter
level: high
```

### YARA Rule
Targets specific strings often found in unpacked IcedID payloads.

```java
rule Trojan_IcedID_Loader {
    meta: 
        description = "Detects IcedID / BokBot Loader"
        author = "Nihal"
        date = "2025-12-05"
        reference = "Analysis Report IcedID"
    strings:
        $s1 = "cookie: __gads=" ascii
        $s2 = "poneres.dll" ascii
        $s3 = "update_b" ascii
        $x1 = "/photo.png" wide
    condition:
        uint16(0) == 0x5A4D and
        2 of ($s*) or $x1
}
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **Domain**    | `form-style-resource.com`                         | C2 Domain                   |
| **IP Address**| `45.147.229.15`                                   | C2 Server                   |
| **File Name** | `document_copy.doc`                               | Malicious Attachment        |
| **File Name** | `license.dat`                                     | Dropped DLL Payload         |
| **Hash**      | `7f8e9d1a2b3c4d5e6f7a8b9c0d1e2f3a`                | IcedID DLL Hash             |

## Indicators of Attack (IOAs)

*   **Office Spawning System Binaries:** Word or Excel launching `rundll32.exe`, `regsvr32.exe`, or `cmd.exe`.
*   **Unusual Scheduled Task Creation:** `schtasks.exe` creating a task with a random name pointing to a file in `%AppData%`.
*   **Svchost Network Activity:** A `svchost.exe` process initiating connections to public IPs on port 8080 or 443 (if not part of standard Windows services).

## Priority Recommendations

1.  **Disable Macros:** Enforce Group Policy to block macros from the Internet (Mark-of-the-Web).
2.  **Monitor Rundll32:** Alert on `rundll32.exe` execution where the parent is not `explorer.exe` or `services.exe`.
3.  **Network Segmentation:** Restrict workstation-to-workstation communication to limit lateral movement.

## Platform Things


**Log Event:**
```text
2025-12-05 09:30:15,WORKSTATION-FIN-02,finance_user,2045,C:\Program Files\Microsoft Office\Office16\WINWORD.EXE,"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" /n "C:\Users\finance_user\Downloads\document_copy.doc",-,-,-,-,-,-,a1b2c3d4e5f678901234567890abcdef
```

```yaml
title: Malicious Document Execution
id: 3a4b5c6d-7e8f-4901-ab2c-3d4e5f67890a
status: stable
description: Detects the execution of a suspicious document file via Word.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|contains: 'WINWORD.EXE'
    commandline|contains: '.doc'
  condition: selection
level: medium
```

**Log Event:**
```text
2025-12-05 09:30:20,WORKSTATION-FIN-02,finance_user,4099,C:\Windows\System32\rundll32.exe,"rundll32.exe" C:\Users\finance_user\AppData\Local\Temp\license.dat,PluginInit,C:\Program Files\Microsoft Office\Office16\WINWORD.EXE,-,-,-,-,-,-
```

```yaml
title: IcedID DLL Execution via Rundll32
id: 1b2c3d4e-5f6a-4789-0123-456789abcdef
status: stable
description: Detects rundll32 loading a DLL from a Temp directory spawned by Word.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    parentimage|contains: 'WINWORD.EXE'
    image|contains: 'rundll32.exe'
    commandline|contains: 'Temp'
  condition: selection
level: critical
```

**Log Event:**
```text
2025-12-05 09:30:25,WORKSTATION-FIN-02,finance_user,5100,C:\Windows\System32\schtasks.exe,"schtasks.exe" /create /tn "UpdateHelper" /tr "rundll32.exe C:\Users\finance_user\AppData\Local\Temp\license.dat,PluginInit" /sc onlogon,C:\Windows\System32\rundll32.exe,-,-,-,-,-,-
```

```yaml
title: Scheduled Task Creation for Persistence
id: 9a8b7c6d-5e4f-4321-0987-654321fedcba
status: stable
description: Detects the creation of a scheduled task to maintain persistence for the IcedID payload.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|contains: 'schtasks.exe'
    commandline|contains|all:
      - '/create'
      - 'rundll32.exe'
      - 'onlogon'
  condition: selection
level: high
```

**Log Event:**
```text
2025-12-05 09:31:00,WORKSTATION-FIN-02,finance_user,1055,C:\Windows\System32\svchost.exe,-,-,-,-,45.147.229.15,443,TCP,-
```

```yaml
title: Suspicious Svchost Network Connection
id: f1e2d3c4-b5a6-4978-0123-456789abcdef
status: experimental
description: Detects a system process (svchost) initiating a network connection to an external IP, which can indicate process injection (Note: requires tuning).
author: Nihal
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    image|contains: 'svchost.exe'
    initiated: 'true'
    protocol: tcp
    destinationport: 443
  condition: selection
level: medium
```
