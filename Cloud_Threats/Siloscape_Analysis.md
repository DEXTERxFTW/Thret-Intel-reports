# Siloscape Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: Operation Siloscape (Windows Container Escape)

Author: Nihal

Date: January 30, 2026

## High-Level Summary

Siloscape is the first heavily obfuscated malware targeting **Windows Containers** in Kubernetes environments. Its primary goal is not just cryptomining, but **Cluster Compromise**. It exploits known vulnerabilities (like the "CloudContainer" exploit) to escape the container, execute code on the underlying host node, and steal Kubernetes credentials. This allows the attacker to issue `kubectl` commands to the API server, potentially backdooring the entire cluster.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | Siloscape                                                             |
| Attribution        | Unknown                                                               |
| Target Assets      | Windows Server Containers, Kubernetes Clusters                        |
| Primary Objective  | Cluster Backdooring & Resource Hijacking                              |
| Propagation Vector | Exploiting Public-Facing Web Apps (ASP.NET, older IIS)                |
| Targeted Platforms | Windows Server (Containerized)                                        |

## Threat at a Glance: Key ATT&CK TTPs (Cloud Focus)

*   **T1611 (Escape to Host):** Exploits vulnerabilities (e.g., CVE-2021-34424) to break out of the container isolation and access the underlying node.
*   **T1609 (Container Administration Command):** actively searches for the `kubectl` binary or kubeconfig files to run commands against the cluster API.
*   **T1071.003 (Application Layer Protocol: IRC):** Uses the IRC protocol over Tor (using a bundled Tor client) to communicate with its C2 server, a rare technique in modern cloud malware.
*   **T1059.001 (Command and Scripting Interpreter: PowerShell):** Heavily relies on obfuscated PowerShell scripts for the escape logic and persistence.

## Siloscape Deep Dive: Technical Analysis

### Initial Access
Attackers compromise a web application running inside a Windows container (e.g., a vulnerable .NET app). They gain a webshell or remote code execution (RCE).

### The Great Escape
Siloscape uses a technique often involving the impersonation of the `CExecSvc.exe` process or abusing symbolic links (symlinks) to access the host's filesystem. Once on the host, it searches for Kubernetes credentials (usually found in `C:\var\lib\kubelet\` or environment variables).

### C2 Communication (IRC via Tor)
The malware connects to an IRC server via the Tor network. It joins a channel where it receives commands. This makes tracking the C2 infrastructure extremely difficult for defenders.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Infiltration**
    Attacker exploits a vulnerability in a web server running inside a Windows container.

2.  **Escape**
    Siloscape executes an exploit to break out of the container boundary, gaining `System` privileges on the node.

3.  **Credential Theft**
    It hunts for the `kubeconfig` file or service account tokens used by the node to talk to the K8s API.

4.  **Cluster Expansion**
    Using the stolen credentials, it queries the API Server (`kubectl get nodes`, `kubectl create deployment`) to launch malicious pods (miners or backdoors) across the entire cluster.

5.  **C2 check-in**
    It connects to the IRC C2 to report success and await further commands.

## Actionable Detections and Threat Hunting

### Hunting for "CloudContainer" Escape
Look for suspicious processes spawning from `w3wp.exe` (IIS Worker) that attempt to access the host file system or global namespaces.

### Sigma Rule (Windows/Container)
Detects the specific behavior of Siloscape trying to find the Kubernetes client binary `kubectl.exe` on a Windows host.

```yaml
title: Siloscape Kubectl Discovery
id: 44556677-8899-0011-2233-445566778899
status: high
description: Detects command line activities associated with Siloscape searching for the Kubernetes control binary 'kubectl' on a Windows node.
author: Nihal
date: 2026-01-02
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'where /r'
      - 'kubectl.exe'
  condition: selection
level: high
tags:
  - attack.discovery
  - attack.t1083
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :---------------- | :------------------------------------------------ | :-------------------------- |
| **File Hash** | `95a32ac...` (SHA256)                             | Siloscape Main Binary       |
| **Mutex**     | `Siloscape`                                       | Global Mutex                |
| **File Name** | `CloudContainer.exe`                              | Escape Exploit              |
| **Protocol**  | IRC (Port 6667, 9050 for Tor)                     | C2 Traffic                  |
| **Command**   | `kubectl get nodes`                               | Suspicious if from WebSvc   |

## Platform Things

### Event Logs (Windows Security Simulation)

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2026-01-02 11:30:00,win-node-01,IIS AppPool\DefaultAppPool,3120,C:\Windows\System32\cmd.exe,"cmd.exe /c CloudContainer.exe",-,-,-,-,-,-,-
2026-01-02 11:30:05,win-node-01,NT AUTHORITY\SYSTEM,3145,C:\Windows\System32\cmd.exe,"cmd.exe /c where /r C:\ kubectl.exe",-,-,-,-,-,-,-
2026-01-02 11:30:15,win-node-01,NT AUTHORITY\SYSTEM,3150,C:\Temp\Siloscape.exe,"Siloscape.exe",-,-,-,127.0.0.1,9050,TCP,f5d4c3b2a1098765432101234567890abcde1234
```

### Sigma Rules(2)

**Log Event:**
```text
2026-01-02 11:30:05,win-node-01,NT AUTHORITY\SYSTEM,3145,C:\Windows\System32\cmd.exe,"cmd.exe /c where /r C:\ kubectl.exe",-,-,-,-,-,-,-
```

```yaml
title: Suspicious Kubectl Search via Cmd
id: 77889900-1122-3344-5566-778899001122
status: high
description: Detects a process attempting to locate the 'kubectl.exe' binary across the filesystem, a technique used by Siloscape to tool up after escaping.
author: Nihal
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'where'
      - 'kubectl.exe'
  condition: selection
level: high
```

**Log Event:**
```text
2026-01-02 11:30:15,win-node-01,NT AUTHORITY\SYSTEM,3150,C:\Temp\Siloscape.exe,"Siloscape.exe",-,-,-,127.0.0.1,9050,TCP,f5d4c3b2a1098765432101234567890abcde1234
```

```yaml
title: Tor Process Connection (Local Proxy)
id: bbccdd11-2233-4455-6677-bbccdd112233
status: medium
description: Detects a process connecting to the local Tor proxy port (9050 or 9150), often used by malware to route traffic through Tor.
author: Nihal
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '127.0.0.1'
    DestinationPort:
      - 9050
      - 9150
  condition: selection
level: medium
```
