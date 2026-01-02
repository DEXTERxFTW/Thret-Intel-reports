# Denonia Threat Intel Report

THREAT LEVEL: HIGH

Subject: Operation Denonia (Serverless Malware)

Author: Nihal

Date: December 29, 2026

## High-Level Summary

Denonia is notable for being the first publicly discovered malware specifically designed to execute inside **AWS Lambda** environments. Written in Go, it deploys a customized XMRig cryptominer. What makes Denonia unique is its use of **DNS over HTTPS (DoH)** to communicate with its C2 server, effectively bypassing traditional network monitoring and firewall rules that might block direct IP connections. It demonstrates that serverless functions are not immune to malware, despite their ephemeral nature.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | Denonia                                                               |
| Attribution        | Unknown                                                               |
| Target Assets      | AWS Lambda (Serverless Functions), Amazon Linux Environments          |
| Primary Objective  | Cryptojacking (Monero Mining)                                         |
| Propagation Vector | Compromised AWS Credentials or Supply Chain Injection in Lambda Layers|
| Targeted Platforms | Linux (AWS Lambda Runtime)                                            |

## Threat at a Glance: Key ATT&CK TTPs (Cloud Focus)

*   **T1071.004 (Application Layer Protocol: DNS):** Uses DNS over HTTPS (DoH) to hide command and control traffic inside legitimate HTTPS requests.
*   **T1588.002 (Obtain Capabilities: Tool):** Deploys a customized version of the XMRig miner adapted for the Lambda environment.
*   **T1496 (Resource Hijacking):** Consumes AWS Lambda compute time (billed by the millisecond) to mine cryptocurrency.
*   **T1574.002 (Hijack Execution Flow: DLL Side-Loading):** (Theoretical variant) Could potential hijack LD_PRELOAD in the Lambda execution environment.

## Denonia Deep Dive: Technical Analysis

### Execution Environment
Denonia is a 64-bit ELF executable written in Go. It checks if it is running inside an AWS Lambda environment by inspecting environment variables like `AWS_LAMBDA_FUNCTION_NAME`.

### Command and Control (DoH)
Unlike standard malware that connects to an IP address, Denonia uses DoH to query a malicious domain. It often uses the Google (`8.8.8.8`) or Cloudflare (`1.1.1.1`) DoH resolvers. This makes the traffic look like legitimate HTTPS traffic to a trusted DNS provider, bypassing outbound filtering.

### Evasion Techniques
The malware creates a hidden directory `/tmp/.denonia` (since `/tmp` is the only writable path in Lambda) to store its miner and configuration logs. It relies on the ephemeral nature of Lambda (max 15 min runtime) to wipe traces automatically when the function times out.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Infiltration**
    Attacker compromises AWS credentials with `lambda:UpdateFunctionCode` permissions or injects malicious code into a shared Lambda Layer.

2.  **Deployment**
    The attacker updates a legitimate Lambda function to include the Denonia Go binary.

3.  **Execution**
    When the Lambda is triggered (by an event or manually), Denonia starts.

4.  **C2 Communication (DoH)**
    It resolves its mining pool address using DNS over HTTPS, evading VPC flow log alerts for "bad IPs".

5.  **Mining**
    It spawns the XMRig miner, consuming the function's allocated memory and CPU until the 15-minute timeout is reached.

## Actionable Detections and Threat Hunting

### Hunting for High Costs
The most reliable indicator for Denonia is a sudden spike in **AWS Lambda billing costs** or **Duration** metrics hitting the 15-minute timeout cap repeatedly.

### Sigma Rule (Cloud/Network)
Detects the use of DNS over HTTPS to known non-corporate resolvers within a serverless context.

```yaml
title: DNS over HTTPS (DoH) Usage in Lambda
id: 33445566-7788-9900-aabb-ccddeeff0011
status: experimental
description: Detects connection attempts to common public DNS-over-HTTPS providers (Google, Cloudflare) from within an AWS Lambda environment, which may indicate C2 evasion.
author: Nihal
date: 2026-01-02
logsource:
  category: network_connection
  product: linux
detection:
  selection_doh_ips:
    DestinationIp:
      - '8.8.8.8'
      - '8.8.4.4'
      - '1.1.1.1'
    DestinationPort: 443
  selection_process:
    Image|contains: '/var/task/' # Default Lambda task directory
  condition: selection_doh_ips and selection_process
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **Domain**    | `gw.denonia.xyz`                                  | C2 Domain                   |
| **IP Address**| `1.1.1.1`, `8.8.8.8` (Port 443)                   | Used for DoH tunneling      |
| **File Name** | `denonia`                                         | The main binary             |
| **Env Var**   | `AWS_LAMBDA_FUNCTION_NAME`                        | Checked by malware          |
| **Path**      | `/tmp/.denonia`                                   | Hidden working directory    |

## Platform Things

### Event Logs (CloudTrail & VPC Flow Logs Simulation)

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2026-01-02 10:00:01,aws-lambda-function,lambda_exec,501,/var/task/denonia,"./denonia",-,-,-,-,-,-,a1b2c3d4e5f678901234567890abcdef12345678
2026-01-02 10:00:05,aws-lambda-function,lambda_exec,505,/var/task/denonia,"[DoH Query] https://1.1.1.1/dns-query?name=gw.denonia.xyz",-,-,-,1.1.1.1,443,TCP,-
2026-01-02 10:00:10,aws-lambda-function,lambda_exec,510,/tmp/.denonia/xmrig,"./xmrig --config config.json",-,-,-,198.51.100.22,443,TCP,-
```

### Sigma Rules(2)

**Log Event:**
```text
2026-01-02 10:00:01,aws-lambda-function,lambda_exec,501,/var/task/denonia,"./denonia",-,-,-,-,-,-,a1b2c3d4e5f678901234567890abcdef12345678
```

```yaml
title: Suspicious Binary Execution in Lambda /var/task
id: 66778899-0011-2233-4455-6677889900aa
status: high
description: Detects the execution of unknown binaries directly from the Lambda task root, which is unusual for interpreted languages like Python/Node.js.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    image|startswith: '/var/task/'
    image|endswith: 'denonia' # Specific IOC, but can be genericized
  condition: selection
level: high
```

**Log Event:**
```text
2026-01-02 10:00:10,aws-lambda-function,lambda_exec,510,/tmp/.denonia/xmrig,"./xmrig --config config.json",-,-,-,198.51.100.22,443,TCP,-
```

```yaml
title: Execution from /tmp in Lambda
id: aa00bb11-cc22-dd33-ee44-ff5500112233
status: medium
description: Detects binary execution from the /tmp directory in a Lambda environment, a common tactic for dropped payloads.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection_path:
    image|startswith: '/tmp/'
  selection_context:
    ParentImage|startswith: '/var/task/' # Spawned by the main function
  condition: selection_path and selection_context
level: medium
```
