# SCARLETEEL Threat Intel Report

THREAT LEVEL: CRITICAL

Subject: Operation SCARLETEEL (Cloud-Native Campaign)

Author: Nihal

Date: December 23, 2025

## High-Level Summary

SCARLETEEL is a sophisticated operation targeting containerized cloud environments (specifically AWS Fargate and Kubernetes). Unlike typical "smash-and-grab" cryptojacking scripts, SCARLETEEL combines crypto-mining with high-value intellectual property theft. The actors exploit vulnerable public-facing web applications (like Jupyter Notebooks) to gain initial access, steal AWS credentials from the Instance Metadata Service (IMDS), and pivot laterally to compromise the broader cloud estate.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | SCARLETEEL (Operation/Campaign)                                       |
| Attribution        | Unknown (Likely Financially Motivated)                                |
| Target Assets      | AWS Fargate, Kubernetes Clusters, IAM Credentials, Proprietary Code   |
| Primary Objective  | Intellectual Property Theft & Cryptomining                            |
| Propagation Vector | Exploiting Public-facing Web Apps (e.g., Jupyter, Laravel)            |
| Targeted Platforms | Linux (Containers), AWS Cloud Control Plane                           |

## Threat at a Glance: Key ATT&CK TTPs (Cloud Focus)

*   **T1190 (Exploit Public-Facing Application):** Gains access by exploiting vulnerabilities in web applications hosted on containers.
*   **T1552.005 (Unsecured Credentials: Cloud Instance Metadata API):** Queries the AWS IMDS (`169.254.169.254`) to steal temporary IAM role credentials associated with the container.
*   **T1082 (System Information Discovery):** Uses built-in tools like `pacman` or `apt` to install AWS CLI and run reconnaissance commands (`aws sts get-caller-identity`).
*   **T1078.004 (Valid Accounts: Cloud Accounts):** Uses the stolen IAM credentials to authenticate against the AWS API from an external IP address.
*   **T1496 (Resource Hijacking):** Deploys XMRig miners to utilize compute resources.

## SCARLETEEL Deep Dive: Technical Analysis

### Initial Access & Persistence
The attack begins by compromising a container via a web vulnerability. Once inside, the attacker often lacks persistence mechanisms (since containers are ephemeral). To counter this, they attempt to create long-term IAM users or modify Security Groups if the stolen credentials allow it.

### Credential Access: The IMDS Exploit
The hallmark of this attack is the extraction of IAM Role credentials. The attacker runs a command similar to:
`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<RoleName>`
This returns the `AccessKeyId`, `SecretAccessKey`, and `Token` needed to impersonate the container's role.

### Lateral Movement
Once credentials are exfiltrated, the attacker configures the AWS CLI on their own C2 infrastructure using these keys. They then enumerate S3 buckets (`aws s3 ls`) and attempt to download sensitive code or customer data.

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Infiltration**
    Attacker finds a misconfigured Jupyter Notebook exposed to the internet and opens a terminal session.

2.  **Tooling Up**
    Attacker installs reconnaissance tools inside the container: `apt-get update && apt-get install awscli nmap -y`.

3.  **Credential Theft**
    Attacker queries the internal link-local address `169.254.169.254` to get temporary AWS credentials.

4.  **Reconnaissance (Cloud)**
    Using the stolen keys, they run `aws sts get-caller-identity` to see who they are, and `aws iam list-users` to map the permission landscape.

5.  **Action on Objectives**
    *   **Mining:** Downloads `xmrig` and starts mining Monero.
    *   **Theft:** Downloads the contents of private S3 buckets containing source code.

## Actionable Detections and Threat Hunting

### Hunting for IMDS Access
Monitoring for processes like `curl` or `wget` accessing the specific IP `169.254.169.254` from non-orchestration binaries is a critical detection signal.

### Sigma Rule (Cloud/Container)
Detects a command-line attempt to access AWS metadata.

```yaml
title: AWS Instance Metadata Service (IMDS) Query via CURL
id: 567890ab-cdef-1234-5678-90abcdef1234
status: stable
description: Detects curl or wget commands attempting to access the AWS Instance Metadata Service, a common technique for stealing cloud credentials.
author: Nihal
date: 2025-12-23
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    image|endswith: 
      - '/curl'
      - '/wget'
    commandline|contains: '169.254.169.254'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **IP Address**| `45.9.148.221`                                    | C2 / Miner Pool             |
| **IP Address**| `169.254.169.254` (Target)                        | AWS IMDS (Internal)         |
| **File Name** | `xmrig`                                           | Cryptominer                 |
| **Command**   | `aws s3 ls --recursive`                           | Bulk Data Enumeration       |
| **UserAgent** | `aws-cli/2.7.35 Python/3.9.11`                    | Suspicious if from unexpected IP |

## Platform Things

### Event Logs (Linux/Container & CloudTrail Simulation)

```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-23 14:00:01,prod-fargate-01,www-data,1022,/usr/bin/curl,"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",-,-,-,169.254.169.254,80,TCP,-
2025-12-23 14:05:00,prod-fargate-01,www-data,1045,/usr/bin/apt-get,"apt-get install awscli -y",-,-,-,-,-,-,-
2025-12-23 14:06:30,prod-fargate-01,www-data,1088,/usr/local/bin/aws,"aws s3 ls",-,-,-,-,-,-,-
2025-12-23 14:10:00,prod-fargate-01,www-data,1100,/tmp/xmrig,"./xmrig -o pool.minexmr.com:443 -u WALLET_ID",-,-,-,103.212.111.22,443,TCP,a1b2c3d4e5f678901234567890abcdef
```

### Sigma Rules(3)

**Log Event:**
```text
2025-12-23 14:00:01,prod-fargate-01,www-data,1022,/usr/bin/curl,"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",-,-,-,169.254.169.254,80,TCP,-
```

```yaml
title: Potential Cloud Credential Theft via IMDS
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: critical
description: Detects attempts to retrieve IAM credentials from the link-local metadata service using command line tools.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains|all:
      - '169.254.169.254'
      - 'security-credentials'
  condition: selection
level: critical
```

**Log Event:**
```text
2025-12-23 14:05:00,prod-fargate-01,www-data,1045,/usr/bin/apt-get,"apt-get install awscli -y",-,-,-,-,-,-,-
```

```yaml
title: Installation of AWS CLI in Container
id: 99887766-5544-3322-1100-aabbccddeeff
status: high
description: Detects the installation of the AWS CLI tool inside a production container, which is often a precursor to reconnaissance.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    image|endswith: 
      - '/apt-get'
      - '/yum'
      - '/apk'
    commandline|contains: 'awscli'
  condition: selection
level: high
```

**Log Event:**
```text
2025-12-23 14:10:00,prod-fargate-01,www-data,1100,/tmp/xmrig,"./xmrig -o pool.minexmr.com:443 -u WALLET_ID",-,-,-,103.212.111.22,443,TCP,a1b2c3d4e5f678901234567890abcdef
```

```yaml
title: Cryptominer Execution (XMRig)
id: ffeeccdd-1122-3344-5566-77889900aabb
status: high
description: Detects the execution of the XMRig cryptominer based on command line arguments.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains:
      - 'xmrig'
      - 'pool.minexmr.com'
      - 'stratum+tcp'
  condition: selection
level: high
```
