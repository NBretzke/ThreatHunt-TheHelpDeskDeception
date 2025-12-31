# 🛡️ Threat Hunt Report: Simulated Support Tool Misuse & Persistence

## Overview

This threat hunt investigates a simulated incident involving suspected misuse of a “support tool” across intern-operated machines. The activity followed a recognizable attack sequence: initial foothold, host reconnaissance, security tampering indicators, data staging, outbound connectivity validation, persistence, and narrative misdirection.

The objective was to reconstruct the timeline, separate legitimate system behavior from staged artifacts, and determine intent using Microsoft Defender for Endpoint (MDE) telemetry.

---

## Scope & Starting Intelligence

### Initial Intel Provided

- Multiple machines spawned processes from **Downloads** folders in early October.
- Several endpoints shared **similar executables and naming patterns**.
- Common keywords across artifacts included **desk**, **help**, **support**, and **tool**.
- **Intern-operated machines** appeared disproportionately affected.

This combination suggested targeted activity masquerading as legitimate support operations.

---

## Identifying the Primary Endpoint

An early hypothesis focused on intern accounts as likely entry points. The following query helped isolate suspicious behavior outside standard Windows directories:

```kql
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-30))
| where not(FolderPath startswith @"C:\Windows\")
| where FolderPath contains "intern"
| order by TimeGenerated asc
```
## Result
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/Pre-HuntFlag.png">
- Device: gab-intern-vm

This device became the primary focus of the hunt. It had a high amount of activity in the first half of October and featured "intern" in the device and account name.

## Initial Access / Entry Point

The next step was to determine the earliest anomalous execution that could represent an entry point. In threat hunting, anchoring the timeline is critical; identifying the first unusual action allows subsequent activity to be interpreted as follow-on behavior rather than isolated noise.

The investigation focused on interactive PowerShell usage, particularly scripts executed from the Downloads directory.

```kql
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-30))
| where AccountName == "g4bri3lintern"
| where FileName == "powershell.exe"
| where ProcessCommandLine has "SupportTool"
| order by TimeGenerated asc
```
The earliest suspicious execution observed was:
```kql
powershell.exe -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag1.png">
This command strongly suggests intentional user-driven execution. The use of ExecutionPolicy Bypass combined with a script launched from a Downloads folder is a well-known red flag, frequently associated with initial access or the execution of unsanctioned tooling.

## Simulated Security Tampering Indicator
Following initial execution, the hunt revealed activity designed to imply changes to the system’s security posture. Rather than directly disabling protections, the actor created artifacts that suggested Defender tampering.
```kql
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-30))
| where AccountName == "g4bri3lintern"
| where InitiatingProcessCommandLine contains "tamper"
| order by TimeGenerated asc
```
This query surfaced a PowerShell command that wrote a Defender-related instruction into a public text file:
```kql
Write-Output 'Set-MpPreference -DisableRealtimeMonitoring $true'| Out-File 'C:\Users\Public\DefenderTamperArtifact.txt'
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag2.png">
Importantly, this action did not actually modify Defender configuration. Instead, it created a tangible artifact implying tampering. From a hunting perspective, this represents intent, not effect. Such staged indicators are commonly used to mislead analysts or create plausible explanations during later review.

## Shortcut-Based Misdirection Artifact
Further reinforcing the misdirection theme, file system telemetry revealed the creation of a shortcut referencing the tamper artifact.
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName == "explorer.exe"
| summarize by FileName, FolderPath
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag3.png">
The presence of DefenderTamperArtifact.lnk is significant. Shortcuts are user-facing and are often opened via Explorer, suggesting deliberate placement for visibility. While the underlying text file contained no functional tampering, the shortcut served to reinforce a false narrative that Defender settings had been altered.

## Clipboard Reconnaissance
As the timeline progressed, the actor performed quick, low-effort reconnaissance targeting transient data sources.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "clipboard"
```
This query revealed the execution of:
```kql
powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag4.png">
This command silently checks the clipboard without logging or storing its contents. Such behavior is characteristic of attackers looking for easy wins—credentials, tokens, or copied data—before committing to broader reconnaissance or collection efforts.

## Host & Storage Enumeration
Subsequent activity focused on understanding the host environment. Commands such as qwinsta, tasklist, and wmic logicaldisk were executed to enumerate active sessions, running processes, and available storage.
```kql
The query I used was: 
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("Get-PSDrive","Get-Volume","Get-Disk","wmic logicaldisk","fsutil fsinfo drives","mountvol","diskpart")
| project TimeGenerated, AccountName, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine
```
For example:
```kql
cmd.exe /c wmic logicaldisk get name,freespace,size
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag5.png">
## Network Reachability & Data Staging
The actor confirmed outbound network connections by connecting to well known endpoints to avoid detection. In connecting with endpoints, the actor was preparing for successful exfiltration of data.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping","nslookup","ipconfig","tracert","pathping","Test-NetConnection","Resolve-DnsName","Get-DnsClient","netsh","route","arp")
| project TimeGenerated, AccountName, FileName,InitiatingProcessFileName, InitiatingProcessCommandLine,ProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated desc
```
This query genereated logs of endpoints connections that all had the same parent process:
```kql
RuntimeBroker.exe
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag6.png">

## Enumerate Active Sessions
The actor enumerated active sessions on nearby hosts to keep secrecy. Using the following query was helpful in understanding how the attacker was methodically approaching their next step.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("quser","query user","qwinsta")
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag7.png">
The earliest unique process ID of enumeration was "2533274790397065". This is helpful in correlating these events with other endpoint databases. 


## Persistence Mechanism

To ensure continued access, the actor established process enumeration using a scheduled task.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("Get-Process","ps ","tasklist","wmic process","Win32_Process","Get-CimInstance","wmi")
```
This revealed how the attacker created persistent tasks using:
```kql
TaskList.exe
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag8.png">
Scheduled execution on logon ensures the tooling survives beyond a single session, a common persistence technique that blends easily into administrative activity if naming is carefully chosen.

## Privilege Enumeration

Detect attempts to understand privileges available to the current actor.
After establishing an initial foothold and conducting lightweight reconnaissance, the next logical step for an actor is to determine **what level of access they currently possess**. Privilege enumeration informs whether further action can be taken immediately or whether elevation is required.
In Windows environments, this often takes the form of built-in commands that enumerate group membership, token privileges, and local administrative rights. These commands are low-noise, widely available, and commonly used by both administrators and attackers.
To identify this behavior, process telemetry was examined for commands associated with user and privilege enumeration.
Query:
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami /all","whoami /groups","whoami /priv","net user","net localgroup","Get-LocalGroup","Get-LocalGroupMember")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated desc
```
This enumeration began at the timestamp below:
```kql
2025-10-09T12:52:14.3646503Z
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag9.png">
This activity demonstrates deliberate privilege awareness. Rather than immediately attempting elevation, the actor first assessed their current access level. This behavior aligns with controlled, methodical post-access decision-making rather than opportunistic exploitation.

## Outbound Reachability Validation

Before attempting to move data off-host, an actor must confirm that outbound connectivity is possible. This step is critical: without egress, later staging and exfiltration attempts are futile.
Rather than using overt or suspicious endpoints, attackers often rely on legitimate system connectivity checks to validate outbound access. These checks blend into normal operating system behavior and reduce detection risk.

Query Used:
```kql
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15))
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag10.png">
The domain contacted was: www.msftconnecttest.com

msftconnecttest.com is a Windows Network Connectivity Status Indicator (NCSI) endpoint. While benign in isolation, its appearance within this sequence strongly suggests intentional egress validation prior to staging or transfer activity. This step confirms both access and readiness for potential data movement.

## Artifact Staging

Following reconnaissance and connectivity validation, the actor transitioned into staging—the process of consolidating collected artifacts into a form suitable for transfer. Staging simplifies exfiltration by reducing multiple files into a single package. Compressed archives are a common choice due to their efficiency and ubiquity.

Query Used:
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where (FileName contains "recon") or (FolderPath contains "recon") 
| sort by TimeGenerated asc
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
```
This query led me to the artifact: 
```kql
ReconArtifact.zip
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag11.png">
The creation of a recon-themed archive marks a clear transition from discovery to pre-exfiltration preparation. This behavior should be correlated back to earlier reconnaissance to fully understand what data was deemed valuable.


## Outbound Transfer Attempt
Even failed or incomplete transfer attempts provide valuable insight into attacker intent. At this stage, the focus shifts from preparation to execution, where the actor tests whether data can be moved beyond the endpoint.

Query Used:
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| sort by TimeGenerated asc
| project TimeGenerated, RemoteIP, ActionType, RemoteUrl,
          InitiatingProcessAccountName, InitiatingProcessCommandLine,
          InitiatingProcessFileName
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag12.png">
The remote IP the attacker attempted to send information to was 100.29.147.161. Regardless of success or failure, this outbound attempt demonstrates intent to move data off-host. Such events are critical for understanding possible egress paths and identifying control points for prevention.

## Persistence via Scheduled Task

Persistence mechanisms allow an actor to survive beyond a single session. Scheduled tasks are particularly attractive because they are native to Windows, easy to configure, and can appear legitimate if named carefully.

Query Used:
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName == "schtasks.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```
The task name found was SupportToolUpdater. The task name mimics legitimate administrative tooling, reinforcing the broader theme of masquerading. Logon-triggered execution ensures the actor’s tooling persists across sessions without requiring additional user interaction.
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/flag13.png">

## Planted Narrative Artifact
Rather than relying solely on technical stealth, the actor attempted human-level misdirection by leaving behind artifacts that framed the activity as legitimate support work. These artifacts are designed to influence interpretation during casual review. Shortcuts (.lnk files) are particularly effective because they are user-visible and commonly interacted with.

Query Used:
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where (FileName contains ".lnk")
```
<img width="1000" src="https://github.com/NBretzke/ThreatHunt-TheHelpDeskDeception/blob/main/lastflag.png">
The narrative artifact found was titled SupportChat_log.lnk. This shortcut reinforces the illusion of a legitimate support session. When viewed in isolation, it appears benign; when viewed in sequence, it serves as a cover story for prior suspicious activity.
## Executive Summary

This threat hunt reconstructed a simulated incident involving the misuse of a purported support tool on an intern-operated Windows endpoint. While individual actions initially appeared consistent with legitimate administrative or troubleshooting behavior, correlating telemetry across process execution, file system activity, and network events revealed a deliberate and methodical attack sequence.

The investigation identified a clear progression: execution of an unsigned PowerShell script from a user-controlled directory, reconnaissance of host context and privileges, staged indicators of security tampering, opportunistic data collection, artifact consolidation, outbound connectivity validation, simulated transfer attempts, and persistence through scheduled task creation. The activity concluded with the placement of narrative artifacts designed to frame the behavior as a routine support interaction.

This hunt highlights how attackers can rely on plausibility, sequence, and human misdirection—rather than overt exploitation—to blend into enterprise environments. The findings reinforce the importance of timeline-based threat hunting and contextual analysis when evaluating seemingly benign activity.

---
## High-Level Timeline

| Phase | Key Activity |
|------|-------------|
| Initial Access | SupportTool.ps1 executed from Downloads |
| Recon | Clipboard, session, storage enumeration |
| Staging | ReconArtifact.zip created |
| Egress Prep | msftconnecttest.com connectivity check |
| Persistence | Scheduled task `SupportToolUpdater` |
| Cover | SupportChat_log.lnk placed |
---

## Lessons Learned

### 1. Sequence Matters More Than Individual Events  
Many of the observed actions such as PowerShell usage, scheduled tasks, shortcuts, and connectivity checks are common in enterprise environments. Evaluated in isolation, none were conclusively malicious. Only by reconstructing the **full timeline** did the coordinated intent become apparent. Effective threat hunting depends on understanding how events relate over time, not just what occurred.

### 2. Legitimate Tools Can Enable Malicious Outcomes  
The actor relied almost entirely on native Windows utilities and PowerShell rather than custom malware. This underscores the challenge defenders face in distinguishing malicious activity from administrative behavior and reinforces the importance of behavioral baselining and context-aware analysis.

### 3. Artifacts Can Signal Intent Without Causing Impact  
Several findings—such as the Defender tamper artifact—were staged rather than functional. These artifacts did not change system configuration but served as **signals of intent** and misdirection. Treating intent as a meaningful hunting signal is critical, even when no direct impact is observed.

### 4. Narrative Misdirection Is a Real Technique  
The placement of support-themed shortcuts and logs demonstrates how attackers may attempt to influence human interpretation. Threat hunts should account for **social engineering artifacts**, not just technical indicators, when reconstructing activity.

### 5. Baseline Noise Must Be Understood, Not Ignored  
System-generated events such as connectivity checks (`msftconnecttest.com`) and scheduled background tasks are often dismissed as noise. However, their **timing and context** can make them meaningful. Understanding baseline behavior is essential to recognizing when it is being intentionally leveraged.

### 6. Clear Flag Definitions Matter in Simulated Hunts  
This exercise also highlighted the importance of precise definitions in structured hunts. Ambiguity around expected formats or interpretations can obscure valid analysis. In real-world investigations, documenting assumptions and definitions up front helps prevent misalignment during incident response.

---
