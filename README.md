
<p align="center">
  <img
    src="https://i.imgur.com/APWYuq7.jpeg"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>




# 🛡️ Threat Hunt Report – Crosscheck

---

## 📌 Executive Summary

Investigation of irregular access patterns during year-end compensation reviews involving unauthorized script execution, sensitive file access, and data exfiltration.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:**  sys1-dept (initial target device), main1-srvr (secondary target device)
- **Data Sources:** Logs from Log Analytics Workspace in Azure
- **Timeframe:** 2025-12-03 → 2025-12-04  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The investigation focused on a targeted intrusion where a threat actor utilized remote interactive sessions (RDP) to infiltrate the network and access sensitive year-end bonus and compensation documentation. This activity was critical to identify because it threatened the confidentiality of finalized financial data, with the attacker progressing to staging the data into archives and attempting outbound exfiltration. By correlating endpoint telemetry with logon events, the hunt successfully reconstructed the attack chain, pinpointing the specific compromised accounts and identifying lateral movement to a second device executing similar evasion and discovery tactics

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Valid Accounts | T1078 | High |
| 2 | Remote Desktop Protocol | T1021.001 | High |
| 3 | PowerShell | T1059.001 | High |
| 4 | System Owner/User Discovery | T1033 | Medium |
| 5 | File and Directory Discovery | T1083 | High |
| 6 | Archive via Utility | T1560.001 | High |
| 7 | Application Layer Protocol | T1071 | High |
| 8 | Registry Run Keys / Startup Folder | T1547.001 | High |
| 9 | Scheduled Task | T1053.005 | High |
| 10 | Valid Accounts | T1078 | High |
| 11 | Remote Desktop Protocol | T1021.001 | High |
| 12 | Data from Local System | T1005 | Medium |
| 13 | Data from Local System | T1005 | Critical |
| 14 | Archive Collected Data | T1560 | High |
| 15 | Exfiltration Over Alternative Protocol | T1048 | Critical |
| 16 | Clear Windows Event Logs | T1070.001 | High |
| 17 | Remote Services | T1021 | Critical |
| 18 | Data from Local System | T1005 | High |
| 19 | Valid Accounts | T1078 | High |
| 20 | Archive Collected Data | T1560 | Critical |
| 21 | Archive Colelcted Data | T1560 | Low |
| 22 | Exfiltration Over Alternative Protocol | T1048 | Critical |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Initial Endpoint Association</strong></summary>

### 🎯 Objective
To establish an initial foothold on a workstation within the target environment.

### 📌 Finding
A specific local account (5y51-d3p7) was observed executing suspicious processes on the device sys1-dept.

### 💡 Why it matters
Identifies "Patient Zero," the entry point for the attack, allowing defenders to scope the initial breach.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents 
| where TimeGenerated >= datetime(2025-12-01)
| where AccountName == "5y51-d3p7" 
| summarize FirstSeen=min(TimeGenerated) by DeviceName 
| order by FirstSeen asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/glpiED0.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Implement User and Entity Behavior Analytics (UEBA) to alert on users logging into unusual devices or executing atypical administrative commands.

</details>

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Initial Remote Session IP</strong></summary>

### 🎯 Objective
To access the compromised host remotely, likely moving laterally from another internal segment.

### 📌 Finding
The attacker initiated a remote session to sys1-dept from the IP address 192.168.0.110

### 💡 Why it matters
Reveals the source of the attack (internal vs. external) and helps map the attacker's lateral movement path.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= datetime(2025-12-01)
| where InitiatingProcessRemoteSessionIP != ""
| summarize FirstSeen=min(TimeGenerated) by InitiatingProcessRemoteSessionIP
| order by FirstSeen asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/2eXTesz.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Restrict RDP access (Port 3389) to authorized jump hosts only and enforce MFA for all remote access.

</details>

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Support Script Execution</strong></summary>

### 🎯 Objective
To execute malicious code disguised as a legitimate administrative tool.

### 📌 Finding
Execution of a PowerShell script named PayrollSupportTool.ps1 from the user's Downloads folder using execution policy bypass flags.

### 💡 Why it matters
Demonstrates the attacker's method of running unauthorized code, often to install persistence or tools.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents 
| where AccountName == "5y51-d3p7" 
| where TimeGenerated >= datetime(2025-12-01) 
| where FileName in ("powershell.exe", "pwsh.exe") 
| where ProcessCommandLine has_any ("\\Users\\", "\\Downloads\\") 
| where ProcessCommandLine has ".ps1" 
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName 
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/fQKjauW.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Enforce PowerShell Constrained Language Mode and sign all legitimate administrative scripts.

</details>

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: System Reconnaissance</strong></summary>

### 🎯 Objective
To gather information about the current user's privileges and group memberships.

### 📌 Finding
The attacker ran whoami /all immediately after gaining access to understand their permissions.

### 💡 Why it matters
Indicates the attacker is in the "Discovery" phase and assessing if they can escalate privileges.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-01)
| where AccountName == "5y51-d3p7"
| where ProcessCommandLine has_any (
    "whoami",
    "quser",
    "qwinsta",
    "query user",
    "tasklist",
    "net user",
    "net group",
    "net localgroup",
    "systeminfo",
    "hostname",
    "ipconfig",
    "Get-Process",
    "Get-LocalUser",
    "Get-ADUser"
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/1JfbpH5.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for rapid execution of multiple discovery commands (whoami, net user, ipconfig) by non-admin users.

</details>

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Sensitive File Exposure</strong></summary>

### 🎯 Objective
To identify and collect high-value data related to financial compensation.

### 📌 Finding
The attacker accessed a sensitive file named BonusMatrix_Draft_v3.xlsx during their initial exploration.

### 💡 Why it matters
Confirms the attacker's intent is data theft (confidentiality breach) rather than just destruction.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName contains ("bonus")
| where TimeGenerated between (datetime(2025-12-03T03:12:03) .. datetime(2025-12-03T06:12:03) + 5h)
| project TimeGenerated, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/yw1Yg4j.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Implement strict File Integrity Monitoring (FIM) or DLP alerts for access to files with sensitive keywords like "Bonus" or "Salary."

</details>

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Data Staging Activity</strong></summary>

### 🎯 Objective
To bundle stolen data into a single file for easier exfiltration.

### 📌 Finding
A zip file was created to stage the stolen content, initiated by a specific process ID.

### 💡 Why it matters
Staging is a direct precursor to data exfiltration; detecting this offers a final chance to stop the data loss.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where InitiatingProcessIntegrityLevel != "System"
| where FileName has_any (".zip")
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/prYcLQB.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on the creation of archive files (zip, rar, 7z) in user profile directories like Downloads or Documents.

</details>

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Outbound Connectivity Test</strong></summary>

### 🎯 Objective
To verify that the compromised host can connect to the attacker's external infrastructure.

### 📌 Finding
A PowerShell-driven connection to an external endpoint was attempted to test egress capabilities.

### 💡 Why it matters
Confirms the attacker has a viable path to exfiltrate data.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where InitiatingProcessCommandLine contains ("powershell.exe")
| where InitiatingProcessAccountName == "5y51-d3p7"
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/5ak7Vbh.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Restrict outbound internet access for servers/workstations to allowed domains only (Allowlisting).

</details>

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Registry Persistence</strong></summary>

### 🎯 Objective
To ensure malicious tools run automatically whenever the user logs in.

### 📌 Finding
A registry value was added to the CurrentVersion\Run key to establish persistence.

### 💡 Why it matters
Persistence allows the attacker to maintain access even after reboots, turning a temporary intrusion into a long-term compromise.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/k2r4q3H.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor and alert on all changes to known auto-start registry keys (ASEPs).

</details>

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Persistence</strong></summary>

### 🎯 Objective
To create a redundant persistence mechanism that survives registry cleanups.

### 📌 Finding
A scheduled task named BonusReviewAssist was created to run the malicious PowerShell script daily.

### 💡 Why it matters
Shows the attacker is deeply embedding themselves into the system using built-in Windows tools.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= datetime(2025-12-01)
| where ProcessCommandLine has_any ("schtasks")
| order by TimeGenerated desc
```

The returned an action with the ProcessCommandLine of:

"schtasks.exe" /Create /SC DAILY /TN BonusReviewAssist /TR "powershell.exe -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1" /ST 09:15 /F


### 🖼️ Screenshot
<img src="https://i.imgur.com/fJ5jd68.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Audit scheduled task creation events (Event ID 4698) and alert on suspicious task names or paths.

</details>

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Secondary Access Scorecard</strong></summary>

### 🎯 Objective
To expand access or leverage compromised credentials from other departments.

### 📌 Finding
A different user account (YE-HELPDESKTECH) accessed employee scorecard files via a remote session.

### 💡 Why it matters
Indicates credential theft has spread beyond the initial user, complicating containment.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where IsInitiatingProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/zMeLbD7.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Implement strict role-based access control (RBAC) to ensure Helpdesk accounts cannot access HR/Finance data.

</details>

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Bonus Matrix Activity</strong></summary>

### 🎯 Objective
To access specific financial planning documents using a specialized department account.

### 📌 Finding
The YE-HRPLANNER remote session context was observed interacting with bonus payout files.

### 💡 Why it matters
Highlights the targeted nature of the attack against specific business functions (HR/Planning).

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| order by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/Hy51dd2.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for lateral movement where specific functional accounts access data outside their normal behavior.

</details>

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Performance Review Access</strong></summary>

### 🎯 Objective
To gather intelligence on high-value targets or employee performance data.

### 📌 Finding
The attacker used Notepad to open a performance review shortcut/file.

### 💡 Why it matters
Confirms manual review of documents, indicating a "hands-on-keyboard" operator.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any ("performance", "review", "employee", "bonus", "salary", "compensation") 
      or FolderPath has_any ("\\PerformanceReviews\\", "\\HRCorp\\", "\\Compensation\\")
```

And the ProcessCommandLine is 

"notepad.exe" C:\Users\5y51-D3p7\HR\PerformanceReviews\Review_JavierR.lnk

### 🖼️ Screenshot
<img src="https://i.imgur.com/w89ugKN.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Flag the use of simple text editors (notepad, wordpad) to open sensitive file types from unusual directories.

</details>

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Approved Bonus Access</strong></summary>

### 🎯 Objective
To steal the finalized, approved financial data (the "crown jewels").

### 📌 Finding
Unauthorized read access to the file BonusMatrix_Q4_Approved.xlsx.

### 💡 Why it matters
Represents the realization of the primary risk; the attacker has the finalized sensitive data.

### 🔧 KQL Query Used
Finally, after poking around and changing the table to

```kql
DeviceEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where ActionType == "SensitiveFileRead"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated desc
```

I found the file BonusMatrix_Q4_Approved.xlsx

Which happened at 2025-12-03T07:25:39.1653621Z

### 🖼️ Screenshot
<img src="https://i.imgur.com/SoHLn9t.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Deploy Information Rights Management (IRM) to prevent unauthorized opening of sensitive Excel sheets even if exfiltrated.

</details>

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Candidate Archive Location</strong></summary>

### 🎯 Objective
To hide the stolen data in a compressed format for transport.

### 📌 Finding
A zip file Q4Candidate_Pack.zip was created in the user's Documents folder.

### 💡 Why it matters
Identifies the exact artifact that needs to be tracked to see if it left the network.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-12-01)
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName endswith ".zip" 
    or FileName endswith ".7z" 
    or FileName endswith ".rar" 
    or FileName endswith ".tar" 
    or FileName endswith ".gz"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/LnS9yqI.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Correlate file creation events for archives with immediate subsequent network connections.

</details>

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Outbound Transfer Timestamp</strong></summary>

### 🎯 Objective
To exfiltrate the staged data to an external server.

### 📌 Finding
A successful outbound network connection was made shortly after the archive was created.

### 💡 Why it matters
Confirms the breach has occurred and data has likely been lost.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= datetime(2025-12-03T07:26:00)
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/1SMJjZw.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Network Intrusion Detection Systems (NIDS) should alert on large outbound transfers to uncategorized IP addresses.

</details>

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Log Clearing</strong></summary>

### 🎯 Objective
To remove forensic evidence of their activities.

### 📌 Finding
The attacker executed wevtutil to clear the PowerShell operational logs.

### 💡 Why it matters
An attempt to hinder incident response; often indicates the attacker is finishing their operation on that host.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-03T07:26:00)
| where DeviceName == "sys1-dept"
| where isnotempty(ProcessCommandLine)
| where isnotempty(ProcessRemoteSessionDeviceName)
| project 
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessRemoteSessionDeviceName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/9hdjNJq.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Forward logs to a central SIEM immediately so local clearing does not destroy the historical record.

</details>

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Second Endpoint Scope</strong></summary>

### 🎯 Objective
To move laterally to a high-value server (likely a file server or domain controller).

### 📌 Finding
Suspicious behavior (bypass, compression, discovery) was detected on a second device, main1-srvr.

### 💡 Why it matters
Shows the attack has spread to critical infrastructure, escalating the severity of the incident.

### 🔧 KQL Query Used
```kql
let StartDate = datetime(2025-12-01);
let EndDate = datetime(2025-12-05);
DeviceProcessEvents
| where TimeGenerated between (StartDate .. EndDate)
// Filter for any of the three suspicious behaviors in the command line
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine has_any (
    "-ExecutionPolicy Bypass", "-nop", "-w hidden", "-enc",  // Security Bypass flags
    "Compress-Archive", "7z", "winrar",                      // Compression/Staging
    "whoami /all", "systeminfo", "net user", "net group", "ipconfig /all" // Discovery
)
// Tag the events for easier analysis
| extend Tactic = case(
    ProcessCommandLine has_any ("-ExecutionPolicy Bypass", "-nop", "-enc"), "PS Bypass",
    ProcessCommandLine has_any ("Compress-Archive", "7z", "winrar"), "Compression",
    ProcessCommandLine has_any ("whoami", "systeminfo", "net user"), "Discovery",
    "Other Suspicious"
)
| project TimeGenerated, DeviceName, Tactic, FileName, ProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/q1DD5lY.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Segment high-value servers from general workstation networks to prevent easy lateral movement.

</details>

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Approved Bonus Access 2nd Endpoint</strong></summary>

### 🎯 Objective
To verify or collect the same sensitive data from the central server repository.

### 📌 Finding
The attacker accessed the approved bonus matrix again, this time on the server.

### 💡 Why it matters
Confirms the attacker is consolidating data from the source of discovery.

### 🔧 KQL Query Used
For this I pivoted back to DeviceEvents because I was looking for the ActionType of SensitiveFileRead:

```kql
let StartDate = datetime(2025-12-01);
let EndDate = datetime(2025-12-05);
DeviceEvents
| where ActionType == "SensitiveFileRead"
| where DeviceName == "main1-srvr"
| where FileName contains "bonus"
| where TimeGenerated between (StartDate .. EndDate)
| sort by TimeGenerated desc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/HgLV7vt.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Enable strict auditing on file servers for access to sensitive directories (SACLs).

</details>

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Employee Scorecard Access 2nd Endpoint</strong></summary>

### 🎯 Objective
To leverage Finance department credentials to access restricted server data.

### 📌 Finding
The device YE-FINANCEREVIE was identified as the remote source accessing scorecard files on the server.

### 💡 Why it matters
Identifies the specific compromised machine/account used for the server-side theft.

### 🔧 KQL Query Used
For this one I just used the suspicious looking RemoteSessionDeviceName I had seen accessing this device. I did not do a KQL looking specifically for access to a scorecard file, but used the last one

### 🖼️ Screenshot
<img src="https://i.imgur.com/rBqTWqx.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Implement "jump boxes" or Privileged Access Workstations (PAWs) for all Finance/HR administrative tasks.

</details>

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Staging Directory 2nd Endpoint</strong></summary>

### 🎯 Objective
To create a final, comprehensive exfiltration bundle containing all stolen data.

### 📌 Finding
A large archive named YearEnd_ReviewPackage_2025.zip was created in an internal reference directory.

### 💡 Why it matters
Represents the total aggregate of the data theft operation.

### 🔧 KQL Query Used
The answer for this was 
C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip

Which I found via looking for FileEvents related to the suspicious user above
```kql
let StartDate = datetime(2025-12-03);
let EndDate = datetime(2025-12-05);
DeviceFileEvents
| where TimeGenerated between (StartDate .. EndDate)
| where DeviceName == "main1-srvr"
| where InitiatingProcessRemoteSessionDeviceName == "YE-FINANCEREVIE"
| sort by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="https://i.imgur.com/HdsSWsW.png" height="80%" width="80%" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on the creation of large files (>50MB) in non-standard directories on servers.

</details>

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Staging Activity Timing</strong></summary>

### 🎯 Objective
To prepare for the final exfiltration step.

### 📌 Finding
The timestamp confirms exactly when the final data package was sealed.

### 💡 Why it matters
Helps correlate the file creation with the subsequent network connection for attribution.

### 🔧 KQL Query Used
Reused the query from Flag 20 to extract the exact TimeGenerated, which was:

2025-12-04T03:15:29.2597235Z

### 🖼️ Screenshot
See above flag. 

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Synchronize time sources (NTP) across the enterprise to ensure accurate forensic timelines.

</details>

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Outbound Connection Remote IP</strong></summary>

### 🎯 Objective
To successfully exfiltrate the final data package to the attacker's infrastructure.

### 📌 Finding
A connection was established to 54.83.21.156 using PowerShell/Curl/Wget to upload the data.

### 💡 Why it matters
The definitive "smoking gun" of the breach; confirms where the data went.

### 🔧 KQL Query Used
```kql
let StartDate = datetime(2025-12-01);
let EndDate = datetime(2025-12-05);
let TargetDevice = "main1-srvr"; // Replace with the second device name
DeviceNetworkEvents
| where TimeGenerated between (StartDate .. EndDate)
| where DeviceName == TargetDevice
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessIntegrityLevel == "High"
// Filter for processes commonly used by attackers to transfer data
| where InitiatingProcessFileName has_any (
    "powershell.exe", "pwsh.exe", 
    "curl.exe", "wget.exe", 
    "ftp.exe", "scp.exe", 
    "nc.exe", "ncat.exe",
    "bitsadmin.exe"
)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine

| sort by TimeGenerated asc

```

### 🖼️ Screenshot
<img src="https://i.imgur.com/dWoFoeq.png" height="80%" width="80%" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Block traffic to unclassified or low-reputation IPs and investigate all connections to public cloud ranges (AWS/Azure) from internal servers.

</details>


---

<!-- Duplicate Flag 1 section for Flags 2–222 -->

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- Unrestricted Lateral Movement via RDP
  - The attacker pivoted seamlessly from a workstation (sys1-dept) to a critical server (main1-srvr) using Remote Desktop Protocol (RDP) with compromised credentials from various departments (Helpdesk, HR, Finance). There appears to be no segmentation preventing a workstation user from accessing a server via RDP.
- Lack of PowerShell Restrictions
  - The attacker executed malicious scripts (PayrollSupportTool.ps1) from a user's Downloads folder using simple bypass flags like -ExecutionPolicy Bypass. This indicates that standard users have the ability to execute arbitrary code.
- Insufficient Egress Filtering
  - The environment allowed direct outbound connections to external IP addresses (e.g., 54.83.21.156) using standard tools like PowerShell and Curl. This allowed the attacker to easily test connectivity and eventually exfiltrate the staged data.
- Undetected Local Persistence
  - The attacker successfully established persistence using standard, well-known techniques: a Registry Run key and a Scheduled Task named BonusReviewAssist. These mechanisms went undetected until the hunt, allowing the attacker to maintain access across reboots.

### Recommendations
- 1. Implement strict network segmentation and "Jump Box" architecture. Workstations should not be able to RDP directly to servers. Enforce "Tiered Administration" where Helpdesk/HR accounts cannot log into high-value servers, and require Multi-Factor Authentication (MFA) for all internal remote access.
- 2. Enforce AppLocker or Windows Defender Application Control (WDAC) to block script execution from user-writable directories (like Downloads or Temp). Additionally, enable PowerShell Constrained Language Mode for standard users to limit the API capabilities available to potential attackers.
- 3. Implement a "Deny All" outbound firewall policy for servers, allowing traffic only to known, business-critical destinations (Allowlisting). Use a web proxy to inspect and categorize all outbound web traffic, blocking connections to uncategorized IPs or known file-sharing sites.
- 4. Configure EDR (Endpoint Detection and Response) tools to alert immediately on the creation of new Scheduled Tasks or modifications to HKCU\...\Run keys. Regularly audit these locations for anomalies.

---

## 🧾 Final Assessment

The organization currently faces a High risk posture due to a "flat" network architecture that permitted an adversary to escalate a single workstation compromise into a significant data breach involving sensitive financial records. The attacker demonstrated moderate sophistication, utilizing standard "living-off-the-land" techniques (PowerShell, RDP, Task Scheduler) rather than custom malware, which suggests that basic hygiene controls were insufficient. While endpoint telemetry (EDR) was successfully capturing evidence, the defensive posture was reactive rather than preventive; the lack of automated blocking for script execution, RDP segmentation, and outbound data transfer allowed the adversary to complete their objective—exfiltrating finalized year-end bonus data—without interruption. Immediate remediation of lateral movement paths and egress controls is required to prevent recurrence.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---





