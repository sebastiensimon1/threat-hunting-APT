
 ![image](https://github.com/user-attachments/assets/be43729d-5124-47c3-9d42-2c2f67e4171a)


# Threat Hunt Report: The Great Admin Heist 
- Scenario Creation: Custom Red Team Simulation

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

At Acme Corp, the eccentric yet brilliant IT admin, Bubba Rockerfeatherman III, isn’t just patching servers and resetting passwords — he’s the secret guardian of trillions in digital assets. Hidden deep within encrypted vaults lie private keys, sensitive data, and intellectual gold... all protected by his privileged account.

But the shadows have stirred.
A covert APT group known only as The Phantom Hackers 👤 has set their sights on Bubba. Masters of deception, they weave social engineering, fileless malware, and stealthy persistence into a multi-stage campaign designed to steal it all — without ever being seen.

The breach has already begun.
Using phishing, credential theft, and evasive tactics, the attackers have infiltrated Acme’s network. Bubba doesn’t even know he's compromised.

🧠 Your mission:
Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.

Will you stop the heist in time… or will the Phantom Hackers disappear with the crown jewels of cyberspace?

Known Information:
DeviceName: anthony-001

---

## Flags Solved

### Flag 1: Identify the Fake Antivirus Program Name

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName startswith "A" or FileName startswith "B" or FileName startswith "C"
| summarize count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName, FolderPath, ProcessCommandLine
| order by count_ asc
```
**Suspicious Program Identified:** `BitSentinelCore.exe`

---

### Flag 2: Malicious File Written Somewhere

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FolderPath endswith "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp asc
```
**File Written By:** `csc.exe`

---

### Flag 3: Execution of the Program

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
```
**Executable Launched:** `BitSentinelCore.exe` via `explorer.exe`

---

### Flag 4: Keylogger Artifact Written

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T02:00:00Z) .. datetime(2025-05-07T02:10:00Z))
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Keylogger Artifact Identified:** `systemreport.lnk`

---

### Flag 5: Registry Persistence Entry

**Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T02:00:00Z) .. datetime(2025-05-07T02:10:00Z))
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ReportId
| order by Timestamp asc
```
**Persistence Path:** 
`HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

---

### Flag 6: Daily Scheduled Task Created

**Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine has_any ("schtasks", "Task Scheduler", "/create")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```
**Scheduled Task Created:** `UpdateHealthTelemetry`

---

### Flag 7: Process Spawn Chain

**Process Chain:**
`BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

### Flag 8: Timestamp Correlation

**Earliest Causative Event:**
`2025-05-07T02:00:36.794406Z`

---

## Summary

The fake antivirus `BitSentinelCore.exe` was stealthily dropped by `csc.exe`, executed by the user via `explorer.exe`, and proceeded to initiate registry persistence, keylogger activity, and daily scheduled tasks. Each stage was validated through KQL hunts correlating telemetry in Microsoft Defender. The timeline confirms an orchestrated campaign leveraging native tools for stealth, culminating in a full compromise of Bubba’s endpoint.

---

## Response Taken

Incident artifacts have been documented. The endpoint was isolated and escalation was made to the SOC. Continuous monitoring has been enabled to validate full remediation and hunt for lateral movement.

