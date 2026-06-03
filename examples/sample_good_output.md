# Detection Goal
Detect suspicious PowerShell processes launched by Microsoft Outlook, which may indicate a phishing-based initial access or macro execution attempt.

# Required Data Source
Microsoft Defender for Endpoint (MDE) — endpoint telemetry with process creation events enabled.

# Required Table
DeviceProcessEvents

# Required Fields
- Timestamp
- DeviceName
- AccountName
- InitiatingProcessFileName
- FileName
- ProcessCommandLine
- InitiatingProcessCommandLine
- FolderPath

# KQL Query

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "OUTLOOK.EXE"
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath
```

# Why This Query Works
Outlook directly spawning PowerShell is uncommon in many environments and should be reviewed, especially when paired with suspicious command-line activity or related email evidence. When a malicious macro or embedded link is clicked, Outlook may spawn PowerShell to download or execute a payload. This query surfaces that parent-child relationship using MDE telemetry.

# False Positives
- IT automation scripts that use Outlook COM objects on managed devices.
- Legacy automated reporting tools that invoke PowerShell via Outlook rules.
- Known developer workstations running test macros.

# Tuning Ideas
- Narrow to specific departments or device groups using DeviceName filters.
- Add SHA256 allowlisting for known-good PowerShell scripts.
- Combine with network connection events to confirm outbound C2 attempts.

# What This Query Cannot Prove
- This query cannot confirm that the PowerShell process was malicious. It only shows that Outlook spawned PowerShell.
- It cannot determine whether data exfiltration occurred.
- It cannot confirm the payload executed successfully.
- It does not rule out legitimate administrative use.

# MITRE ATT&CK Mapping
- T1059.001 — Command and Scripting Interpreter: PowerShell (confirmed by query)
- T1566 — Phishing (only if supporting email evidence exists; not confirmed by this query alone)
- T1204.002 — User Execution: Malicious File (only if user execution evidence exists; not confirmed by this query alone)

# Confidence Level
Medium — the parent-child relationship is suspicious but not conclusive without additional context.

# Human Review Checklist
- [ ] Confirm Outlook is the direct parent (not a child of explorer.exe first).
- [ ] Review the full ProcessCommandLine for download cradles or encoded commands.
- [ ] Check whether the affected device is a known developer or IT workstation.
- [ ] Correlate with email logs to identify the potential phishing message.
- [ ] Check for subsequent network connections from the PowerShell process.
- [ ] Verify whether the SHA256 of the spawned process matches known-bad hashes.
