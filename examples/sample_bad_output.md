# Detection Goal
Detect suspicious process activity on endpoints.

# KQL Query

```kql
BadTableName
| where ParentProcess contains "outlook"
| where ChildProcess contains "powershell"
| project Timestamp, DeviceName, ParentProcess, ChildProcess
```

# Why This Query Works
This query looks for Outlook spawning PowerShell.

# Tuning Ideas
- Add more filters.
