# Project Notes — KQL Detection Assistant

## Purpose
This tool provides structural and quality validation for AI-generated KQL detection packages before they reach an analyst's review queue. It is not a substitute for human review or production testing.

## Design Decisions

### Why no backend?
The v1 goal is a frictionless tool any SOC analyst can open in a browser without setup, accounts, or API keys. A static HTML/CSS/JS file achieves that with zero infrastructure.

### Why no AI API calls in v1?
AI validation adds latency, cost, and complexity. The highest-value checks (missing sections, bad table names, invalid fields, no time filter) are deterministic and can be done with string matching. AI enrichment is a v2 concern.

### Why Markdown input format?
Detection packages produced by AI models (ChatGPT, Claude, Copilot) are typically returned as Markdown. Accepting Markdown directly means zero copy-paste friction for the analyst.

## Known Limitations

- Field validation is basic — it only checks for known-bad fields, not exhaustive schema compliance.
- KQL syntax is not parsed — only structure and keyword presence are checked.
- The tool cannot tell whether a query will actually return results in your environment.
- Only two tables are in scope for v1 (DeviceProcessEvents, DeviceFileEvents).

## Planned Improvements (v2+)
- Add more known tables and field schemas.
- Add KQL syntax linting via a lightweight parser.
- Add AI-assisted logic review (Claude API).
- Add export to PDF or JSON for documentation workflows.
- Add detection package templates for common attack techniques.

## Table and Field Reference

### DeviceProcessEvents
Valid fields: Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, SHA256, InitiatingProcessSHA256

Known invalid fields: ParentProcess, ChildProcess, ParentProcessName, ChildProcessName

### DeviceFileEvents
Valid fields: Timestamp, DeviceName, AccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256

## Validation Logic Summary

| Check | Type | Severity |
|---|---|---|
| Required section present | Structural | Error |
| KQL code block present | Structural | Error |
| Known table name in query | Schema | Error |
| ago() time filter present | Quality | Warning |
| project clause present | Quality | Warning |
| False positives section has content | Quality | Warning |
| What This Query Cannot Prove has content | Quality | Warning |
| Human Review Checklist present | Review | Warning |
| Invalid field used for detected table | Schema | Warning |
