# DET 011 Sysmon Process Creation

## Objective
Detect process creation from Sysmon Event ID 1.

## Severity
**MEDIUM**

## Data Source
Sysmon EventID=1

## MITRE ATT&CK Mapping
T1059 - Command and Scripting Interpreter

## Splunk SPL
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=1
| table _time host Image ParentImage CommandLine User
| sort - _time
```

## Triage Steps
1. Identify the user, host, source IP, and timestamp.
2. Check whether the activity is expected for this user or host.
3. Pivot to surrounding events within ±30 minutes.
4. Review successful logons, privilege changes, and process execution around the same time.
5. Check whether the account is privileged or service-related.
6. Decide verdict: benign, suspicious, or malicious.

## False Positives
- Admin activity
- Scheduled tasks
- Vulnerability scanners
- Helpdesk troubleshooting
- Service accounts

## Tuning Ideas
- Add known admin/service accounts to lookup allowlists.
- Add thresholds by host criticality.
- Add business-hours checks.
- Correlate with asset and identity context.

## Analyst Interview Explanation
This detection helps identify detect process creation from sysmon event id 1. In a SOC workflow, I would validate the source, affected user, timing, and nearby events before escalating.
