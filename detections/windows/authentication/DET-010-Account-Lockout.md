# DET 010 Account Lockout

## Objective
Detect locked user accounts.

## Severity
**MEDIUM**

## Data Source
EventCode=4740

## MITRE ATT&CK Mapping
T1110 - Brute Force

## Splunk SPL
```spl
index=main EventCode=4740
| stats count values(TargetUserName) as locked_users values(CallerComputerName) as caller_hosts by host
| sort - count
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
This detection helps identify detect locked user accounts. In a SOC workflow, I would validate the source, affected user, timing, and nearby events before escalating.
