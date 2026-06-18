# DET 001 Brute Force Failed Logons

## Objective
Detect multiple failed logons from the same source or user.

## Severity
**HIGH**

## Data Source
EventCode=4625

## MITRE ATT&CK Mapping
T1110 - Brute Force

## Splunk SPL
```spl
index=main EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen values(FailureReason) as failure_reasons values(LogonType) as logon_types by TargetUserName, src_ip, host
| where count >= 5
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
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
This detection helps identify detect multiple failed logons from the same source or user. In a SOC workflow, I would validate the source, affected user, timing, and nearby events before escalating.
