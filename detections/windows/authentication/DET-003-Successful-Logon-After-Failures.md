# DET 003 Successful Logon After Failures

## Objective
Detect successful authentication shortly after repeated failures.

## Severity
**CRITICAL**

## Data Source
EventCode=4624 and EventCode=4625

## MITRE ATT&CK Mapping
T1110 - Brute Force

## Splunk SPL
```spl
index=main (EventCode=4625 OR EventCode=4624)
| eval action=if(EventCode=4625,"failure","success")
| stats count(eval(action="failure")) as failures count(eval(action="success")) as successes min(_time) as first_seen max(_time) as last_seen by TargetUserName, src_ip, host
| where failures >= 5 AND successes >= 1
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - failures
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
This detection helps identify detect successful authentication shortly after repeated failures. In a SOC workflow, I would validate the source, affected user, timing, and nearby events before escalating.
