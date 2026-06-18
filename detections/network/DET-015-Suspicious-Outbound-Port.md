# DET 015 Suspicious Outbound Port

## Objective
Detect outbound connections to uncommon ports.

## Severity
**MEDIUM**

## Data Source
firewall/proxy/sysmon

## MITRE ATT&CK Mapping
T1041 - Exfiltration Over C2 Channel

## Splunk SPL
```spl
index=* (DestinationPort=* OR dest_port=*)
| eval dest_port=coalesce(DestinationPort,dest_port)
| where NOT dest_port IN (53,80,443,123,22,3389)
| stats count values(Image) as processes by src_ip, dest_ip, dest_port, host
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
This detection helps identify detect outbound connections to uncommon ports. In a SOC workflow, I would validate the source, affected user, timing, and nearby events before escalating.
