# Case 003 Success After Failures

## Scenario
Successful login occurs after repeated failures.

## Alert Source
Splunk detection: `DET-003`

## MITRE ATT&CK
T1110 Brute Force

## Initial Questions
- Which user triggered the alert?
- Which host was involved?
- What was the source IP?
- Did the activity happen during normal hours?
- Was there a successful login after failures?
- Is the account privileged?

## Investigation SPL
```spl
index=main
| stats count by EventCode, TargetUserName, host
| sort - count
```

## Timeline Query
```spl
index=main TargetUserName="<USER>" earliest=-2h latest=now
| table _time EventCode host TargetUserName SubjectUserName src_ip NewProcessName Process_Command_Line
| sort _time
```

## Evidence To Collect
- Screenshot of alert output
- User and host details
- Event IDs involved
- Timeline of activity
- Any suspicious process execution
- Any privilege escalation event

## Analyst Notes
Fill this section with your real Splunk findings.

## Verdict
Choose one: Benign / Suspicious / Malicious

## Recommended Response
- If benign: document reason and close.
- If suspicious: escalate to L2 and request endpoint/user validation.
- If malicious: disable account, isolate host, preserve evidence, escalate incident.
