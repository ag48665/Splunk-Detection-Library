# SOC Interview Talking Points

## How I Explain This Project
This project is a Splunk detection library and SOC triage portfolio. I built detections for common Windows and Sysmon events, mapped them to MITRE ATT&CK, wrote triage playbooks, and documented false positives and tuning ideas.

## What I Can Demonstrate Live
- Count Windows Event IDs in Splunk
- Investigate failed logons
- Find privileged logons
- Look for PowerShell execution
- Explain Sigma and convert it to SPL
- Write a short SOC incident report

## Key SPL Commands I Used
- search
- stats
- table
- sort
- top
- rare
- eval
- where
- timechart
- rex
- lookup

## Example Interview Answer
If I receive a brute-force alert, I first check the number of failed attempts, affected user, source IP, time range, and whether a successful login occurred afterward. Then I pivot into process activity and privileged events, check false positives such as scanners or helpdesk activity, and escalate if the behavior is suspicious.
