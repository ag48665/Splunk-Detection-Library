# Splunk Detection Library + SOC Alert Triage Cases

Advanced SOC Analyst portfolio project focused on **Splunk**, **Windows Security Logs**, **Sysmon**, **Sigma rules**, **MITRE ATT&CK**, and realistic alert triage.

This repository is designed to show practical SOC L1/L2 skills:

- Building detections in Splunk SPL
- Mapping alerts to MITRE ATT&CK
- Writing Sigma rules and Splunk equivalents
- Creating SOC triage playbooks
- Explaining false positives and tuning logic
- Documenting analyst verdicts like a real SOC ticket
- Using risk scoring and investigation workflows

## Repository Structure

```text
Splunk-Detection-Library-Enterprise/
├── detections/              # Production-style SPL detections
├── sigma/                   # Sigma versions of detections
├── triage-cases/            # SOC alert investigation case files
├── risk-based-alerting/     # Risk scoring examples
├── splunk-savedsearches/    # savedsearches.conf examples
├── dashboards/              # Dashboard searches and panels
├── lookups/                 # Example lookup files
├── tests/                   # Test plan for validating detections
├── reports/                 # Analyst-style reports
├── docs/                    # SOC workflow and interview notes
└── templates/               # Reusable templates
```

## Core Detection Areas

| Area | Examples |
|---|---|
| Authentication | brute force, password spraying, success after failures |
| Privilege | privileged logon, admin group modification |
| Process Execution | PowerShell, CMD, LOLBins |
| Persistence | new local user, scheduled task indicators |
| Defense Evasion | encoded PowerShell, suspicious script execution |
| Sysmon | process creation, network connection, DNS query |
| Network | suspicious outbound connections, rare destinations |

## How to Use

1. Upload Windows Security Logs and/or Sysmon logs into Splunk.
2. Start with `index=main` and adjust indexes/sourcetypes to your lab.
3. Run each detection search.
4. Add screenshots to `screenshots/`.
5. Complete triage cases with real findings from your data.

## Example Detection Quality Standard

Each detection includes:

- Objective
- Data source
- SPL query
- MITRE ATT&CK mapping
- Severity
- Triage steps
- False positives
- Tuning ideas
- Analyst interview explanation
- Portfolio notes

## Key Skills Demonstrated

- Splunk SPL
- Windows Security Event IDs
- Sysmon event analysis
- Alert triage
- Detection engineering
- MITRE ATT&CK mapping
- Sigma-to-Splunk conversion
- SOC documentation
- False-positive reduction
