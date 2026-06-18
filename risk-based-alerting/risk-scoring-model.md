# Risk-Based Alerting Model

This section shows how detections can contribute to a risk score instead of generating isolated alerts.

## Example Risk Logic

| Detection | Risk Object | Risk Score |
|---|---|---:|
| Failed logons | user, src_ip | 20 |
| Password spraying | src_ip | 40 |
| Success after failures | user, src_ip | 70 |
| Privileged logon | user | 30 |
| Encoded PowerShell | host, user | 80 |
| Admin group modification | user | 90 |

## SPL Example

```spl
index=main (EventCode=4625 OR EventCode=4672 OR EventCode=4728 OR EventCode=4688)
| eval risk_score=case(EventCode=4625,20, EventCode=4672,30, EventCode=4728,90, match(Process_Command_Line,"(?i)encodedcommand|-enc"),80, true(),10)
| eval risk_object=coalesce(TargetUserName,SubjectUserName,host)
| stats sum(risk_score) as total_risk values(EventCode) as events by risk_object, host
| where total_risk >= 70
| sort - total_risk
```
