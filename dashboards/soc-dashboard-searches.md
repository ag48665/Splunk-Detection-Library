# SOC Dashboard Searches

## Events by EventCode
```spl
index=main
| stats count by EventCode
| sort - count
```

## Authentication Trend
```spl
index=main (EventCode=4624 OR EventCode=4625)
| timechart count by EventCode
```

## Top Users With Failed Logons
```spl
index=main EventCode=4625
| top limit=10 TargetUserName
```

## Privileged Activity
```spl
index=main EventCode=4672
| stats count by TargetUserName, host
| sort - count
```

## Suspicious Process Activity
```spl
index=main EventCode=4688
| search NewProcessName="*powershell*" OR NewProcessName="*cmd.exe*"
| table _time host SubjectUserName NewProcessName Process_Command_Line
```
