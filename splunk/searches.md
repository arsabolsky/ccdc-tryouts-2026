# Splunk hunting searches

Paste into Splunk Search on redstone (`http://192.168.200+x.12:8000`). Set the time picker to "Last 4 hours" or "Since 10:00".
If a search returns nothing, run `index=* | stats count by index, sourcetype` first. Index names differ between setups.

## Windows (lapis)

| What | Search |
|---|---|
| Failed logons by source | `index=* EventCode=4625 \| stats count by Account_Name, Source_Network_Address \| sort -count` |
| Failed, then successful logon (brute force that worked) | `index=* (EventCode=4625 OR EventCode=4624) \| stats count(eval(EventCode=4625)) as fails count(eval(EventCode=4624)) as ok by Account_Name, Source_Network_Address \| where fails>5 AND ok>0` |
| Account created | `index=* EventCode=4720 \| table _time host SAM_Account_Name Subject_Account_Name` |
| Added to a privileged group | `index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756) \| table _time host Group_Name Member_Name Subject_Account_Name` |
| Password reset by someone else | `index=* EventCode=4724 \| table _time host Target_Account_Name Subject_Account_Name` |
| Scheduled task created | `index=* EventCode=4698 \| table _time host Task_Name Subject_Account_Name` |
| Service installed | `index=* EventCode=7045 \| table _time host Service_Name Service_File_Name` |
| Service stopped (scored service killed?) | `index=* EventCode=7036 "stopped" \| table _time host Message` |
| Security log cleared | `index=* (EventCode=1102 OR EventCode=104) \| table _time host` |
| Process creation with command line | `index=* EventCode=4688 \| table _time host New_Process_Name Process_Command_Line Creator_Process_Name` |
| PowerShell script blocks | `index=* EventCode=4104 \| table _time host ScriptBlockText` |
| Firewall rule changed | `index=* (EventCode=4946 OR EventCode=4947 OR EventCode=4948 OR EventCode=2004 OR EventCode=2006) \| table _time host EventCode Message` |

## Linux (iron, redstone)

| What | Search |
|---|---|
| Failed SSH logins by source | `index=* "Failed password" \| rex "for (invalid user )?(?<user>\S+) from (?<src>\S+)" \| stats count by user, src \| sort -count` |
| Successful SSH logins | `index=* "Accepted password" OR "Accepted publickey" \| rex "for (?<user>\S+) from (?<src>\S+)" \| table _time host user src` |
| sudo commands | `index=* "sudo:" "COMMAND=" \| rex "sudo:\s+(?<user>\S+) :.*COMMAND=(?<cmd>.*)" \| table _time host user cmd` |
| New users or groups | `index=* ("useradd" OR "new user" OR "groupadd" OR "usermod")` |
| Password changes | `index=* ("password changed" OR "chpasswd" OR "passwd\[")` |
| Cron activity | `index=* CRON CMD \| rex "CMD \((?<cmd>.*)\)" \| stats count by host, cmd` |
| Service stops/crashes | `index=* ("Stopped" OR "Failed to start" OR "Main process exited") \| table _time host _raw` |
| Web shells in access logs | `index=* ("cmd=" OR "exec=" OR ".php?c=" OR "/../" OR "union select" OR "/etc/passwd") \| table _time host clientip uri _raw` |

## Correlate one attacker

Once a source IP or account shows up, pivot on it everywhere:

```
index=* "<ip-or-username>" | sort _time | table _time host sourcetype _raw
```

Write down the time, host, account, source IP and action for each hit. Those are the facts an incident report needs.
