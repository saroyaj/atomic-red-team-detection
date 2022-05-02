<details>
<summary>T1218.002-1 Control Panel Items :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" EventCode=1 AND (((CommandLine="*.cpl" AND  NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*"))) AND  NOT (CommandLine="*regsvr32 *" AND CommandLine="* /s *" AND CommandLine="*igfxCPL.cpl*")) OR (Image="*\\reg.exe" AND CommandLine="*add*" AND (CommandLine="*CurrentVersion\\Control Panel\\CPLs*"))) 

title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: test
description: Detects the malicious use of a control panel item
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
references:
  - https://attack.mitre.org/techniques/T1196/
  - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
  - https://github.com/SigmaHQ/sigma/blob/dd7576e4b34058061769941b51ff3e8f3e19d68b/rules/windows/process_creation/proc_creation_win_control_panel_item.yml
date: 2020/06/22
modified: 2022/03/31
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    CommandLine|endswith: '.cpl'
  filter:
    CommandLine|contains:
      - '\System32\'
      - '%System%'
  fp1_igfx:
    CommandLine|contains|all:
      - 'regsvr32 '
      - ' /s '
      - 'igfxCPL.cpl'
  selection2:
    Image|endswith: '\reg.exe'
    CommandLine|contains: 'add'
  selection3:
    CommandLine|contains:
      - 'CurrentVersion\\Control Panel\\CPLs'
  condition: (selection1 and not filter and not fp1_igfx) or (selection2 and selection3)
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.002
  - attack.persistence
  - attack.t1546
</pre>
</details>
