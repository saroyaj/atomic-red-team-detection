<details>
<summary>T1218.002-1 Control Panel Items :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" EventCode=1 AND (((CommandLine="*.cpl" AND  NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*"))) AND  NOT (CommandLine="*regsvr32 *" AND CommandLine="* /s *" AND CommandLine="*igfxCPL.cpl*")) OR (Image="*\\reg.exe" AND CommandLine="*add*" AND (CommandLine="*CurrentVersion\\Control Panel\\CPLs*"))) </pre>
</details>
