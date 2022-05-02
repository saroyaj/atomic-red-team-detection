<details>
<summary>T1218.002-1 Control Panel Items :white_check_mark:
</summary>
  <b>Splunk</b> 
<pre>├── index=win_* sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" EventCode=1 AND (((CommandLine="*.cpl" AND  NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*"))) AND  NOT (CommandLine="*regsvr32 *" AND CommandLine="* /s *" AND CommandLine="*igfxCPL.cpl*")) OR (Image="*\\reg.exe" AND CommandLine="*add*" AND (CommandLine="*CurrentVersion\\Control Panel\\CPLs*"))) 
     ├── <a https://github.com/SigmaHQ/sigma/blob/dd7576e4b34058061769941b51ff3e8f3e19d68b/rules/windows/process_creation/proc_creation_win_control_panel_item.yml">Sigma</a>  
</pre>
</details>
