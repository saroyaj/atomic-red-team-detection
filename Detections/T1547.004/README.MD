<details>
<summary>T1547.004-1 Winlogon Shell Key Persistence - PowerShell
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1547.004-2 Winlogon Userinit Key Persistence - PowerShell
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1547.004-3 Winlogon Notify Key Logon Persistence - PowerShell :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" AND EventCode=12 TargetObject="*CurrentVersion\\Winlogon\\Notify*" </pre>
</details>
