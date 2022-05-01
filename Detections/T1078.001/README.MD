<details>
<summary>T1078.001-1 Enable Guest account with RDP capability and admin privileges :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" AND (EventCode=1 AND (CommandLine="*net user*" OR CommandLine="*net localgroup * add*")) OR (EventCode=13 AND (TargetObject="*Terminal Server\\fDenyTSConnections" OR TargetObject="*Terminal Server\\AllowTSConnections")) </pre>
</details>
<details>
<summary>T1078.001-2 Activate Guest Account
</summary>
<pre>$ NA </pre>
</details>
