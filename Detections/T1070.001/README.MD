<details>
<summary>T1070.001-1 Clear Logs :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND (sourcetype=WinEventLog AND EventCode=1102) OR (sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" AND EventCode=1 AND CommandLine="*wevtutil cl*") </pre>
</details>
<details>
<summary>T1070.001-2 Delete System Logs Using Clear-EventLog
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1070.001-3 Clear Event Logs via VBA
</summary>
<pre>$ NA </pre>
</details>
