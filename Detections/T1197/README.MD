<details>
<summary>T1197-1 Bitsadmin Download (cmd) :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*bitsadmin.exe" AND (CommandLine="*transfer*" OR CommandLine="*download*") </pre>
</details>
<details>
<summary>T1197-2 Bitsadmin Download (PowerShell) :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe" CommandLine="*Start-BitsTransfer*" </pre>
</details>
<details>
<summary>T1197-3 Persist, Download, & Execute :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*bitsadmin.exe" AND (CommandLine="*create*" OR CommandLine="*addfile*" OR CommandLine="*setnotifycmdline*" OR CommandLine="*resume*" OR CommandLine="*complete*") </pre>
</details>
<details>
<summary>T1197-4 Bits download using desktopimgdownldr.exe (cmd)
</summary>
<pre>$ NA </pre>
</details>
