<details>
<summary>T1197-1 Bitsadmin Download (cmd) :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" Image="*bitsadmin.exe" AND (CommandLine="*transfer*" OR CommandLine="*download*") </pre>
</details>
<details>
<summary>T1197-2 Bitsadmin Download (PowerShell)
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1197-3 Persist, Download, & Execute
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1197-4 Bits download using desktopimgdownldr.exe (cmd)
</summary>
<pre>$ NA </pre>
</details>
