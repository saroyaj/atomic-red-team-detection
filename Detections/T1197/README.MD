<details>
<summary>T1197-1 Bitsadmin Download (cmd) :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*bitsadmin.exe" AND (CommandLine="*transfer*" OR CommandLine="*download*") </pre>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=*bitsadmin*.exe AND (Processes.process="*transfer*" OR Processes.process="*download*") ) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre> 
</details>
<details>
<summary>T1197-2 Bitsadmin Download (PowerShell) :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe" CommandLine="*Start-BitsTransfer*" </pre>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=*powershell*.exe AND Processes.process="*Start-BitsTransfer*" ) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)`  </pre>
</details>
<details>
<summary>T1197-3 Persist, Download, & Execute :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*bitsadmin.exe" AND (CommandLine="*create*" OR CommandLine="*addfile*" OR CommandLine="*setnotifycmdline*" OR CommandLine="*resume*" OR CommandLine="*complete*") </pre>
</details>
<details>
  <b>Splunk</b>
<summary>T1197-4 Bits download using desktopimgdownldr.exe (cmd) :white_check_mark:
</summary>
<pre>$ index=win_* EventChannel="Microsoft-Windows-Sysmon/Operational" EventID=1 CommandLine="*desktopimgdownldr*" </pre>
</details>
