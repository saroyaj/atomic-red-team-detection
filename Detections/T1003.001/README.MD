<details>
<summary>T1003.001-1 Dump LSASS.exe Memory using ProcDump :white_check_mark:
</summary>
<b>Splunk</b>
<pre>$ index=win_* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="* -ma *" AND (CommandLine="* lsass*" OR CommandLine="* ls*") | table host, User, Image, CommandLine </pre>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="* -ma *" AND (Processes.process="* lsass*" OR Processes.process="* ls*")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre>
</details>
<details>
<summary>T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND (CommandLine="*comsvcs.dll*" OR CommandLine="*rundll32*" OR CommandLine="*.dmp*") AND CommandLine="* full*" | table host, User, Image, CommandLine </pre>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  ((Processes.process="*comsvcs.dll*" OR Processes.process="*rundll32*" OR Processes.process="*.dmp*") AND Processes.process="* full*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)`</pre>
</details>
<details>
<summary>T1003.001-3 Dump LSASS.exe Memory using direct system calls and API unhooking
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-4 Dump LSASS.exe Memory using NanoDump
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-6 Offline Credential Theft With Mimikatz :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 AND (CommandLine="*sekurlsa::minidump*" OR CommandLine="*sekurlsa::logonpasswords*") | table host, User, Image, CommandLine </pre>
</details>
<details>
<summary>T1003.001-7 LSASS read with pypykatz :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*lsass.exe" AND (CallTrace="*ntdll.dll*" AND CallTrace="*KERNELBASE.dll*" AND CallTrace="*libffi-*.dll*" AND CallTrace="*_ctypes.pyd*" AND CallTrace="*python3*.dll*") GrantedAccess=0x1fffff </pre>
</details>
<details>
<summary>T1003.001-8 Dump LSASS.exe Memory using Out-Minidump.ps1
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-9 Create Mini Dump of LSASS.exe using ProcDump
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-10 Powershell Mimikatz :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage=*powershell*.exe AND (CommandLine="*sekurlsa::minidump*" OR CommandLine="*sekurlsa::logonpasswords*") | table host, User, Image, CommandLine </pre>
</details>
<details>
<summary>T1003.001-11 Dump LSASS with .Net 5 createdump.exe
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-12 Dump LSASS.exe using imported Microsoft DLLs
</summary>
<pre>$ NA </pre>
</details>
