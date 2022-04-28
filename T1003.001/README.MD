<details>
<summary>T1003.001-1 Dump LSASS.exe Memory using ProcDump :white_check_mark:
</summary>
<b>Splunk</b>
<pre>$ index=win_* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="* -ma *" AND (CommandLine="* lsass*" OR CommandLine="* ls*") | table host, User, Image, CommandLine </pre>
</details>
<details>
<summary>T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll :white_check_mark:
</summary>
<pre>$ index=win_* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND (CommandLine="*comsvcs.dll*" OR CommandLine="*rundll32*" OR CommandLine="*.dmp*") AND CommandLine="* full*" | table host, User, Image, CommandLine </pre>
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
<summary>T1003.001-6 Offline Credential Theft With Mimikatz
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.001-7 LSASS read with pypykatz
</summary>
<pre>$ NA </pre>
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
<summary>T1003.001-10 Powershell Mimikatz
</summary>
<pre>$ NA </pre>
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
