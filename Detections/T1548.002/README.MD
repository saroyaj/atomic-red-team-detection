<details>
<summary>T1548.002-1 Bypass UAC using Event Viewer (cmd)
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-2 Bypass UAC using Event Viewer (PowerShell)
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-3 Bypass UAC using Fodhelper
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-4 Bypass UAC using Fodhelper - PowerShell
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-5 Bypass UAC using ComputerDefaults (PowerShell)
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-6 Bypass UAC by Mocking Trusted Directories
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-7 Bypass UAC using sdclt DelegateExecute
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-8 Disable UAC using reg.exe
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-9 Bypass UAC using SilentCleanup task :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND (EventID=13 OR EventType=SetValue) AND (TargetObject="*\\Environment\\windir" AND Details="*REM*") | table host, User, Image, TargetObject, registry_value_name, registry_value_data </pre>
</details>
<details>
<summary>T1548.002-10 UACME Bypass Method 23
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-11 UACME Bypass Method 31
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-12 UACME Bypass Method 33
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-13 UACME Bypass Method 34
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-14 UACME Bypass Method 39
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-15 UACME Bypass Method 56
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-16 UACME Bypass Method 59
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1548.002-17 UACME Bypass Method 61
</summary>
<pre>$ NA </pre>
</details>
