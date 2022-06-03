<details>
<summary>T1003.002-1 Registry dump of SAM, creds, and secrets :white_check_mark:
</summary>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=reg.exe OR Processes.process_name=cmd.exe) Processes.process=*save* (Processes.process=*HKEY_LOCAL_MACHINE\\Security* OR Processes.process=*HKEY_LOCAL_MACHINE\\SAM* OR Processes.process=*HKEY_LOCAL_MACHINE\\System* OR Processes.process=*HKLM\\Security* OR Processes.process=*HKLM\\System* OR Processes.process=*HKLM\\SAM*) by Processes.user Processes.process_name Processes.process Processes.dest Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` | `attempted_credential_dump_from_registry_via_reg_exe_filter` </pre>
</details>
<details>
<summary>T1003.002-2 Registry parse with pypykatz
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.002-3 esentutl.exe SAM copy :white_check_mark:
</summary>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=*esentutl.exe* AND Processes.process="*/y /vss*/d*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre>
</details>
<details>
<summary>T1003.002-4 PowerDump Hashes and Usernames from Registry
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.002-5 dump volume shadow copy hives with certutil
</summary>
<pre>$ NA </pre>
</details>
<details>
<summary>T1003.002-6 dump volume shadow copy hives with System.IO.File
</summary>
<pre>$ NA </pre>
</details>
