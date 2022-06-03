<details>
<summary>T1003.004-1 Dumping LSA Secrets :white_check_mark:
</summary>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=*PsExec*.exe AND (Processes.process="*reg*save*HKLM\\security\\policy\\secrets*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre>
</details>
