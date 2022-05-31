<details>
<summary>T1078.001-1 Enable Guest account with RDP capability and admin privileges :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" AND (EventCode=1 AND (CommandLine="*net user*" OR CommandLine="*net localgroup * add*")) OR (EventCode=13 AND (TargetObject="*Terminal Server\\fDenyTSConnections" OR TargetObject="*Terminal Server\\AllowTSConnections")) </pre>
  <pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*net user*" OR Processes.process="*net localgroup * add*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre>

<pre>| tstats `security_content_summariesonly` count values(Registry.registry_key_name) as registry_key_name values(Registry.registry_path) as registry_path min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where (Registry.registry_path="*Terminal Server\\fDenyTSConnections" OR Registry.registry_path="*Terminal Server\\AllowTSConnections") by Registry.dest Registry.user | `security_content_ctime(lastTime)` | `security_content_ctime(firstTime)` | `drop_dm_object_name(Registry)` | `registry_keys_used_for_persistence_filter` </pre>
</details>
<details>
<summary>T1078.001-2 Activate Guest Account :white_check_mark:
</summary>
  <b>Splunk</b>
<pre>$ index=win_* AND sourcetype="XmlWinEventLog:microsoft-windows-sysmon/Operational" AND EventCode=1 AND CommandLine="*net  user* /active:yes" </pre>
<pre>| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process_name=net.exe AND Processes.process="*net  user* /active:yes*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` </pre>
</details>
