Follina — a Microsoft Office code execution vulnerability	<br />
T1003-2 Credential Dumping with NPPSpy	<br />
T1003-3 Dump svchost.exe to gather RDP credentials	<br />
T1003.001-1 Dump LSASS.exe Memory using ProcDump	<br />
T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll	<br />
T1003.001-3 Dump LSASS.exe Memory using direct system calls and API unhooking	<br />
T1003.001-4 Dump LSASS.exe Memory using NanoDump	<br />
T1003.001-6 Offline Credential Theft With Mimikatz	<br />
T1003.001-7 LSASS read with pypykatz	<br />
T1003.001-8 Dump LSASS.exe Memory using Out-Minidump.ps1	<br />
T1003.001-9 Create Mini Dump of LSASS.exe using ProcDump	<br />
T1003.001-10 Powershell Mimikatz	<br />
T1003.001-11 Dump LSASS with .Net 5 createdump.exe	<br />
T1003.001-12 Dump LSASS.exe using imported Microsoft DLLs	<br />
T1003.002-1 Registry dump of SAM, creds, and secrets	<br />
T1003.002-2 Registry parse with pypykatz	<br />
T1003.002-3 esentutl.exe SAM copy	<br />
T1003.002-4 PowerDump Hashes and Usernames from Registry	<br />
T1003.002-5 dump volume shadow copy hives with certutil	<br />
T1003.002-6 dump volume shadow copy hives with System.IO.File	<br />
T1003.003-1 Create Volume Shadow Copy with vssadmin	<br />
T1003.003-2 Copy NTDS.dit from Volume Shadow Copy	<br />
T1003.003-3 Dump Active Directory Database with NTDSUtil	<br />
T1003.003-4 Create Volume Shadow Copy with WMI	<br />
T1003.003-5 Create Volume Shadow Copy remotely with WMI	<br />
T1003.003-6 Create Volume Shadow Copy remotely (WMI) with esentutl	<br />
T1003.003-7 Create Volume Shadow Copy with Powershell	<br />
T1003.003-8 Create Symlink to Volume Shadow Copy	<br />
T1003.004-1 Dumping LSA Secrets	<br />
T1003.005-1 Cached Credential Dump via Cmdkey	<br />
T1003.006-1 DCSync (Active Directory)	<br />
T1003.006-2 Run DSInternals Get-ADReplAccount	<br />
T1006-1 Read volume boot sector via DOS device path (PowerShell)	<br />
T1007-1 System Service Discovery	<br />
T1007-2 System Service Discovery - net.exe	<br />
T1010-1 List Process Main Windows - C# .NET	<br />
T1012-1 Query Registry	<br />
T1016-1 System Network Configuration Discovery on Windows	<br />
T1016-2 List Windows Firewall Rules	<br />
T1016-4 System Network Configuration Discovery (TrickBot Style)	<br />
T1016-5 List Open Egress Ports	<br />
T1016-6 Adfind - Enumerate Active Directory Subnet Objects	<br />
T1016-7 Qakbot Recon	<br />
T1018-1 Remote System Discovery - net	<br />
T1018-2 Remote System Discovery - net group Domain Computers	<br />
T1018-3 Remote System Discovery - nltest	<br />
T1018-4 Remote System Discovery - ping sweep	<br />
T1018-5 Remote System Discovery - arp	<br />
T1018-8 Remote System Discovery - nslookup	<br />
T1018-9 Remote System Discovery - adidnsdump	<br />
T1018-10 Adfind - Enumerate Active Directory Computer Objects	<br />
T1018-11 Adfind - Enumerate Active Directory Domain Controller Objects	<br />
T1018-15 Enumerate domain computers within Active Directory using DirectorySearcher	<br />
T1018-16 Enumerate Active Directory Computers with Get-AdComputer	<br />
T1018-17 Enumerate Active Directory Computers with ADSISearcher	<br />
T1018-18 Get-DomainController with PowerView	<br />
T1018-19 Get-wmiobject to Enumerate Domain Controllers	<br />
T1020-1 IcedID Botnet HTTP PUT	<br />
T1021.001-1 RDP to DomainController	<br />
T1021.001-2 RDP to Server	<br />
T1021.001-3 Changing RDP Port to Non Standard Port via Powershell	<br />
T1021.001-4 Changing RDP Port to Non Standard Port via Command_Prompt	<br />
T1021.002-1 Map admin share	<br />
T1021.002-2 Map Admin Share PowerShell	<br />
T1021.002-3 Copy and Execute File with PsExec	<br />
T1021.002-4 Execute command writing output to local Admin Share	<br />
T1021.003-1 PowerShell Lateral Movement using MMC20	<br />
T1021.006-1 Enable Windows Remote Management	<br />
T1021.006-2 Invoke-Command	<br />
T1021.006-3 WinRM Access with Evil-WinRM	<br />
T1027-2 Execute base64-encoded PowerShell	<br />
T1027-3 Execute base64-encoded PowerShell from Windows Registry	<br />
T1027-4 Execution from Compressed File	<br />
T1027-5 DLP Evasion via Sensitive Data in VBA Macro over email	<br />
T1027-6 DLP Evasion via Sensitive Data in VBA Macro over HTTP	<br />
T1027-7 Obfuscated Command in PowerShell	<br />
T1027.004-1 Compile After Delivery using csc.exe	<br />
T1027.004-2 Dynamic C# Compile	<br />
T1033-1 System Owner/User Discovery	<br />
T1033-3 Find computers where user has session - Stealth mode (PowerView)	<br />
T1033-4 User Discovery With Env Vars PowerShell Script	<br />
T1033-5 GetCurrent User with PowerShell Script	<br />
T1036-1 System File Copied to Unusual Location	<br />
T1036-2 Malware Masquerading and Execution from Zip File	<br />
T1036.003-1 Masquerading as Windows LSASS process	<br />
T1036.003-3 Masquerading - cscript.exe running as notepad.exe	<br />
T1036.003-4 Masquerading - wscript.exe running as svchost.exe	<br />
T1036.003-5 Masquerading - powershell.exe running as taskhostw.exe	<br />
T1036.003-6 Masquerading - non-windows exe running as windows exe	<br />
T1036.003-7 Masquerading - windows exe running as different windows exe	<br />
T1036.003-8 Malicious process Masquerading as LSM.exe	<br />
T1036.003-9 File Extension Masquerading	<br />
T1036.004-1 Creating W32Time similar named service using schtasks	<br />
T1036.004-2 Creating W32Time similar named service using sc	<br />
T1036.005-2 Masquerade as a built-in system executable	<br />
T1037.001-1 Logon Scripts	<br />
T1039-1 Copy a sensitive File over Administive share with copy	<br />
T1039-2 Copy a sensitive File over Administive share with Powershell	<br />
T1040-3 Packet Capture Windows Command Prompt	<br />
T1040-4 Windows Internal Packet Capture	<br />
T1041-1 C2 Data Exfiltration	<br />
T1046-3 Port Scan NMap for Windows	<br />
T1046-4 Port Scan using python	<br />
T1047-1 WMI Reconnaissance Users	<br />
T1047-2 WMI Reconnaissance Processes	<br />
T1047-3 WMI Reconnaissance Software	<br />
T1047-4 WMI Reconnaissance List Remote Services	<br />
T1047-5 WMI Execute Local Process	<br />
T1047-6 WMI Execute Remote Process	<br />
T1047-7 Create a Process using WMI Query and an Encoded Command	<br />
T1047-8 Create a Process using obfuscated Win32_Process	<br />
T1047-9 WMI Execute rundll32	<br />
T1047-10 Application uninstall using WMIC	<br />
T1048-3 DNSExfiltration (doh)	<br />
T1048.002-1 Exfiltrate data HTTPS using curl windows	<br />
T1048.003-2 Exfiltration Over Alternative Protocol - ICMP	<br />
T1048.003-4 Exfiltration Over Alternative Protocol - HTTP	<br />
T1048.003-5 Exfiltration Over Alternative Protocol - SMTP	<br />
T1049-1 System Network Connections Discovery	<br />
T1049-2 System Network Connections Discovery with PowerShell	<br />
T1049-4 System Discovery using SharpView	<br />
T1053.002-1 At.exe Scheduled task	<br />
T1053.005-1 Scheduled Task Startup Script	<br />
T1053.005-2 Scheduled task Local	<br />
T1053.005-3 Scheduled task Remote	<br />
T1053.005-4 Powershell Cmdlet Scheduled Task	<br />
T1053.005-5 Task Scheduler via VBA	<br />
T1053.005-6 WMI Invoke-CimMethod Scheduled Task	<br />
T1053.005-7 Scheduled Task Executing Base64 Encoded Commands From Registry	<br />
T1055-1 Shellcode execution via VBA	<br />
T1055-2 Remote Process Injection in LSASS via mimikatz	<br />
T1055.001-1 Process Injection via mavinject.exe	<br />
T1055.004-1 Process Injection via C#	<br />
T1055.012-1 Process Hollowing using PowerShell	<br />
T1055.012-2 RunPE via VBA	<br />
T1056.001-1 Input Capture	<br />
T1056.002-2 PowerShell - Prompt User for Password	<br />
T1056.004-1 Hook PowerShell TLS Encrypt/Decrypt Messages	<br />
T1057-2 Process Discovery - tasklist	<br />
T1057-3 Process Discovery - Get-Process	<br />
T1057-4 Process Discovery - get-wmiObject	<br />
T1057-5 Process Discovery - wmic process	<br />
T1059.001-1 Mimikatz	<br />
T1059.001-2 Run BloodHound from local disk	<br />
T1059.001-3 Run Bloodhound from Memory using Download Cradle	<br />
T1059.001-4 Obfuscation Tests	<br />
T1059.001-5 Mimikatz - Cradlecraft PsSendKeys	<br />
T1059.001-6 Invoke-AppPathBypass	<br />
T1059.001-7 Powershell MsXml COM object - with prompt	<br />
T1059.001-8 Powershell XML requests	<br />
T1059.001-9 Powershell invoke mshta.exe download	<br />
T1059.001-11 PowerShell Fileless Script Execution	<br />
T1059.001-12 PowerShell Downgrade Attack	<br />
T1059.001-13 NTFS Alternate Data Stream Access	<br />
T1059.001-14 PowerShell Session Creation and Use	<br />
T1059.001-15 ATHPowerShellCommandLineParameter -Command parameter variations	<br />
T1059.001-16 ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments	<br />
T1059.001-17 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations	<br />
T1059.001-18 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments	<br />
T1059.001-19 PowerShell Command Execution	<br />
T1059.001-20 PowerShell Invoke Known Malicious Cmdlets	<br />
T1059.001-21 PowerUp Invoke-AllChecks	<br />
T1059.003-1 Create and Execute Batch Script	<br />
T1059.003-2 Writes text to a file and displays it.	<br />
T1059.003-3 Suspicious Execution via Windows Command Shell	<br />
T1059.003-4 Simulate BlackByte Ransomware Print Bombing	<br />
T1059.005-1 Visual Basic script execution to gather local computer information	<br />
T1059.005-2 Encoded VBS code execution	<br />
T1059.005-3 Extract Memory via VBA	<br />
T1069.001-2 Basic Permission Groups Discovery Windows (Local)	<br />
T1069.001-3 Permission Groups Discovery PowerShell (Local)	<br />
T1069.001-4 SharpHound3 - LocalAdmin	<br />
T1069.001-5 Wmic Group Discovery	<br />
T1069.001-6 WMIObject Group Discovery	<br />
T1069.002-1 Basic Permission Groups Discovery Windows (Domain)	<br />
T1069.002-2 Permission Groups Discovery PowerShell (Domain)	<br />
T1069.002-3 Elevated group enumeration using net group (Domain)	<br />
T1069.002-4 Find machines where user has local admin access (PowerView)	<br />
T1069.002-5 Find local admins on all machines in domain (PowerView)	<br />
T1069.002-6 Find Local Admins via Group Policy (PowerView)	<br />
T1069.002-7 Enumerate Users Not Requiring Pre Auth (ASRepRoast)	<br />
T1069.002-8 Adfind - Query Active Directory Groups	<br />
T1069.002-9 Enumerate Active Directory Groups with Get-AdGroup	<br />
T1069.002-10 Enumerate Active Directory Groups with ADSISearcher	<br />
T1069.002-11 Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)	<br />
T1069.002-12 Get-DomainGroupMember with PowerView	<br />
T1069.002-13 Get-DomainGroup with PowerView	<br />
T1070-1 Indicator Removal using FSUtil	<br />
T1070.001-1 Clear Logs	<br />
T1070.001-2 Delete System Logs Using Clear-EventLog	<br />
T1070.001-3 Clear Event Logs via VBA	<br />
T1070.003-10 Prevent Powershell History Logging	<br />
T1070.003-11 Clear Powershell History by Deleting History File	<br />
T1070.004-4 Delete a single file - Windows cmd	<br />
T1070.004-5 Delete an entire folder - Windows cmd	<br />
T1070.004-6 Delete a single file - Windows PowerShell	<br />
T1070.004-7 Delete an entire folder - Windows PowerShell	<br />
T1070.004-9 Delete Prefetch File	<br />
T1070.004-10 Delete TeamViewer Log Files	<br />
T1070.005-1 Add Network Share	<br />
T1070.005-2 Remove Network Share	<br />
T1070.005-3 Remove Network Share PowerShell	<br />
T1070.005-4 Disable Administrative Share Creation at Startup	<br />
T1070.005-5 Remove Administrative Shares	<br />
T1070.006-5 Windows - Modify file creation timestamp with PowerShell	<br />
T1070.006-6 Windows - Modify file last modified timestamp with PowerShell	<br />
T1070.006-7 Windows - Modify file last access timestamp with PowerShell	<br />
T1070.006-8 Windows - Timestomp a File	<br />
T1071.001-1 Malicious User Agents - Powershell	<br />
T1071.001-2 Malicious User Agents - CMD	<br />
T1071.004-1 DNS Large Query Volume	<br />
T1071.004-2 DNS Regular Beaconing	<br />
T1071.004-3 DNS Long Domain Query	<br />
T1071.004-4 DNS C2	<br />
T1072-1 Radmin Viewer Utility	<br />
T1074.001-1 Stage data from Discovery.bat	<br />
T1074.001-3 Zip a Folder with PowerShell for Staging in Temp	<br />
T1078.001-1 Enable Guest account with RDP capability and admin privileges	<br />
T1078.001-2 Activate Guest Account	<br />
T1078.003-1 Create local account with admin privileges	<br />
T1078.004-1 Creating GCP Service Account and Service Account Key	<br />
T1082-1 System Information Discovery	<br />
T1082-6 Hostname Discovery (Windows)	<br />
T1082-8 Windows MachineGUID Discovery	<br />
T1082-9 Griffon Recon	<br />
T1082-10 Environment variables discovery on windows	<br />
T1083-1 File and Directory Discovery (cmd.exe)	<br />
T1083-2 File and Directory Discovery (PowerShell)	<br />
T1083-5 Simulating MAZE Directory Enumeration	<br />
T1087.001-8 Enumerate all accounts on Windows (Local)	<br />
T1087.001-9 Enumerate all accounts via PowerShell (Local)	<br />
T1087.001-10 Enumerate logged on users via CMD (Local)	<br />
T1087.002-1 Enumerate all accounts (Domain)	<br />
T1087.002-2 Enumerate all accounts via PowerShell (Domain)	<br />
T1087.002-3 Enumerate logged on users via CMD (Domain)	<br />
T1087.002-4 Automated AD Recon (ADRecon)	<br />
T1087.002-5 Adfind -Listing password policy	<br />
T1087.002-6 Adfind - Enumerate Active Directory Admins	<br />
T1087.002-7 Adfind - Enumerate Active Directory User Objects	<br />
T1087.002-8 Adfind - Enumerate Active Directory Exchange AD Objects	<br />
T1087.002-9 Enumerate Default Domain Admin Details (Domain)	<br />
T1087.002-10 Enumerate Active Directory for Unconstrained Delegation	<br />
T1087.002-11 Get-DomainUser with PowerView	<br />
T1087.002-12 Enumerate Active Directory Users with ADSISearcher	<br />
T1090.001-3 portproxy reg key	<br />
T1090.003-1 Psiphon	<br />
T1090.003-2 Tor Proxy Usage - Windows	<br />
T1091-1 USB Malware Spread Simulation	<br />
T1095-1 ICMP C2	<br />
T1095-2 Netcat C2	<br />
T1095-3 Powercat C2	<br />
T1098-1 Admin Account Manipulate	<br />
T1098-2 Domain Account and Group Manipulate	<br />
T1098-4 Azure - adding user to Azure AD role	<br />
T1098-5 Azure - adding service principal to Azure AD role	<br />
T1098-6 Azure - adding user to Azure role in subscription	<br />
T1098-7 Azure - adding service principal to Azure role in subscription	<br />
T1098-8 AzureAD - adding permission to application	<br />
T1098.001-1 Azure AD Application Hijacking - Service Principal	<br />
T1098.001-2 Azure AD Application Hijacking - App Registration	<br />
T1105-7 certutil download (urlcache)	<br />
T1105-8 certutil download (verifyctl)	<br />
T1105-9 Windows - BITSAdmin BITS Download	<br />
T1105-10 Windows - PowerShell Download	<br />
T1105-11 OSTAP Worming Activity	<br />
T1105-12 svchost writing a file to a UNC path	<br />
T1105-13 Download a File with Windows Defender MpCmdRun.exe	<br />
T1105-15 File Download via PowerShell	<br />
T1105-16 File download with finger.exe on Windows	<br />
T1105-17 Download a file with IMEWDBLD.exe	<br />
T1105-18 Curl Download File	<br />
T1105-19 Curl Upload File	<br />
T1105-20 Download a file with Microsoft Connection Manager Auto-Download	<br />
T1106-1 Execution through API - CreateProcess	<br />
T1110.001-1 Brute Force Credentials of single Active Directory domain users via SMB	<br />
T1110.001-2 Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)	<br />
T1110.001-3 Brute Force Credentials of single Azure AD user	<br />
T1110.002-1 Password Cracking with Hashcat	<br />
T1110.003-1 Password Spray all Domain Users	<br />
T1110.003-2 Password Spray (DomainPasswordSpray)	<br />
T1110.003-3 Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)	<br />
T1110.003-4 Password spray all Azure AD users with a single password	<br />
T1112-1 Modify Registry of Current User Profile - cmd	<br />
T1112-2 Modify Registry of Local Machine - cmd	<br />
T1112-3 Modify registry to store logon credentials	<br />
T1112-4 Add domain to Trusted sites Zone	<br />
T1112-5 Javascript in registry	<br />
T1112-6 Change Powershell Execution Policy to Bypass	<br />
T1112-7 BlackByte Ransomware Registry Changes - CMD	<br />
T1112-8 BlackByte Ransomware Registry Changes - Powershell	<br />
T1112-9 Disable Windows Registry Tool	<br />
T1112-10 Disable Windows CMD application	<br />
T1112-11 Disable Windows Task Manager application	<br />
T1112-12 Disable Windows Notification Center	<br />
T1112-13 Disable Windows Shutdown Button	<br />
T1112-14 Disable Windows LogOff Button	<br />
T1112-15 Disable Windows Change Password Feature	<br />
T1112-16 Disable Windows Lock Workstation Feature	<br />
T1112-17 Activate Windows NoDesktop Group Policy Feature	<br />
T1112-18 Activate Windows NoRun Group Policy Feature	<br />
T1112-19 Activate Windows NoFind Group Policy Feature	<br />
T1112-20 Activate Windows NoControlPanel Group Policy Feature	<br />
T1112-21 Activate Windows NoFileMenu Group Policy Feature	<br />
T1112-22 Activate Windows NoClose Group Policy Feature	<br />
T1112-23 Activate Windows NoSetTaskbar Group Policy Feature	<br />
T1112-24 Activate Windows NoTrayContextMenu Group Policy Feature	<br />
T1112-25 Activate Windows NoPropertiesMyDocuments Group Policy Feature	<br />
T1112-26 Hide Windows Clock Group Policy Feature	<br />
T1112-27 Windows HideSCAHealth Group Policy Feature	<br />
T1112-28 Windows HideSCANetwork Group Policy Feature	<br />
T1112-29 Windows HideSCAPower Group Policy Feature	<br />
T1112-30 Windows HideSCAVolume Group Policy Feature	<br />
T1112-31 Windows Modify Show Compress Color And Info Tip Registry	<br />
T1112-32 Windows Powershell Logging Disabled	<br />
T1112-33 Windows Add Registry Value to Load Service in Safe Mode without Network	<br />
T1112-34 Windows Add Registry Value to Load Service in Safe Mode with Network	<br />
T1113-5 Windows Screencapture	<br />
T1113-6 Windows Screen Capture (CopyFromScreen)	<br />
T1114.001-1 Email Collection with PowerShell Get-Inbox	<br />
T1115-1 Utilize Clipboard to store or execute commands from	<br />
T1115-2 Execute Commands from Clipboard using PowerShell	<br />
T1115-4 Collect Clipboard Data via VBA	<br />
T1119-1 Automated Collection Command Prompt	<br />
T1119-2 Automated Collection PowerShell	<br />
T1119-3 Recon information for export with PowerShell	<br />
T1119-4 Recon information for export with Command Prompt	<br />
T1120-1 Win32_PnPEntity Hardware Inventory	<br />
T1123-1 using device audio capture commandlet	<br />
T1123-2 Registry artefact when application use microphone	<br />
T1124-1 System Time Discovery	<br />
T1124-2 System Time Discovery - PowerShell	<br />
T1125-1 Registry artefact when application use webcam	<br />
T1127.001-1 MSBuild Bypass Using Inline Tasks (C#)	<br />
T1127.001-2 MSBuild Bypass Using Inline Tasks (VB)	<br />
T1132.001-2 XOR Encoded data.	<br />
T1133-1 Running Chrome VPN Extensions via the Registry 2 vpn extension	<br />
T1134.001-1 Named pipe client impersonation	<br />
T1134.001-2 `SeDebugPrivilege` token duplication	<br />
T1134.002-1 Access Token Manipulation	<br />
T1134.004-1 Parent PID Spoofing using PowerShell	<br />
T1134.004-2 Parent PID Spoofing - Spawn from Current Process	<br />
T1134.004-3 Parent PID Spoofing - Spawn from Specified Process	<br />
T1134.004-4 Parent PID Spoofing - Spawn from svchost.exe	<br />
T1134.004-5 Parent PID Spoofing - Spawn from New Process	<br />
T1135-3 Network Share Discovery command prompt	<br />
T1135-4 Network Share Discovery PowerShell	<br />
T1135-5 View available share drives	<br />
T1135-6 Share Discovery with PowerView	<br />
T1135-7 PowerView ShareFinder	<br />
T1136.001-3 Create a new user in a command prompt	<br />
T1136.001-4 Create a new user in PowerShell	<br />
T1136.001-6 Create a new Windows admin user	<br />
T1136.002-1 Create a new Windows domain admin user	<br />
T1136.002-2 Create a new account similar to ANONYMOUS LOGON	<br />
T1136.002-3 Create a new Domain Account using PowerShell	<br />
T1137-1 Office Application Startup - Outlook as a C2	<br />
T1137.002-1 Office Application Startup Test Persistence	<br />
T1137.004-1 Install Outlook Home Page Persistence	<br />
T1137.006-1 Code Executed Via Excel Add-in File (Xll)	<br />
T1140-1 Deobfuscate/Decode Files Or Information	<br />
T1140-2 Certutil Rename and Decode	<br />
T1187-1 PetitPotam	<br />
ERROR: C:\AtomicRedTeam\atomics\T1195\T1195.yaml does not exist	<br />
Check your Atomic Number and your PathToAtomicsFolder parameter	<br />
T1197-1 Bitsadmin Download (cmd)	<br />
T1197-2 Bitsadmin Download (PowerShell)	<br />
T1197-3 Persist, Download, & Execute	<br />
T1197-4 Bits download using desktopimgdownldr.exe (cmd)	<br />
T1201-5 Examine local password policy - Windows	<br />
T1201-6 Examine domain password policy - Windows	<br />
T1201-8 Get-DomainPolicy with PowerView	<br />
T1201-9 Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy	<br />
T1202-1 Indirect Command Execution - pcalua.exe	<br />
T1202-2 Indirect Command Execution - forfiles.exe	<br />
T1202-3 Indirect Command Execution - conhost.exe	<br />
T1204.002-1 OSTap Style Macro Execution	<br />
T1204.002-2 OSTap Payload Download	<br />
T1204.002-3 Maldoc choice flags command execution	<br />
T1204.002-4 OSTAP JS version	<br />
T1204.002-5 Office launching .bat file from AppData	<br />
T1204.002-6 Excel 4 Macro	<br />
T1204.002-7 Headless Chrome code execution via VBA	<br />
T1204.002-8 Potentially Unwanted Applications (PUA)	<br />
T1204.002-9 Office Generic Payload Download	<br />
T1207-1 DCShadow (Active Directory)	<br />
T1216-1 SyncAppvPublishingServer Signed Script PowerShell Command Execution	<br />
T1216-2 manage-bde.wsf Signed Script Command Execution	<br />
T1216.001-1 PubPrn.vbs Signed Script Bypass	<br />
T1217-4 List Google Chrome / Opera Bookmarks on Windows with powershell	<br />
T1217-5 List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt	<br />
T1217-6 List Mozilla Firefox bookmarks on Windows with command prompt	<br />
T1217-7 List Internet Explorer Bookmarks using the command prompt	<br />
T1218-1 mavinject - Inject DLL into running process	<br />
T1218-2 SyncAppvPublishingServer - Execute arbitrary PowerShell code	<br />
T1218-3 Register-CimProvider - Execute evil dll	<br />
T1218-4 InfDefaultInstall.exe .inf Execution	<br />
T1218-5 ProtocolHandler.exe Downloaded a Suspicious File	<br />
T1218-6 Microsoft.Workflow.Compiler.exe Payload Execution	<br />
T1218-7 Renamed Microsoft.Workflow.Compiler.exe Payload Executions	<br />
T1218-8 Invoke-ATHRemoteFXvGPUDisablementCommand base test	<br />
T1218-9 DiskShadow Command Execution	<br />
T1218-10 Load Arbitrary DLL via Wuauclt (Windows Update Client)	<br />
T1218.001-1 Compiled HTML Help Local Payload	<br />
T1218.001-2 Compiled HTML Help Remote Payload	<br />
T1218.001-3 Invoke CHM with default Shortcut Command Execution	<br />
T1218.001-4 Invoke CHM with InfoTech Storage Protocol Handler	<br />
T1218.001-5 Invoke CHM Simulate Double click	<br />
T1218.001-6 Invoke CHM with Script Engine and Help Topic	<br />
T1218.001-7 Invoke CHM Shortcut Command with ITS and Help Topic	<br />
T1218.002-1 Control Panel Items	<br />
T1218.003-1 CMSTP Executing Remote Scriptlet	<br />
T1218.003-2 CMSTP Executing UAC Bypass	<br />
T1218.004-1 CheckIfInstallable method call	<br />
T1218.004-2 InstallHelper method call	<br />
T1218.004-3 InstallUtil class constructor method call	<br />
T1218.004-4 InstallUtil Install method call	<br />
T1218.004-5 InstallUtil Uninstall method call - /U variant	<br />
T1218.004-6 InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant	<br />
T1218.004-7 InstallUtil HelpText method call	<br />
T1218.004-8 InstallUtil evasive invocation	<br />
T1218.005-1 Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject	<br />
T1218.005-2 Mshta executes VBScript to execute malicious command	<br />
T1218.005-3 Mshta Executes Remote HTML Application (HTA)	<br />
T1218.005-4 Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement	<br />
T1218.005-5 Invoke HTML Application - Jscript Engine Simulating Double Click	<br />
T1218.005-6 Invoke HTML Application - Direct download from URI	<br />
T1218.005-7 Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler	<br />
T1218.005-8 Invoke HTML Application - JScript Engine with Inline Protocol Handler	<br />
T1218.005-9 Invoke HTML Application - Simulate Lateral Movement over UNC Path	<br />
T1218.005-10 Mshta used to Execute PowerShell	<br />
T1218.007-1 Msiexec.exe - Execute Local MSI file with embedded JScript	<br />
T1218.007-2 Msiexec.exe - Execute Local MSI file with embedded VBScript	<br />
T1218.007-3 Msiexec.exe - Execute Local MSI file with an embedded DLL	<br />
T1218.007-4 Msiexec.exe - Execute Local MSI file with an embedded EXE	<br />
T1218.007-5 WMI Win32_Product Class - Execute Local MSI file with embedded JScript	<br />
T1218.007-6 WMI Win32_Product Class - Execute Local MSI file with embedded VBScript	<br />
T1218.007-7 WMI Win32_Product Class - Execute Local MSI file with an embedded DLL	<br />
T1218.007-8 WMI Win32_Product Class - Execute Local MSI file with an embedded EXE	<br />
T1218.007-9 Msiexec.exe - Execute the DllRegisterServer function of a DLL	<br />
T1218.007-10 Msiexec.exe - Execute the DllUnregisterServer function of a DLL	<br />
T1218.007-11 Msiexec.exe - Execute Remote MSI file	<br />
T1218.008-1 Odbcconf.exe - Execute Arbitrary DLL	<br />
T1218.009-1 Regasm Uninstall Method Call Test	<br />
T1218.009-2 Regsvcs Uninstall Method Call Test	<br />
T1218.010-1 Regsvr32 local COM scriptlet execution	<br />
T1218.010-2 Regsvr32 remote COM scriptlet execution	<br />
T1218.010-3 Regsvr32 local DLL execution	<br />
T1218.010-4 Regsvr32 Registering Non DLL	<br />
T1218.010-5 Regsvr32 Silent DLL Install Call DllRegisterServer	<br />
T1218.011-1 Rundll32 execute JavaScript Remote Payload With GetObject	<br />
T1218.011-2 Rundll32 execute VBscript command	<br />
T1218.011-3 Rundll32 advpack.dll Execution	<br />
T1218.011-4 Rundll32 ieadvpack.dll Execution	<br />
T1218.011-5 Rundll32 syssetup.dll Execution	<br />
T1218.011-6 Rundll32 setupapi.dll Execution	<br />
T1218.011-7 Execution of HTA and VBS Files using Rundll32 and URL.dll	<br />
T1218.011-8 Launches an executable using Rundll32 and pcwutl.dll	<br />
T1218.011-9 Execution of non-dll using rundll32.exe	<br />
T1218.011-10 Rundll32 with Ordinal Value	<br />
T1218.011-11 Rundll32 with Control_RunDLL	<br />
T1219-1 TeamViewer Files Detected Test on Windows	<br />
T1219-2 AnyDesk Files Detected Test on Windows	<br />
T1219-3 LogMeIn Files Detected Test on Windows	<br />
T1219-4 GoToAssist Files Detected Test on Windows	<br />
T1219-5 ScreenConnect Application Download and Install on Windows	<br />
T1219-6 Ammyy Admin Software Execution	<br />
T1219-7 RemotePC Software Execution	<br />
T1220-1 MSXSL Bypass using local files	<br />
T1220-2 MSXSL Bypass using remote files	<br />
T1220-3 WMIC bypass using local XSL file	<br />
T1220-4 WMIC bypass using remote XSL file	<br />
T1221-1 WINWORD Remote Template Injection	<br />
T1222.001-1 Take ownership using takeown utility	<br />
T1222.001-2 cacls - Grant permission to specified user or group recursively	<br />
T1222.001-3 attrib - Remove read-only attribute	<br />
T1222.001-4 attrib - hide file	<br />
T1222.001-5 Grant Full Access to folder for Everyone - Ryuk Ransomware Style	<br />
T1482-1 Windows - Discover domain trusts with dsquery	<br />
T1482-2 Windows - Discover domain trusts with nltest	<br />
T1482-3 Powershell enumerate domains and forests	<br />
T1482-4 Adfind - Enumerate Active Directory OUs	<br />
T1482-5 Adfind - Enumerate Active Directory Trusts	<br />
T1482-6 Get-DomainTrust with PowerView	<br />
T1482-7 Get-ForestTrust with PowerView	<br />
T1484.002-1 Add Federation to Azure AD	<br />
T1485-1 Windows - Overwrite file with Sysinternals SDelete	<br />
T1485-3 Overwrite deleted data on C drive	<br />
T1486-5 PureLocker Ransom Note	<br />
T1489-1 Windows - Stop service using Service Controller	<br />
T1489-2 Windows - Stop service using net.exe	<br />
T1489-3 Windows - Stop service by killing process	<br />
T1490-1 Windows - Delete Volume Shadow Copies	<br />
T1490-2 Windows - Delete Volume Shadow Copies via WMI	<br />
T1490-3 Windows - wbadmin Delete Windows Backup Catalog	<br />
T1490-4 Windows - Disable Windows Recovery Console Repair	<br />
T1490-5 Windows - Delete Volume Shadow Copies via WMI with PowerShell	<br />
T1490-6 Windows - Delete Backup Files	<br />
T1490-7 Windows - wbadmin Delete systemstatebackup	<br />
T1490-8 Windows - Disable the SR scheduled task	<br />
T1490-9 Disable System Restore Through Registry	<br />
T1491.001-1 Replace Desktop Wallpaper	<br />
T1497.001-2 Detect Virtualization Environment (Windows)	<br />
T1497.001-4 Detect Virtualization Environment via WMI Manufacturer/Model Listing (Windows)	<br />
T1505.002-1 Install MS Exchange Transport Agent Persistence	<br />
T1505.003-1 Web Shell Written to Disk	<br />
T1518-1 Find and Display Internet Explorer Browser Version	<br />
T1518-2 Applications Installed	<br />
T1518.001-1 Security Software Discovery	<br />
T1518.001-2 Security Software Discovery - powershell	<br />
T1518.001-5 Security Software Discovery - Sysmon Service	<br />
T1518.001-6 Security Software Discovery - AV Discovery via WMI	<br />
T1529-1 Shutdown System - Windows	<br />
T1529-2 Restart System - Windows	<br />
T1531-1 Change User Password - Windows	<br />
T1531-2 Delete User - Windows	<br />
T1531-3 Remove Account From Domain Admin Group	<br />
T1539-1 Steal Firefox Cookies (Windows)	<br />
T1543.003-1 Modify Fax service to run PowerShell	<br />
T1543.003-2 Service Installation CMD	<br />
T1543.003-3 Service Installation PowerShell	<br />
T1543.003-4 TinyTurla backdoor service w64time	<br />
T1546.001-1 Change Default File Association	<br />
T1546.002-1 Set Arbitrary Binary as Screensaver	<br />
T1546.003-1 Persistence via WMI Event Subscription	<br />
T1546.007-1 Netsh Helper DLL Registration	<br />
T1546.008-1 Attaches Command Prompt as a Debugger to a List of Target Processes	<br />
T1546.008-2 Replace binary of sticky keys	<br />
T1546.010-1 Install AppInit Shim	<br />
T1546.011-1 Application Shim Installation	<br />
T1546.011-2 New shim database files created in the default shim database directory	<br />
T1546.011-3 Registry key creation and/or modification events for SDB	<br />
T1546.012-1 IFEO Add Debugger	<br />
T1546.012-2 IFEO Global Flags	<br />
T1546.013-1 Append malicious start-process cmdlet	<br />
T1546.015-1 COM Hijacking - InprocServer32	<br />
T1546.015-2 Powershell Execute COM Object	<br />
T1547-1 Add a driver	<br />
T1547.001-1 Reg Key Run	<br />
T1547.001-2 Reg Key RunOnce	<br />
T1547.001-3 PowerShell Registry RunOnce	<br />
T1547.001-4 Suspicious vbs file run from startup Folder	<br />
T1547.001-5 Suspicious jse file run from startup Folder	<br />
T1547.001-6 Suspicious bat file run from startup Folder	<br />
T1547.001-7 Add Executable Shortcut Link to User Startup Folder	<br />
T1547.001-8 Add persistance via Recycle bin	<br />
T1547.001-9 SystemBC Malware-as-a-Service Registry	<br />
T1547.002-1 Authentication Package	<br />
T1547.004-1 Winlogon Shell Key Persistence - PowerShell	<br />
T1547.004-2 Winlogon Userinit Key Persistence - PowerShell	<br />
T1547.004-3 Winlogon Notify Key Logon Persistence - PowerShell	<br />
T1547.005-1 Modify SSP configuration in registry	<br />
T1547.009-1 Shortcut Modification	<br />
T1547.009-2 Create shortcut to cmd in startup folders	<br />
T1547.010-1 Add Port Monitor persistence in Registry	<br />
T1548.002-1 Bypass UAC using Event Viewer (cmd)	<br />
T1548.002-2 Bypass UAC using Event Viewer (PowerShell)	<br />
T1548.002-3 Bypass UAC using Fodhelper	<br />
T1548.002-4 Bypass UAC using Fodhelper - PowerShell	<br />
T1548.002-5 Bypass UAC using ComputerDefaults (PowerShell)	<br />
T1548.002-6 Bypass UAC by Mocking Trusted Directories	<br />
T1548.002-7 Bypass UAC using sdclt DelegateExecute	<br />
T1548.002-8 Disable UAC using reg.exe	<br />
T1548.002-9 Bypass UAC using SilentCleanup task	<br />
T1548.002-10 UACME Bypass Method 23	<br />
T1548.002-11 UACME Bypass Method 31	<br />
T1548.002-12 UACME Bypass Method 33	<br />
T1548.002-13 UACME Bypass Method 34	<br />
T1548.002-14 UACME Bypass Method 39	<br />
T1548.002-15 UACME Bypass Method 56	<br />
T1548.002-16 UACME Bypass Method 59	<br />
T1548.002-17 UACME Bypass Method 61	<br />
T1550.002-1 Mimikatz Pass the Hash	<br />
T1550.002-2 crackmapexec Pass the Hash	<br />
T1550.003-1 Mimikatz Kerberos Ticket Attack	<br />
T1550.003-2 Rubeus Kerberos Pass The Ticket	<br />
T1552.001-3 Extracting passwords with findstr	<br />
T1552.001-4 Access unattend.xml	<br />
T1552.002-1 Enumeration for Credentials in Registry	<br />
T1552.002-2 Enumeration for PuTTY Credentials in Registry	<br />
T1552.004-1 Private Keys	<br />
T1552.004-6 ADFS token signing and encryption certificates theft - Local	<br />
T1552.004-7 ADFS token signing and encryption certificates theft - Remote	<br />
T1552.006-1 GPP Passwords (findstr)	<br />
T1552.006-2 GPP Passwords (Get-GPPPassword)	<br />
T1553.004-4 Install root CA on Windows	<br />
T1553.004-5 Install root CA on Windows with certutil	<br />
T1553.004-6 Add Root Certificate to CurrentUser Certificate Store	<br />
T1553.005-1 Mount ISO image	<br />
T1553.005-2 Mount an ISO image and run executable from the ISO	<br />
T1553.005-3 Remove the Zone.Identifier alternate data stream	<br />
T1555-1 Extract Windows Credential Manager via VBA	<br />
T1555-2 Dump credentials from Windows Credential Manager With PowerShell [windows Credentials]	<br />
T1555-3 Dump credentials from Windows Credential Manager With PowerShell [web Credentials]	<br />
T1555-4 Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]	<br />
T1555-5 Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]	<br />
T1555.003-1 Run Chrome-password Collector	<br />
T1555.003-3 LaZagne - Credentials from Browser	<br />
T1555.003-4 Simulating access to Chrome Login Data	<br />
T1555.003-5 Simulating access to Opera Login Data	<br />
T1555.003-6 Simulating access to Windows Firefox Login Data	<br />
T1555.003-7 Simulating access to Windows Edge Login Data	<br />
T1555.003-8 Decrypt Mozilla Passwords with Firepwd.py	<br />
T1555.004-1 Access Saved Credentials via VaultCmd	<br />
T1556.002-1 Install and Register Password Filter DLL	<br />
T1557.001-1 LLMNR Poisoning with Inveigh (PowerShell)	<br />
T1558.001-1 Crafting Active Directory golden tickets with mimikatz	<br />
T1558.001-2 Crafting Active Directory golden tickets with Rubeus	<br />
T1558.003-1 Request for service tickets	<br />
T1558.003-2 Rubeus kerberoast	<br />
T1558.003-3 Extract all accounts in use as SPN using setspn	<br />
T1558.003-4 Request A Single Ticket via PowerShell	<br />
T1558.003-5 Request All Tickets via PowerShell	<br />
T1558.004-1 Rubeus asreproast	<br />
T1558.004-2 Get-DomainUser with PowerView	<br />
T1559.002-2 Execute PowerShell script via Word DDE	<br />
T1560-1 Compress Data for Exfiltration With PowerShell	<br />
T1560.001-1 Compress Data for Exfiltration With Rar	<br />
T1560.001-2 Compress Data and lock with password for Exfiltration with winrar	<br />
T1560.001-3 Compress Data and lock with password for Exfiltration with winzip	<br />
T1560.001-4 Compress Data and lock with password for Exfiltration with 7zip	<br />
T1562.001-10 Unload Sysmon Filter Driver	<br />
T1562.001-11 Uninstall Sysmon	<br />
T1562.001-12 AMSI Bypass - AMSI InitFailed	<br />
T1562.001-13 AMSI Bypass - Remove AMSI Provider Reg Key	<br />
T1562.001-14 Disable Arbitrary Security Windows Service	<br />
T1562.001-15 Tamper with Windows Defender ATP PowerShell	<br />
T1562.001-16 Tamper with Windows Defender Command Prompt	<br />
T1562.001-17 Tamper with Windows Defender Registry	<br />
T1562.001-18 Disable Microsoft Office Security Features	<br />
T1562.001-19 Remove Windows Defender Definition Files	<br />
T1562.001-20 Stop and Remove Arbitrary Security Windows Service	<br />
T1562.001-21 Uninstall Crowdstrike Falcon on Windows	<br />
T1562.001-22 Tamper with Windows Defender Evade Scanning -Folder	<br />
T1562.001-23 Tamper with Windows Defender Evade Scanning -Extension	<br />
T1562.001-24 Tamper with Windows Defender Evade Scanning -Process	<br />
T1562.001-25 office-365-Disable-AntiPhishRule	<br />
T1562.001-26 Disable Windows Defender with DISM	<br />
T1562.001-27 Disable Defender with Defender Control	<br />
T1562.001-28 Disable Defender Using NirSoft AdvancedRun	<br />
T1562.002-1 Disable Windows IIS HTTP Logging	<br />
T1562.002-2 Kill Event Log Service Threads	<br />
T1562.002-3 Impair Windows Audit Log Policy	<br />
T1562.002-4 Clear Windows Audit Policy Config	<br />
T1562.002-5 Disable Event Logging with wevtutil	<br />
T1562.002-6 Makes Eventlog blind with Phant0m	<br />
T1562.004-1 Disable Microsoft Defender Firewall	<br />
T1562.004-2 Disable Microsoft Defender Firewall via Registry	<br />
T1562.004-3 Allow SMB and RDP on Microsoft Defender Firewall	<br />
T1562.004-4 Opening ports for proxy - HARDRAIN	<br />
T1562.004-5 Open a local port through Windows Firewall to any profile	<br />
T1562.004-6 Allow Executable Through Firewall Located in Non-Standard Location	<br />
T1562.008-2 Azure - Eventhub Deletion	<br />
T1562.008-3 Office 365 - Exchange Audit Log Disabled	<br />
T1563.002-1 RDP hijacking	<br />
T1564-1 Extract binary files via VBA	<br />
T1564-2 Create a Hidden User Called "$"	<br />
T1564-3 Create an "Administrator " user (with a space on the end)	<br />
T1564.001-3 Create Windows System File with Attrib	<br />
T1564.001-4 Create Windows Hidden File with Attrib	<br />
T1564.001-8 Hide Files Through Registry	<br />
T1564.003-1 Hidden Window	<br />
T1564.004-1 Alternate Data Streams (ADS)	<br />
T1564.004-2 Store file in Alternate Data Stream (ADS)	<br />
T1564.004-3 Create ADS command prompt	<br />
T1564.004-4 Create ADS PowerShell	<br />
T1564.006-1 Register Portable Virtualbox	<br />
T1564.006-2 Create and start VirtualBox virtual machine	<br />
T1564.006-3 Create and start Hyper-V virtual machine	<br />
T1566.001-1 Download Macro-Enabled Phishing Attachment	<br />
T1566.001-2 Word spawned a command shell and used an IP address in the command line	<br />
T1567-1 Data Exfiltration with ConfigSecurityPolicy	<br />
T1569.002-1 Execute a Command as a Service	<br />
T1569.002-2 Use PsExec to execute a command on a remote host	<br />
T1571-1 Testing usage of uncommonly used port with PowerShell	<br />
T1572-1 DNS over HTTPS Large Query Volume	<br />
T1572-2 DNS over HTTPS Regular Beaconing	<br />
T1572-3 DNS over HTTPS Long Domain Query	<br />
T1573-1 OpenSSL C2	<br />
T1574.001-1 DLL Search Order Hijacking - amsi.dll	<br />
T1574.002-1 DLL Side-Loading using the Notepad++ GUP.exe binary	<br />
T1574.009-1 Execution of program.exe as service with unquoted service path	<br />
T1574.011-1 Service Registry Permissions Weakness	<br />
T1574.011-2 Service ImagePath Change with reg.exe	<br />
T1574.012-1 User scope COR_PROFILER	<br />
T1574.012-2 System Scope COR_PROFILER	<br />
T1574.012-3 Registry-free process scope COR_PROFILER	<br />
T1606.002-1 Golden SAML	<br />
T1615-1 Display group policy information via gpresult	<br />
