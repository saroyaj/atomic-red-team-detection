Follina — a Microsoft Office code execution vulnerability
T1003-2 Credential Dumping with NPPSpy
T1003-3 Dump svchost.exe to gather RDP credentials
T1003.001-1 Dump LSASS.exe Memory using ProcDump
T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll
T1003.001-3 Dump LSASS.exe Memory using direct system calls and API unhooking
T1003.001-4 Dump LSASS.exe Memory using NanoDump
T1003.001-6 Offline Credential Theft With Mimikatz
T1003.001-7 LSASS read with pypykatz
T1003.001-8 Dump LSASS.exe Memory using Out-Minidump.ps1
T1003.001-9 Create Mini Dump of LSASS.exe using ProcDump
T1003.001-10 Powershell Mimikatz
T1003.001-11 Dump LSASS with .Net 5 createdump.exe
T1003.001-12 Dump LSASS.exe using imported Microsoft DLLs
T1003.002-1 Registry dump of SAM, creds, and secrets
T1003.002-2 Registry parse with pypykatz
T1003.002-3 esentutl.exe SAM copy
T1003.002-4 PowerDump Hashes and Usernames from Registry
T1003.002-5 dump volume shadow copy hives with certutil
T1003.002-6 dump volume shadow copy hives with System.IO.File
T1003.003-1 Create Volume Shadow Copy with vssadmin
T1003.003-2 Copy NTDS.dit from Volume Shadow Copy
T1003.003-3 Dump Active Directory Database with NTDSUtil
T1003.003-4 Create Volume Shadow Copy with WMI
T1003.003-5 Create Volume Shadow Copy remotely with WMI
T1003.003-6 Create Volume Shadow Copy remotely (WMI) with esentutl
T1003.003-7 Create Volume Shadow Copy with Powershell
T1003.003-8 Create Symlink to Volume Shadow Copy
T1003.004-1 Dumping LSA Secrets
T1003.005-1 Cached Credential Dump via Cmdkey
T1003.006-1 DCSync (Active Directory)
T1003.006-2 Run DSInternals Get-ADReplAccount
T1006-1 Read volume boot sector via DOS device path (PowerShell)
T1007-1 System Service Discovery
T1007-2 System Service Discovery - net.exe
T1010-1 List Process Main Windows - C# .NET
T1012-1 Query Registry
T1016-1 System Network Configuration Discovery on Windows
T1016-2 List Windows Firewall Rules
T1016-4 System Network Configuration Discovery (TrickBot Style)
T1016-5 List Open Egress Ports
T1016-6 Adfind - Enumerate Active Directory Subnet Objects
T1016-7 Qakbot Recon
T1018-1 Remote System Discovery - net
T1018-2 Remote System Discovery - net group Domain Computers
T1018-3 Remote System Discovery - nltest
T1018-4 Remote System Discovery - ping sweep
T1018-5 Remote System Discovery - arp
T1018-8 Remote System Discovery - nslookup
T1018-9 Remote System Discovery - adidnsdump
T1018-10 Adfind - Enumerate Active Directory Computer Objects
T1018-11 Adfind - Enumerate Active Directory Domain Controller Objects
T1018-15 Enumerate domain computers within Active Directory using DirectorySearcher
T1018-16 Enumerate Active Directory Computers with Get-AdComputer
T1018-17 Enumerate Active Directory Computers with ADSISearcher
T1018-18 Get-DomainController with PowerView
T1018-19 Get-wmiobject to Enumerate Domain Controllers
T1020-1 IcedID Botnet HTTP PUT
T1021.001-1 RDP to DomainController
T1021.001-2 RDP to Server
T1021.001-3 Changing RDP Port to Non Standard Port via Powershell
T1021.001-4 Changing RDP Port to Non Standard Port via Command_Prompt
T1021.002-1 Map admin share
T1021.002-2 Map Admin Share PowerShell
T1021.002-3 Copy and Execute File with PsExec
T1021.002-4 Execute command writing output to local Admin Share
T1021.003-1 PowerShell Lateral Movement using MMC20
T1021.006-1 Enable Windows Remote Management
T1021.006-2 Invoke-Command
T1021.006-3 WinRM Access with Evil-WinRM
T1027-2 Execute base64-encoded PowerShell
T1027-3 Execute base64-encoded PowerShell from Windows Registry
T1027-4 Execution from Compressed File
T1027-5 DLP Evasion via Sensitive Data in VBA Macro over email
T1027-6 DLP Evasion via Sensitive Data in VBA Macro over HTTP
T1027-7 Obfuscated Command in PowerShell
T1027.004-1 Compile After Delivery using csc.exe
T1027.004-2 Dynamic C# Compile
T1033-1 System Owner/User Discovery
T1033-3 Find computers where user has session - Stealth mode (PowerView)
T1033-4 User Discovery With Env Vars PowerShell Script
T1033-5 GetCurrent User with PowerShell Script
T1036-1 System File Copied to Unusual Location
T1036-2 Malware Masquerading and Execution from Zip File
T1036.003-1 Masquerading as Windows LSASS process
T1036.003-3 Masquerading - cscript.exe running as notepad.exe
T1036.003-4 Masquerading - wscript.exe running as svchost.exe
T1036.003-5 Masquerading - powershell.exe running as taskhostw.exe
T1036.003-6 Masquerading - non-windows exe running as windows exe
T1036.003-7 Masquerading - windows exe running as different windows exe
T1036.003-8 Malicious process Masquerading as LSM.exe
T1036.003-9 File Extension Masquerading
T1036.004-1 Creating W32Time similar named service using schtasks
T1036.004-2 Creating W32Time similar named service using sc
T1036.005-2 Masquerade as a built-in system executable
T1037.001-1 Logon Scripts
T1039-1 Copy a sensitive File over Administive share with copy
T1039-2 Copy a sensitive File over Administive share with Powershell
T1040-3 Packet Capture Windows Command Prompt
T1040-4 Windows Internal Packet Capture
T1041-1 C2 Data Exfiltration
T1046-3 Port Scan NMap for Windows
T1046-4 Port Scan using python
T1047-1 WMI Reconnaissance Users
T1047-2 WMI Reconnaissance Processes
T1047-3 WMI Reconnaissance Software
T1047-4 WMI Reconnaissance List Remote Services
T1047-5 WMI Execute Local Process
T1047-6 WMI Execute Remote Process
T1047-7 Create a Process using WMI Query and an Encoded Command
T1047-8 Create a Process using obfuscated Win32_Process
T1047-9 WMI Execute rundll32
T1047-10 Application uninstall using WMIC
T1048-3 DNSExfiltration (doh)
T1048.002-1 Exfiltrate data HTTPS using curl windows
T1048.003-2 Exfiltration Over Alternative Protocol - ICMP
T1048.003-4 Exfiltration Over Alternative Protocol - HTTP
T1048.003-5 Exfiltration Over Alternative Protocol - SMTP
T1049-1 System Network Connections Discovery
T1049-2 System Network Connections Discovery with PowerShell
T1049-4 System Discovery using SharpView
T1053.002-1 At.exe Scheduled task
T1053.005-1 Scheduled Task Startup Script
T1053.005-2 Scheduled task Local
T1053.005-3 Scheduled task Remote
T1053.005-4 Powershell Cmdlet Scheduled Task
T1053.005-5 Task Scheduler via VBA
T1053.005-6 WMI Invoke-CimMethod Scheduled Task
T1053.005-7 Scheduled Task Executing Base64 Encoded Commands From Registry
T1055-1 Shellcode execution via VBA
T1055-2 Remote Process Injection in LSASS via mimikatz
T1055.001-1 Process Injection via mavinject.exe
T1055.004-1 Process Injection via C#
T1055.012-1 Process Hollowing using PowerShell
T1055.012-2 RunPE via VBA
T1056.001-1 Input Capture
T1056.002-2 PowerShell - Prompt User for Password
T1056.004-1 Hook PowerShell TLS Encrypt/Decrypt Messages
T1057-2 Process Discovery - tasklist
T1057-3 Process Discovery - Get-Process
T1057-4 Process Discovery - get-wmiObject
T1057-5 Process Discovery - wmic process
T1059.001-1 Mimikatz
T1059.001-2 Run BloodHound from local disk
T1059.001-3 Run Bloodhound from Memory using Download Cradle
T1059.001-4 Obfuscation Tests
T1059.001-5 Mimikatz - Cradlecraft PsSendKeys
T1059.001-6 Invoke-AppPathBypass
T1059.001-7 Powershell MsXml COM object - with prompt
T1059.001-8 Powershell XML requests
T1059.001-9 Powershell invoke mshta.exe download
T1059.001-11 PowerShell Fileless Script Execution
T1059.001-12 PowerShell Downgrade Attack
T1059.001-13 NTFS Alternate Data Stream Access
T1059.001-14 PowerShell Session Creation and Use
T1059.001-15 ATHPowerShellCommandLineParameter -Command parameter variations
T1059.001-16 ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments
T1059.001-17 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations
T1059.001-18 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments
T1059.001-19 PowerShell Command Execution
T1059.001-20 PowerShell Invoke Known Malicious Cmdlets
T1059.001-21 PowerUp Invoke-AllChecks
T1059.003-1 Create and Execute Batch Script
T1059.003-2 Writes text to a file and displays it.
T1059.003-3 Suspicious Execution via Windows Command Shell
T1059.003-4 Simulate BlackByte Ransomware Print Bombing
T1059.005-1 Visual Basic script execution to gather local computer information
T1059.005-2 Encoded VBS code execution
T1059.005-3 Extract Memory via VBA
T1069.001-2 Basic Permission Groups Discovery Windows (Local)
T1069.001-3 Permission Groups Discovery PowerShell (Local)
T1069.001-4 SharpHound3 - LocalAdmin
T1069.001-5 Wmic Group Discovery
T1069.001-6 WMIObject Group Discovery
T1069.002-1 Basic Permission Groups Discovery Windows (Domain)
T1069.002-2 Permission Groups Discovery PowerShell (Domain)
T1069.002-3 Elevated group enumeration using net group (Domain)
T1069.002-4 Find machines where user has local admin access (PowerView)
T1069.002-5 Find local admins on all machines in domain (PowerView)
T1069.002-6 Find Local Admins via Group Policy (PowerView)
T1069.002-7 Enumerate Users Not Requiring Pre Auth (ASRepRoast)
T1069.002-8 Adfind - Query Active Directory Groups
T1069.002-9 Enumerate Active Directory Groups with Get-AdGroup
T1069.002-10 Enumerate Active Directory Groups with ADSISearcher
T1069.002-11 Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)
T1069.002-12 Get-DomainGroupMember with PowerView
T1069.002-13 Get-DomainGroup with PowerView
T1070-1 Indicator Removal using FSUtil
T1070.001-1 Clear Logs
T1070.001-2 Delete System Logs Using Clear-EventLog
T1070.001-3 Clear Event Logs via VBA
T1070.003-10 Prevent Powershell History Logging
T1070.003-11 Clear Powershell History by Deleting History File
T1070.004-4 Delete a single file - Windows cmd
T1070.004-5 Delete an entire folder - Windows cmd
T1070.004-6 Delete a single file - Windows PowerShell
T1070.004-7 Delete an entire folder - Windows PowerShell
T1070.004-9 Delete Prefetch File
T1070.004-10 Delete TeamViewer Log Files
T1070.005-1 Add Network Share
T1070.005-2 Remove Network Share
T1070.005-3 Remove Network Share PowerShell
T1070.005-4 Disable Administrative Share Creation at Startup
T1070.005-5 Remove Administrative Shares
T1070.006-5 Windows - Modify file creation timestamp with PowerShell
T1070.006-6 Windows - Modify file last modified timestamp with PowerShell
T1070.006-7 Windows - Modify file last access timestamp with PowerShell
T1070.006-8 Windows - Timestomp a File
T1071.001-1 Malicious User Agents - Powershell
T1071.001-2 Malicious User Agents - CMD
T1071.004-1 DNS Large Query Volume
T1071.004-2 DNS Regular Beaconing
T1071.004-3 DNS Long Domain Query
T1071.004-4 DNS C2
T1072-1 Radmin Viewer Utility
T1074.001-1 Stage data from Discovery.bat
T1074.001-3 Zip a Folder with PowerShell for Staging in Temp
T1078.001-1 Enable Guest account with RDP capability and admin privileges
T1078.001-2 Activate Guest Account
T1078.003-1 Create local account with admin privileges
T1078.004-1 Creating GCP Service Account and Service Account Key
T1082-1 System Information Discovery
T1082-6 Hostname Discovery (Windows)
T1082-8 Windows MachineGUID Discovery
T1082-9 Griffon Recon
T1082-10 Environment variables discovery on windows
T1083-1 File and Directory Discovery (cmd.exe)
T1083-2 File and Directory Discovery (PowerShell)
T1083-5 Simulating MAZE Directory Enumeration
T1087.001-8 Enumerate all accounts on Windows (Local)
T1087.001-9 Enumerate all accounts via PowerShell (Local)
T1087.001-10 Enumerate logged on users via CMD (Local)
T1087.002-1 Enumerate all accounts (Domain)
T1087.002-2 Enumerate all accounts via PowerShell (Domain)
T1087.002-3 Enumerate logged on users via CMD (Domain)
T1087.002-4 Automated AD Recon (ADRecon)
T1087.002-5 Adfind -Listing password policy
T1087.002-6 Adfind - Enumerate Active Directory Admins
T1087.002-7 Adfind - Enumerate Active Directory User Objects
T1087.002-8 Adfind - Enumerate Active Directory Exchange AD Objects
T1087.002-9 Enumerate Default Domain Admin Details (Domain)
T1087.002-10 Enumerate Active Directory for Unconstrained Delegation
T1087.002-11 Get-DomainUser with PowerView
T1087.002-12 Enumerate Active Directory Users with ADSISearcher
T1090.001-3 portproxy reg key
T1090.003-1 Psiphon
T1090.003-2 Tor Proxy Usage - Windows
T1091-1 USB Malware Spread Simulation
T1095-1 ICMP C2
T1095-2 Netcat C2
T1095-3 Powercat C2
T1098-1 Admin Account Manipulate
T1098-2 Domain Account and Group Manipulate
T1098-4 Azure - adding user to Azure AD role
T1098-5 Azure - adding service principal to Azure AD role
T1098-6 Azure - adding user to Azure role in subscription
T1098-7 Azure - adding service principal to Azure role in subscription
T1098-8 AzureAD - adding permission to application
T1098.001-1 Azure AD Application Hijacking - Service Principal
T1098.001-2 Azure AD Application Hijacking - App Registration
T1105-7 certutil download (urlcache)
T1105-8 certutil download (verifyctl)
T1105-9 Windows - BITSAdmin BITS Download
T1105-10 Windows - PowerShell Download
T1105-11 OSTAP Worming Activity
T1105-12 svchost writing a file to a UNC path
T1105-13 Download a File with Windows Defender MpCmdRun.exe
T1105-15 File Download via PowerShell
T1105-16 File download with finger.exe on Windows
T1105-17 Download a file with IMEWDBLD.exe
T1105-18 Curl Download File
T1105-19 Curl Upload File
T1105-20 Download a file with Microsoft Connection Manager Auto-Download
T1106-1 Execution through API - CreateProcess
T1110.001-1 Brute Force Credentials of single Active Directory domain users via SMB
T1110.001-2 Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)
T1110.001-3 Brute Force Credentials of single Azure AD user
T1110.002-1 Password Cracking with Hashcat
T1110.003-1 Password Spray all Domain Users
T1110.003-2 Password Spray (DomainPasswordSpray)
T1110.003-3 Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)
T1110.003-4 Password spray all Azure AD users with a single password
T1112-1 Modify Registry of Current User Profile - cmd
T1112-2 Modify Registry of Local Machine - cmd
T1112-3 Modify registry to store logon credentials
T1112-4 Add domain to Trusted sites Zone
T1112-5 Javascript in registry
T1112-6 Change Powershell Execution Policy to Bypass
T1112-7 BlackByte Ransomware Registry Changes - CMD
T1112-8 BlackByte Ransomware Registry Changes - Powershell
T1112-9 Disable Windows Registry Tool
T1112-10 Disable Windows CMD application
T1112-11 Disable Windows Task Manager application
T1112-12 Disable Windows Notification Center
T1112-13 Disable Windows Shutdown Button
T1112-14 Disable Windows LogOff Button
T1112-15 Disable Windows Change Password Feature
T1112-16 Disable Windows Lock Workstation Feature
T1112-17 Activate Windows NoDesktop Group Policy Feature
T1112-18 Activate Windows NoRun Group Policy Feature
T1112-19 Activate Windows NoFind Group Policy Feature
T1112-20 Activate Windows NoControlPanel Group Policy Feature
T1112-21 Activate Windows NoFileMenu Group Policy Feature
T1112-22 Activate Windows NoClose Group Policy Feature
T1112-23 Activate Windows NoSetTaskbar Group Policy Feature
T1112-24 Activate Windows NoTrayContextMenu Group Policy Feature
T1112-25 Activate Windows NoPropertiesMyDocuments Group Policy Feature
T1112-26 Hide Windows Clock Group Policy Feature
T1112-27 Windows HideSCAHealth Group Policy Feature
T1112-28 Windows HideSCANetwork Group Policy Feature
T1112-29 Windows HideSCAPower Group Policy Feature
T1112-30 Windows HideSCAVolume Group Policy Feature
T1112-31 Windows Modify Show Compress Color And Info Tip Registry
T1112-32 Windows Powershell Logging Disabled
T1112-33 Windows Add Registry Value to Load Service in Safe Mode without Network
T1112-34 Windows Add Registry Value to Load Service in Safe Mode with Network
T1113-5 Windows Screencapture
T1113-6 Windows Screen Capture (CopyFromScreen)
T1114.001-1 Email Collection with PowerShell Get-Inbox
T1115-1 Utilize Clipboard to store or execute commands from
T1115-2 Execute Commands from Clipboard using PowerShell
T1115-4 Collect Clipboard Data via VBA
T1119-1 Automated Collection Command Prompt
T1119-2 Automated Collection PowerShell
T1119-3 Recon information for export with PowerShell
T1119-4 Recon information for export with Command Prompt
T1120-1 Win32_PnPEntity Hardware Inventory
T1123-1 using device audio capture commandlet
T1123-2 Registry artefact when application use microphone
T1124-1 System Time Discovery
T1124-2 System Time Discovery - PowerShell
T1125-1 Registry artefact when application use webcam
T1127.001-1 MSBuild Bypass Using Inline Tasks (C#)
T1127.001-2 MSBuild Bypass Using Inline Tasks (VB)
T1132.001-2 XOR Encoded data.
T1133-1 Running Chrome VPN Extensions via the Registry 2 vpn extension
T1134.001-1 Named pipe client impersonation
T1134.001-2 `SeDebugPrivilege` token duplication
T1134.002-1 Access Token Manipulation
T1134.004-1 Parent PID Spoofing using PowerShell
T1134.004-2 Parent PID Spoofing - Spawn from Current Process
T1134.004-3 Parent PID Spoofing - Spawn from Specified Process
T1134.004-4 Parent PID Spoofing - Spawn from svchost.exe
T1134.004-5 Parent PID Spoofing - Spawn from New Process
T1135-3 Network Share Discovery command prompt
T1135-4 Network Share Discovery PowerShell
T1135-5 View available share drives
T1135-6 Share Discovery with PowerView
T1135-7 PowerView ShareFinder
T1136.001-3 Create a new user in a command prompt
T1136.001-4 Create a new user in PowerShell
T1136.001-6 Create a new Windows admin user
T1136.002-1 Create a new Windows domain admin user
T1136.002-2 Create a new account similar to ANONYMOUS LOGON
T1136.002-3 Create a new Domain Account using PowerShell
T1137-1 Office Application Startup - Outlook as a C2
T1137.002-1 Office Application Startup Test Persistence
T1137.004-1 Install Outlook Home Page Persistence
T1137.006-1 Code Executed Via Excel Add-in File (Xll)
T1140-1 Deobfuscate/Decode Files Or Information
T1140-2 Certutil Rename and Decode
T1187-1 PetitPotam
ERROR: C:\AtomicRedTeam\atomics\T1195\T1195.yaml does not exist
Check your Atomic Number and your PathToAtomicsFolder parameter
T1197-1 Bitsadmin Download (cmd)
T1197-2 Bitsadmin Download (PowerShell)
T1197-3 Persist, Download, & Execute
T1197-4 Bits download using desktopimgdownldr.exe (cmd)
T1201-5 Examine local password policy - Windows
T1201-6 Examine domain password policy - Windows
T1201-8 Get-DomainPolicy with PowerView
T1201-9 Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy
T1202-1 Indirect Command Execution - pcalua.exe
T1202-2 Indirect Command Execution - forfiles.exe
T1202-3 Indirect Command Execution - conhost.exe
T1204.002-1 OSTap Style Macro Execution
T1204.002-2 OSTap Payload Download
T1204.002-3 Maldoc choice flags command execution
T1204.002-4 OSTAP JS version
T1204.002-5 Office launching .bat file from AppData
T1204.002-6 Excel 4 Macro
T1204.002-7 Headless Chrome code execution via VBA
T1204.002-8 Potentially Unwanted Applications (PUA)
T1204.002-9 Office Generic Payload Download
T1207-1 DCShadow (Active Directory)
T1216-1 SyncAppvPublishingServer Signed Script PowerShell Command Execution
T1216-2 manage-bde.wsf Signed Script Command Execution
T1216.001-1 PubPrn.vbs Signed Script Bypass
T1217-4 List Google Chrome / Opera Bookmarks on Windows with powershell
T1217-5 List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt
T1217-6 List Mozilla Firefox bookmarks on Windows with command prompt
T1217-7 List Internet Explorer Bookmarks using the command prompt
T1218-1 mavinject - Inject DLL into running process
T1218-2 SyncAppvPublishingServer - Execute arbitrary PowerShell code
T1218-3 Register-CimProvider - Execute evil dll
T1218-4 InfDefaultInstall.exe .inf Execution
T1218-5 ProtocolHandler.exe Downloaded a Suspicious File
T1218-6 Microsoft.Workflow.Compiler.exe Payload Execution
T1218-7 Renamed Microsoft.Workflow.Compiler.exe Payload Executions
T1218-8 Invoke-ATHRemoteFXvGPUDisablementCommand base test
T1218-9 DiskShadow Command Execution
T1218-10 Load Arbitrary DLL via Wuauclt (Windows Update Client)
T1218.001-1 Compiled HTML Help Local Payload
T1218.001-2 Compiled HTML Help Remote Payload
T1218.001-3 Invoke CHM with default Shortcut Command Execution
T1218.001-4 Invoke CHM with InfoTech Storage Protocol Handler
T1218.001-5 Invoke CHM Simulate Double click
T1218.001-6 Invoke CHM with Script Engine and Help Topic
T1218.001-7 Invoke CHM Shortcut Command with ITS and Help Topic
T1218.002-1 Control Panel Items
T1218.003-1 CMSTP Executing Remote Scriptlet
T1218.003-2 CMSTP Executing UAC Bypass
T1218.004-1 CheckIfInstallable method call
T1218.004-2 InstallHelper method call
T1218.004-3 InstallUtil class constructor method call
T1218.004-4 InstallUtil Install method call
T1218.004-5 InstallUtil Uninstall method call - /U variant
T1218.004-6 InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant
T1218.004-7 InstallUtil HelpText method call
T1218.004-8 InstallUtil evasive invocation
T1218.005-1 Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject
T1218.005-2 Mshta executes VBScript to execute malicious command
T1218.005-3 Mshta Executes Remote HTML Application (HTA)
T1218.005-4 Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement
T1218.005-5 Invoke HTML Application - Jscript Engine Simulating Double Click
T1218.005-6 Invoke HTML Application - Direct download from URI
T1218.005-7 Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler
T1218.005-8 Invoke HTML Application - JScript Engine with Inline Protocol Handler
T1218.005-9 Invoke HTML Application - Simulate Lateral Movement over UNC Path
T1218.005-10 Mshta used to Execute PowerShell
T1218.007-1 Msiexec.exe - Execute Local MSI file with embedded JScript
T1218.007-2 Msiexec.exe - Execute Local MSI file with embedded VBScript
T1218.007-3 Msiexec.exe - Execute Local MSI file with an embedded DLL
T1218.007-4 Msiexec.exe - Execute Local MSI file with an embedded EXE
T1218.007-5 WMI Win32_Product Class - Execute Local MSI file with embedded JScript
T1218.007-6 WMI Win32_Product Class - Execute Local MSI file with embedded VBScript
T1218.007-7 WMI Win32_Product Class - Execute Local MSI file with an embedded DLL
T1218.007-8 WMI Win32_Product Class - Execute Local MSI file with an embedded EXE
T1218.007-9 Msiexec.exe - Execute the DllRegisterServer function of a DLL
T1218.007-10 Msiexec.exe - Execute the DllUnregisterServer function of a DLL
T1218.007-11 Msiexec.exe - Execute Remote MSI file
T1218.008-1 Odbcconf.exe - Execute Arbitrary DLL
T1218.009-1 Regasm Uninstall Method Call Test
T1218.009-2 Regsvcs Uninstall Method Call Test
T1218.010-1 Regsvr32 local COM scriptlet execution
T1218.010-2 Regsvr32 remote COM scriptlet execution
T1218.010-3 Regsvr32 local DLL execution
T1218.010-4 Regsvr32 Registering Non DLL
T1218.010-5 Regsvr32 Silent DLL Install Call DllRegisterServer
T1218.011-1 Rundll32 execute JavaScript Remote Payload With GetObject
T1218.011-2 Rundll32 execute VBscript command
T1218.011-3 Rundll32 advpack.dll Execution
T1218.011-4 Rundll32 ieadvpack.dll Execution
T1218.011-5 Rundll32 syssetup.dll Execution
T1218.011-6 Rundll32 setupapi.dll Execution
T1218.011-7 Execution of HTA and VBS Files using Rundll32 and URL.dll
T1218.011-8 Launches an executable using Rundll32 and pcwutl.dll
T1218.011-9 Execution of non-dll using rundll32.exe
T1218.011-10 Rundll32 with Ordinal Value
T1218.011-11 Rundll32 with Control_RunDLL
T1219-1 TeamViewer Files Detected Test on Windows
T1219-2 AnyDesk Files Detected Test on Windows
T1219-3 LogMeIn Files Detected Test on Windows
T1219-4 GoToAssist Files Detected Test on Windows
T1219-5 ScreenConnect Application Download and Install on Windows
T1219-6 Ammyy Admin Software Execution
T1219-7 RemotePC Software Execution
T1220-1 MSXSL Bypass using local files
T1220-2 MSXSL Bypass using remote files
T1220-3 WMIC bypass using local XSL file
T1220-4 WMIC bypass using remote XSL file
T1221-1 WINWORD Remote Template Injection
T1222.001-1 Take ownership using takeown utility
T1222.001-2 cacls - Grant permission to specified user or group recursively
T1222.001-3 attrib - Remove read-only attribute
T1222.001-4 attrib - hide file
T1222.001-5 Grant Full Access to folder for Everyone - Ryuk Ransomware Style
T1482-1 Windows - Discover domain trusts with dsquery
T1482-2 Windows - Discover domain trusts with nltest
T1482-3 Powershell enumerate domains and forests
T1482-4 Adfind - Enumerate Active Directory OUs
T1482-5 Adfind - Enumerate Active Directory Trusts
T1482-6 Get-DomainTrust with PowerView
T1482-7 Get-ForestTrust with PowerView
T1484.002-1 Add Federation to Azure AD
T1485-1 Windows - Overwrite file with Sysinternals SDelete
T1485-3 Overwrite deleted data on C drive
T1486-5 PureLocker Ransom Note
T1489-1 Windows - Stop service using Service Controller
T1489-2 Windows - Stop service using net.exe
T1489-3 Windows - Stop service by killing process
T1490-1 Windows - Delete Volume Shadow Copies
T1490-2 Windows - Delete Volume Shadow Copies via WMI
T1490-3 Windows - wbadmin Delete Windows Backup Catalog
T1490-4 Windows - Disable Windows Recovery Console Repair
T1490-5 Windows - Delete Volume Shadow Copies via WMI with PowerShell
T1490-6 Windows - Delete Backup Files
T1490-7 Windows - wbadmin Delete systemstatebackup
T1490-8 Windows - Disable the SR scheduled task
T1490-9 Disable System Restore Through Registry
T1491.001-1 Replace Desktop Wallpaper
T1497.001-2 Detect Virtualization Environment (Windows)
T1497.001-4 Detect Virtualization Environment via WMI Manufacturer/Model Listing (Windows)
T1505.002-1 Install MS Exchange Transport Agent Persistence
T1505.003-1 Web Shell Written to Disk
T1518-1 Find and Display Internet Explorer Browser Version
T1518-2 Applications Installed
T1518.001-1 Security Software Discovery
T1518.001-2 Security Software Discovery - powershell
T1518.001-5 Security Software Discovery - Sysmon Service
T1518.001-6 Security Software Discovery - AV Discovery via WMI
T1529-1 Shutdown System - Windows
T1529-2 Restart System - Windows
T1531-1 Change User Password - Windows
T1531-2 Delete User - Windows
T1531-3 Remove Account From Domain Admin Group
T1539-1 Steal Firefox Cookies (Windows)
T1543.003-1 Modify Fax service to run PowerShell
T1543.003-2 Service Installation CMD
T1543.003-3 Service Installation PowerShell
T1543.003-4 TinyTurla backdoor service w64time
T1546.001-1 Change Default File Association
T1546.002-1 Set Arbitrary Binary as Screensaver
T1546.003-1 Persistence via WMI Event Subscription
T1546.007-1 Netsh Helper DLL Registration
T1546.008-1 Attaches Command Prompt as a Debugger to a List of Target Processes
T1546.008-2 Replace binary of sticky keys
T1546.010-1 Install AppInit Shim
T1546.011-1 Application Shim Installation
T1546.011-2 New shim database files created in the default shim database directory
T1546.011-3 Registry key creation and/or modification events for SDB
T1546.012-1 IFEO Add Debugger
T1546.012-2 IFEO Global Flags
T1546.013-1 Append malicious start-process cmdlet
T1546.015-1 COM Hijacking - InprocServer32
T1546.015-2 Powershell Execute COM Object
T1547-1 Add a driver
T1547.001-1 Reg Key Run
T1547.001-2 Reg Key RunOnce
T1547.001-3 PowerShell Registry RunOnce
T1547.001-4 Suspicious vbs file run from startup Folder
T1547.001-5 Suspicious jse file run from startup Folder
T1547.001-6 Suspicious bat file run from startup Folder
T1547.001-7 Add Executable Shortcut Link to User Startup Folder
T1547.001-8 Add persistance via Recycle bin
T1547.001-9 SystemBC Malware-as-a-Service Registry
T1547.002-1 Authentication Package
T1547.004-1 Winlogon Shell Key Persistence - PowerShell
T1547.004-2 Winlogon Userinit Key Persistence - PowerShell
T1547.004-3 Winlogon Notify Key Logon Persistence - PowerShell
T1547.005-1 Modify SSP configuration in registry
T1547.009-1 Shortcut Modification
T1547.009-2 Create shortcut to cmd in startup folders
T1547.010-1 Add Port Monitor persistence in Registry
T1548.002-1 Bypass UAC using Event Viewer (cmd)
T1548.002-2 Bypass UAC using Event Viewer (PowerShell)
T1548.002-3 Bypass UAC using Fodhelper
T1548.002-4 Bypass UAC using Fodhelper - PowerShell
T1548.002-5 Bypass UAC using ComputerDefaults (PowerShell)
T1548.002-6 Bypass UAC by Mocking Trusted Directories
T1548.002-7 Bypass UAC using sdclt DelegateExecute
T1548.002-8 Disable UAC using reg.exe
T1548.002-9 Bypass UAC using SilentCleanup task
T1548.002-10 UACME Bypass Method 23
T1548.002-11 UACME Bypass Method 31
T1548.002-12 UACME Bypass Method 33
T1548.002-13 UACME Bypass Method 34
T1548.002-14 UACME Bypass Method 39
T1548.002-15 UACME Bypass Method 56
T1548.002-16 UACME Bypass Method 59
T1548.002-17 UACME Bypass Method 61
T1550.002-1 Mimikatz Pass the Hash
T1550.002-2 crackmapexec Pass the Hash
T1550.003-1 Mimikatz Kerberos Ticket Attack
T1550.003-2 Rubeus Kerberos Pass The Ticket
T1552.001-3 Extracting passwords with findstr
T1552.001-4 Access unattend.xml
T1552.002-1 Enumeration for Credentials in Registry
T1552.002-2 Enumeration for PuTTY Credentials in Registry
T1552.004-1 Private Keys
T1552.004-6 ADFS token signing and encryption certificates theft - Local
T1552.004-7 ADFS token signing and encryption certificates theft - Remote
T1552.006-1 GPP Passwords (findstr)
T1552.006-2 GPP Passwords (Get-GPPPassword)
T1553.004-4 Install root CA on Windows
T1553.004-5 Install root CA on Windows with certutil
T1553.004-6 Add Root Certificate to CurrentUser Certificate Store
T1553.005-1 Mount ISO image
T1553.005-2 Mount an ISO image and run executable from the ISO
T1553.005-3 Remove the Zone.Identifier alternate data stream
T1555-1 Extract Windows Credential Manager via VBA
T1555-2 Dump credentials from Windows Credential Manager With PowerShell [windows Credentials]
T1555-3 Dump credentials from Windows Credential Manager With PowerShell [web Credentials]
T1555-4 Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]
T1555-5 Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]
T1555.003-1 Run Chrome-password Collector
T1555.003-3 LaZagne - Credentials from Browser
T1555.003-4 Simulating access to Chrome Login Data
T1555.003-5 Simulating access to Opera Login Data
T1555.003-6 Simulating access to Windows Firefox Login Data
T1555.003-7 Simulating access to Windows Edge Login Data
T1555.003-8 Decrypt Mozilla Passwords with Firepwd.py
T1555.004-1 Access Saved Credentials via VaultCmd
T1556.002-1 Install and Register Password Filter DLL
T1557.001-1 LLMNR Poisoning with Inveigh (PowerShell)
T1558.001-1 Crafting Active Directory golden tickets with mimikatz
T1558.001-2 Crafting Active Directory golden tickets with Rubeus
T1558.003-1 Request for service tickets
T1558.003-2 Rubeus kerberoast
T1558.003-3 Extract all accounts in use as SPN using setspn
T1558.003-4 Request A Single Ticket via PowerShell
T1558.003-5 Request All Tickets via PowerShell
T1558.004-1 Rubeus asreproast
T1558.004-2 Get-DomainUser with PowerView
T1559.002-2 Execute PowerShell script via Word DDE
T1560-1 Compress Data for Exfiltration With PowerShell
T1560.001-1 Compress Data for Exfiltration With Rar
T1560.001-2 Compress Data and lock with password for Exfiltration with winrar
T1560.001-3 Compress Data and lock with password for Exfiltration with winzip
T1560.001-4 Compress Data and lock with password for Exfiltration with 7zip
T1562.001-10 Unload Sysmon Filter Driver
T1562.001-11 Uninstall Sysmon
T1562.001-12 AMSI Bypass - AMSI InitFailed
T1562.001-13 AMSI Bypass - Remove AMSI Provider Reg Key
T1562.001-14 Disable Arbitrary Security Windows Service
T1562.001-15 Tamper with Windows Defender ATP PowerShell
T1562.001-16 Tamper with Windows Defender Command Prompt
T1562.001-17 Tamper with Windows Defender Registry
T1562.001-18 Disable Microsoft Office Security Features
T1562.001-19 Remove Windows Defender Definition Files
T1562.001-20 Stop and Remove Arbitrary Security Windows Service
T1562.001-21 Uninstall Crowdstrike Falcon on Windows
T1562.001-22 Tamper with Windows Defender Evade Scanning -Folder
T1562.001-23 Tamper with Windows Defender Evade Scanning -Extension
T1562.001-24 Tamper with Windows Defender Evade Scanning -Process
T1562.001-25 office-365-Disable-AntiPhishRule
T1562.001-26 Disable Windows Defender with DISM
T1562.001-27 Disable Defender with Defender Control
T1562.001-28 Disable Defender Using NirSoft AdvancedRun
T1562.002-1 Disable Windows IIS HTTP Logging
T1562.002-2 Kill Event Log Service Threads
T1562.002-3 Impair Windows Audit Log Policy
T1562.002-4 Clear Windows Audit Policy Config
T1562.002-5 Disable Event Logging with wevtutil
T1562.002-6 Makes Eventlog blind with Phant0m
T1562.004-1 Disable Microsoft Defender Firewall
T1562.004-2 Disable Microsoft Defender Firewall via Registry
T1562.004-3 Allow SMB and RDP on Microsoft Defender Firewall
T1562.004-4 Opening ports for proxy - HARDRAIN
T1562.004-5 Open a local port through Windows Firewall to any profile
T1562.004-6 Allow Executable Through Firewall Located in Non-Standard Location
T1562.008-2 Azure - Eventhub Deletion
T1562.008-3 Office 365 - Exchange Audit Log Disabled
T1563.002-1 RDP hijacking
T1564-1 Extract binary files via VBA
T1564-2 Create a Hidden User Called "$"
T1564-3 Create an "Administrator " user (with a space on the end)
T1564.001-3 Create Windows System File with Attrib
T1564.001-4 Create Windows Hidden File with Attrib
T1564.001-8 Hide Files Through Registry
T1564.003-1 Hidden Window
T1564.004-1 Alternate Data Streams (ADS)
T1564.004-2 Store file in Alternate Data Stream (ADS)
T1564.004-3 Create ADS command prompt
T1564.004-4 Create ADS PowerShell
T1564.006-1 Register Portable Virtualbox
T1564.006-2 Create and start VirtualBox virtual machine
T1564.006-3 Create and start Hyper-V virtual machine
T1566.001-1 Download Macro-Enabled Phishing Attachment
T1566.001-2 Word spawned a command shell and used an IP address in the command line
T1567-1 Data Exfiltration with ConfigSecurityPolicy
T1569.002-1 Execute a Command as a Service
T1569.002-2 Use PsExec to execute a command on a remote host
T1571-1 Testing usage of uncommonly used port with PowerShell
T1572-1 DNS over HTTPS Large Query Volume
T1572-2 DNS over HTTPS Regular Beaconing
T1572-3 DNS over HTTPS Long Domain Query
T1573-1 OpenSSL C2
T1574.001-1 DLL Search Order Hijacking - amsi.dll
T1574.002-1 DLL Side-Loading using the Notepad++ GUP.exe binary
T1574.009-1 Execution of program.exe as service with unquoted service path
T1574.011-1 Service Registry Permissions Weakness
T1574.011-2 Service ImagePath Change with reg.exe
T1574.012-1 User scope COR_PROFILER
T1574.012-2 System Scope COR_PROFILER
T1574.012-3 Registry-free process scope COR_PROFILER
T1606.002-1 Golden SAML
T1615-1 Display group policy information via gpresult
