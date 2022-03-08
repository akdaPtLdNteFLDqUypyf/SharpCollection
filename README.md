# SharpCollection

*UNDER Construction*

This repo is based off of https://github.com/Flangvik/SharpCollection, it similiarly completes nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion as a daily cron Github Action. 

# Github Actions

To download the tools you want select the Actions Tab, select the tool build, scroll down to artifact, download the file which will be a .zip file containing your executable.

# OpSec 
You probably should not download and run random binariers off the internet. These tools are intented for labs, CTFs, VMs, HackTheBox, TryHackMe, and similiar non-production systems. 

# TODO
* Ensure artifact is uploaded for all tools
* Make sure all tools actually run
* Fix tools that don't confirm to standard build process
* Publish helper tool written to automate C# Build yaml files
* Create build action for multiple .NET versions
* Specify CPU architecture

# Warning $$$
If you fork this repo and make it private you may incur costs from total Github actions minutes exceeding free tier. 

# Available builds

| Tools \ .NET Framework | Artifact Built | 
| --------------- | --------------- |
| ADCollector | :heavy_check_mark: |
| ADCSPwn | :heavy_check_mark: |
| ADSearch | :heavy_check_mark: |
| ADFSDump| :heavy_check_mark: |
| AtYourService | :heavy_check_mark: |
| BetterSafetyKatz | :heavy_check_mark: |
| Certify | :heavy_check_mark: |
| EDD | :heavy_check_mark: |
| ForgeCert | :heavy_check_mark: |
| DeployPrinterNightmare | :heavy_check_mark: |
| Grouper2 | :x: |
| InveighZero | :heavy_check_mark: |
| LockLess | :heavy_check_mark: |
| PurpleSharp | :heavy_check_mark: |
| Rubeus | :heavy_check_mark: |
| SafetyKatz | :heavy_check_mark: |
| SauronEye | :heavy_check_mark: |
| SearchOutlook | :heavy_check_mark: |
| Seatbelt | :heavy_check_mark: |
| Sharp-SMBExec | :heavy_check_mark: |
| SharpAllowedToAct | :heavy_check_mark: |
| SharpAppLocker | :heavy_check_mark: |
| SharpBlock | :heavy_check_mark: |
| SharpBypassUAC | :heavy_check_mark: |
| SharpChisel | :heavy_check_mark: |
| SharpChrome | :heavy_check_mark: |
| SharpChromium | :heavy_check_mark: |
| SharpCloud | :heavy_check_mark: |
| SharpCOM | :heavy_check_mark: |
| SharpCrashEventLog | :heavy_check_mark: |
| SharpDir | :heavy_check_mark: |
| SharpDoor | :x: |
| SharpDPAPI | :heavy_check_mark: |
| SharpDump | :heavy_check_mark: |
| SharpEDRChecker | :heavy_check_mark: |
| SharpExec | :heavy_check_mark: |
| SharPersist | :x: |
| SharpFiles | :x: |
| SharpGPOAbuse | :heavy_check_mark: |
| SharpHandler | :heavy_check_mark: |
| SharpHose | :heavy_check_mark: |
| SharpHound3 | :heavy_check_mark: |
| SharpKatz | :heavy_check_mark: |
| SharpLaps | :heavy_check_mark: |
| SharpMapExec | :heavy_check_mark: |
| SharpMiniDump | :heavy_check_mark: |
| SharpMove | :heavy_check_mark: |
| SharpPrinter | :heavy_check_mark: |
| SharpNoPSExec | :heavy_check_mark: |
| SharpRDP | :heavy_check_mark: |
| SharpReg | :heavy_check_mark: |
| SharpSecDump | :heavy_check_mark: |
| SharpShares | :heavy_check_mark: |
| SharpSphere | :heavy_check_mark: |
| SharpSpray | :heavy_check_mark: |
| SharpStay | :heavy_check_mark: |
| SharpSvc | :heavy_check_mark: |
| SharpSniper | :heavy_check_mark: |
| SharpTask | :heavy_check_mark: |
| SharpUp | :heavy_check_mark: |
| SharpView | :heavy_check_mark: |
| SharpWMI | :heavy_check_mark: |
| SharpWebServer | :heavy_check_mark: |
| SharpWifiGrabber | :heavy_check_mark: |
| SharpZeroLogon | :x: |
| Shhmon | :heavy_check_mark: |
| SqlClient | :heavy_check_mark: |
| StandIn | :heavy_check_mark: |
| StickyNotesExtract | :heavy_check_mark: |
| SweetPotato | :heavy_check_mark: |
| ThunderFox | :heavy_check_mark: |
| TruffleSnout | :heavy_check_mark: |
| Watson | :heavy_check_mark: |
| winPEAS | :heavy_check_mark: |
| WMIReg | :heavy_check_mark: |

# Sources / Credits
@Flangvik for compiling the list of tools and the repo idea
* [ADCollector](https://github.com/dev-2null/ADCollector) - C# tool to quickly extract valuable information from the Active Directory environment @dev-2null
* [ADCSPwn](https://github.com/bats3c/ADCSPwn) - C# tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service. @bats3c
* [ADSearch](https://github.com/tomcarver16/ADSearch) - C# tool to help query AD via the LDAP protocol @tomcarver16 (Only NET 4.7)
* [ADFSDump](https://github.com/fireeye/ADFSDump) - A C# tool to dump all sorts of goodies from AD FS. @FireEye
* [AtYourService](https://github.com/mitchmoser/AtYourService) - C# .NET Assembly for Service Enumeration @mitchmoser
* [BetterSafetyKatz](https://github.com/Flangvik/BetterSafetyKatz) - Fork of SafetyKatz dynamically fetches the latest Mimikatz, runtime patching signatures and PE loads Mimikatz into memory. @Flangvik
* [Certify](https://github.com/GhostPack/Certify) - C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS). @harmj0y @tifkin_ 
* [EDD]( https://github.com/FortyNorthSecurity/EDD) - Enumerate Domain Data is designed to be similar to PowerView but in .NET @FortyNorthSecurity
* [ForgeCert](https://github.com/GhostPack/ForgeCert) - uses a stolen CA certificate + private key to forge certificates for arbitrary users. @tifkin_ 
* [DeployPrinterNightmare]( https://github.com/Flangvik/DeployPrinterNightmare) - C# tool for installing a shared network printer abusing the PrinterNightmare bug to allow other network machines easy privesc @Flangvik
* [Grouper2](https://github.com/l0ss/Grouper2) -  C# tool to help find security-related misconfigurations in Active Directory Group Policy. @mikeloss
* [LockLess](https://github.com/GhostPack/LockLess) - Allows for the copying of locked files. @GhostPack
* [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) - C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments. @mvelazc0
* [Rubeus](https://github.com/GhostPack/Rubeus) -  C# toolset for raw Kerberos interaction and abuses. @GhostPack
* [SafetyKatz](https://github.com/GhostPack/SafetyKatz) - Combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader.  @GhostPack
* [SauronEye](https://github.com/vivami/SauronEye) -  C# search tool find specific files containing specific keywords (.doc, .docx, .xls, .xlsx). @_vivami
* [SearchOutlook](https://github.com/RedLectroid/SearchOutlook) - C# tool to search through a running instance of Outlook for keywords @RedLectroid
* [Seatbelt](https://github.com/GhostPack/Seatbelt) - Performs a number of security oriented host-survey "safety checks". @GhostPack
* [Sharp-SMBExec](https://github.com/checkymander/Sharp-SMBExec) -  A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script @checkymander
* [SharpAllowedToAct](https://github.com/pkb1s/SharpAllowedToAct) -  C# implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) @pkb1s
* [SharpAppLocker](https://github.com/Flangvik/SharpAppLocker) - C# port of the Get-AppLockerPolicy PS cmdlet with extended features @Flangvik
* [SharpBlock](https://github.com/CCob/SharpBlock) - A method of bypassing EDR's active projection DLL's by preventing entry point exection. @CCob
* [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC) - C# tool for UAC bypasses @rodzianko
* [SharpChisel](https://github.com/shantanu561993/SharpChisel) -  C# Chisel Wrapper. @shantanu561993
* [SharpChrome](https://github.com/GhostPack/SharpDPAPI) - Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage. @GhostPack
* [SharpChromium](https://github.com/djhohnstein/SharpChromium) -  C# Project to retrieve Chromium data, such as cookies, history and saved logins. @djhohnstein
* [SharpCloud](https://github.com/chrismaddalena/SharpCloud) - Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute. @chrismaddalena
* [SharpCrashEventLog](https://github.com/slyd0g/SharpCrashEventLog) -  C# port of LogServiceCrash @slyd0g @limbenjamin
* [SharpCOM](https://github.com/rvrsh3ll/SharpCOM) - C# port of Invoke-DCOM @424f424f
* [SharpDir](https://github.com/jnqpblc/SharpDir) - C# tool to search both local and remote file systems for files. @jnqpblc
* [SharpDoor](https://github.com/infosecn1nja/SharpDoor) - C# tool to allow multiple RDP (Remote Desktop) sessions by patching termsrv.dll file. @infosecn1nja
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) -  C# port of some Mimikatz DPAPI functionality. @GhostPack
* [SharpDump](https://github.com/GhostPack/SharpDump) - SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality. @GhostPack
* [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) - C# tool to check for the presence of known defensive products such as AV's, EDR's and logging tools @PwnDexter
* [SharPersist] (https://github.com/fireeye/SharPersist) - C# persistence toolkit. 
* [SharpExec](https://github.com/anthemtotheego/SharpExec) - SharpExec is an offensive security C# tool designed to aid with lateral movement. @anthemtotheego
* [SharpFiles](https://github.com/fullmetalcache/SharpFiles) - C# tool to search for files based on SharpShares output. @fullmetalcache
* [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) - SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO). @FSecureLABS
* [SharpHandler](https://github.com/jfmaes/SharpHandler) -  C# tool for stealing/duping handles to LSASS @Jean_Maes_1994
* [SharpHose](https://github.com/ustayready/SharpHose) - Asynchronous Password Spraying Tool in C# for Windows Environments . @ustayready
* [SharpHound3](https://github.com/BloodHoundAD/SharpHound3) - C# Rewrite of the BloodHound Ingestor. @BloodHoundAD
* [SharpKatz](https://github.com/b4rtik/SharpKatz) -  PURE C# port of significant MimiKatz functionality such as logonpasswords, dcsync, etc. @b4rtik
* [SharpLaps](https://github.com/swisskyrepo/SharpLAPS) - A C# tool to retrieve LAPS passwords from LDAP @pentest_swissky
* [SharpMapExec](https://github.com/cube0x0/SharpMapExec) -  C# version of @byt3bl33d3r's tool CrackMapExec @cube0x0
* [SharpMiniDump](https://github.com/b4rtik/SharpMiniDump) - C# tool to Create a minidump of the LSASS process from memory @b4rtik
* [SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec) -  C# tool allowing file less command execution for lateral movement. @juliourena
* [SharpMove](https://github.com/0xthirteen/SharpMove) -  C# tool for performing lateral movement techniques @0xthirteen
* [SharpPrinter](https://github.com/rvrsh3ll/SharpPrinter) - C# tool for discovering Printers on an network @424f424f
* [SharpRDP](https://github.com/0xthirteen/SharpRDP) - C# Remote Desktop Protocol Console Application for Authenticated Command Execution @0xthirteen
* [SharpReg](https://github.com/jnqpblc/SharpReg) - C# tool to interact with the Remote Registry service api. @jnqpblc
* [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump) - C# port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py @G0ldenGunSec
* [SharpShares](https://github.com/djhohnstein/SharpShares) - Enumerate all network shares in the current domain. @djhohnstein
* [SharpSphere](https://github.com/JamesCooteUK/SharpSphere) - C# SharpSphere has the ability to interact with the guest operating systems of virtual machines managed by vCenter. @jkcoote & @grzryc
* [SharpSpray](https://github.com/jnqpblc/SharpSpray) - C# tool to perform a password spraying attack against all users of a domain using LDAP. @jnqpblc
* [SharpStay](https://github.com/0xthirteen/SharpStay) - .NET project for installing Persistence. @0xthirteen
* [SharpSearch](https://github.com/djhohnstein/SharpSearch) - C# Project to quickly filter through a file share for targeted files for desired information. @djhohnstein
* [SharpSvc](https://github.com/jnqpblc/SharpSvc) - C# tool to interact with the SC Manager API. @jnqpblc (Only NET 4.7)
* [SharpSniper](https://github.com/HunnicCyber/SharpSniper) - SharpSniper is a simple tool to find the IP address of these users so that you can target their box. @hunniccyber
* [SharpTask](https://github.com/jnqpblc/SharpTask) - C# tool to interact with the Task Scheduler service api. @jnqpblc
* [SharpUp](https://github.com/GhostPack/SharpUp) - C# port of various PowerUp functionality. @GhostPack
* [SharpView](https://github.com/tevora-threat/SharpView) - C# implementation of harmj0y's PowerView. @tevora-threat
* [SharpWMI](https://github.com/GhostPack/SharpWMI) -  C# implementation of various WMI functionality. @GhostPack
* [SharpWebServer](https://github.com/mgeeky/SharpWebServer) - A Red Team oriented simple HTTP & WebDAV server written in C# with functionality to capture Net-NTLM hashes. @mariuszbit
* [SharpWifiGrabber](https://github.com/r3nhat/SharpWifiGrabber) - Sharp Wifi Password Grabber retrieves in clear-text the Wi-Fi Passwords from all WLAN Profiles saved on a workstation. @r3n_hat
* [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon) -  C# port of CVE-2020-1472 , a.k.a. Zerologon. @buffaloverflow
* [Shhmon](https://github.com/matterpreter/Shhmon) - Neutering Sysmon via driver unload. @Shhmon
* [SqlClient](https://github.com/FortyNorthSecurity/SqlClient) - C# .NET mssql client for accessing database data through beacon. @FortyNorthSecurity
* [StandIn](https://github.com/FuzzySecurity/StandIn) -  C# based small AD post-compromise toolkit. @FuzzySec
* [StickyNotesExtract](https://github.com/V1V1/SharpScribbles) - C# tool that extracts data from the Windows Sticky Notes database. @V1V1 
* [SweetPotato](https://github.com/CCob/SweetPotato) - Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019 . @CCob
* [ThunderFox](https://github.com/V1V1/SharpScribbles) - C# Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox. @V1V1 
* [TruffleSnout](https://github.com/dsnezhkov/TruffleSnout) -  C# based iterative AD discovery toolkit for offensive operators. @dsnezhkov
* [Watson](https://github.com/rasta-mouse/Watson) - Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities . @rasta-mouse
* [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) - PEASS - Privilege Escalation Awesome Scripts (winPEAS). @carlospolop
* [WMIReg](https://github.com/airzero24/WMIReg) - C# PoC to interact with local/remote registry hives through WMI. @airzero24
