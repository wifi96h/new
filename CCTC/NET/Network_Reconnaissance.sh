# red jump box
# net3_student11@10.50.21.8
# password11

USE:
ACTIVE - 
./scan.sh
nmap
nc <ip> <port>

PASSIVE - 
ip addr
netstat/ss
ip route
ip neigh
cd /usr/share/cctc
ps -elf | grep <process>


Target Section:

T1
Hostname: networking-ctfd-1.server.vta
Record Type: TXT
IP: UNKNOWN
Ports: 53
Action: interrogate DNS records

Red Boundry Router
Hostname: RED-SCR
IP: 172.16.120.1
Ports: 22
Username: vyos
Password: password
Action: Use as start point and Perform Passive/Active Reconnaissance

Interface        IP Address                        S/L  Description
---------        ----------                        ---  -----------
eth0             172.16.120.1/29                   u/u  INTERNET
eth1             172.16.120.10/29                  u/u  REDNET
eth2             172.16.101.30/27                  u/u  DMZ
lo               127.0.0.1/8                       u/u
                 120.0.0.1/32
                 ::1/128

T2
Hostname: UNKNOWN
IP: 172.16.182.110
Action: Perform Active Reconnaissance

T3
Hostname: UNKNOWN
IP: 172.16.140.33
Action: Perform Active Reconnaissance

T4
Hostname: UNKNOWN
IP: 172.16.182.106
Action: Perform Active Reconnaissance

T5
Hostname: UNKNOWN
IP: 172.16.182.114
Action: Perform Active Reconnaissance

T6
Hostname: UNKNOWN
IP: 172.16.182.118
Action: Perform Active Reconnaissance

T7
Hostname: UNKNOWN
IP: 172.16.140.35
Action: Perform Active Reconnaissance

# The start flag is an encoded string that is in a record associated with your CTFd server. Decode this string for the flag
dig networking-ctfd-1.server.vta TXT

# Utilizing the intelligence already provided, what is it’s hostname of their boundary router?
ssh vyos@172.16.120.1:password

# How many host(s) did you discover on the DMZ Net? (excluding the router)
show interface # dmz is on eth2
show arp # count number of active devices on eth2 1

#  What is the ip address of the host device(s) in the DMZ network?
show arp # get ip address 172.16.101.2

# How many well-known open TCP ports did you discover on the device(s)?
nmap -sT 172.16.101.2  # 1 port 22

# What well-known TCP port(s) are open on the system(s)?
22 # use results from nmap scan

# What is the Hostname of the system(s)?
ssh net3_student11@172.16.101.2:password11 # red-dmz-host-1

# What is it’s hostname of the device directly connected to the Donovian boundary on eth1?
show arp # go back to vyos, 172.16.120.9             ether   fa:16:3e:70:f5:7a   C                     eth1
ssh vyos@172.16.120.9:password # RED-IPS

# What is the hostname of the device directly connected to the system discovered in Donovian Man in the Middle, on eth1?
show arp
# Address                  HWtype  HWaddress           Flags Mask            Iface
# 172.16.120.17            ether   fa:16:3e:93:fb:f8   C                     eth1
# 172.16.120.22                    (incomplete)                              eth1
# 172.16.120.20                    (incomplete)                              eth1
# 172.16.120.10            ether   fa:16:3e:f1:75:9e   C                     eth0
# 172.16.120.19                    (incomplete)                              eth1
# 172.16.120.21                    (incomplete)                              eth1

ssh vyos@172.16.120.17:password # RED-POP

# What well-known port(s) are open on the system? (separate ports with a comma and no space)
nmap -sT 172.16.182.126/27 # 22,80

# Interface with the web service on the 172.16.182.110 host. The hint provides a suggestion on the ports above the well-known that you will need to recon. What is the range?
nmap -sT 172.16.182.110 -p 1000-9999 # 1980,1982,1988,1989 -or- 1980-1989

# What UDP ports did you find that were open? (List them in in order and separate the ports with a comma and no space.) NOTE: Look in the same port range mentioned in your hint for this target.
sudo nmap -sU 172.16.182.110 -p 1000-2000 -T2 # 1984,1989

# What instrument was being played on UDP port 1984?
nc -u 172.16.182.110 1984 # saxophone...

# What was on the license plate in the link on TCP port 1980?
nc 172.16.182.110 1980 

# What is the Hostname of the system?
ssh net3_student11@172.16.182.106:password11 # red-host-1

# What well-known port(s) are open on the system? (separate ports with a comma and no space)
nmap 172.16.182.114

# What is the Hostname of the system?
ssh net3_student11@172.16.182.114:password11

# What well-known port(s) are open on the system? (separate ports with a comma and no space)
nmap 172.16.182.118

ssh net3_student11@172.16.182.118
